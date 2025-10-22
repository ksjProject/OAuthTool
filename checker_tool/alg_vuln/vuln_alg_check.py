
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vuln_alg_check.py — 잘못된 alg 처리(alg 공격) 전용 진단 모듈
#
# 목적
#  - 팀 스캐너의 "vuln check module" 포맷에 맞춰 **alg 취약**만 점검
#  - 네가 쓰는 어댑터(adapter_to_checker.py)와 **I/O 형식, 출력 스타일(A/B/C 섹션, Failures/Warn)** 동일
#  - 네트워크 호출 없음(정적 분석)
#
# 근거(우선순위)
#  - RFC 8725 (JWT BCP) §2, §3.1, §3.2
#  - RFC 7515/7517/7518/7519 (JWS/JWK/JWA/JWT)
#  - RFC 9068 (OAuth AT as JWT) §2.1, §4  → typ "at+jwt" 확인
#  - OIDC Core/Discovery (jwks_uri, id_token_*_alg, redirect_uri 비교 규칙)
#  - RFC 9449 (DPoP) §5  → (정보성) AT 바인딩
#
# 입력 스켈레톤(flow_bundle) — adapter_to_checker.py가 만드는 구조와 호환
# {
#   "discovery": { "issuer":"...", "jwks_uri":"https://...", "id_token_signing_alg_values_supported":["RS256","PS256"] },
#   "authorization_request": { "url": ".../authorize?...",
#       "params": {"response_type":"code|id_token|code id_token", "scope":"openid ..."} },
#   "authorization_response": { "location":"https://client/cb?... or #...", "form":{...}, "params":{...} },
#   "token_response": { "json": { "access_token": "...", "id_token":"..." } },
#   "refresh_token_response": { "json": {}},
#   "found_jwts": ["...", "..."]                 # 선택: 스토리지/로그에서 수집된 임의 JWT
# }
#
# 출력
# {
#   "ok": bool,
#   "failures": [ {code,title,detail,evidence} ],
#   "warnings":  [ {code,title,detail,evidence} ],
#   "flow_type": "implicit|hybrid|code|unknown",
#   "observed": {...},
#   "checklist": { "A": {...}, "B": {...}, "C": {...} }
# }
#
from __future__ import annotations

import json, base64, re
from dataclasses import dataclass
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urlparse, parse_qs

# ---------------- Configuration (팀 기본 정책) ----------------
# 허용 알고리즘 화이트리스트 (핀닝)
DEFAULT_ALLOWED_ALGS = {"RS256", "PS256", "ES256"}
# Access Token typ 정책: 권고(Advisory). 엄격 모드로 Fail 처리하려면 True
STRICT_AT_TYP = False
# Code Flow에서 ID Token alg=none 예외 허용? (등록 명시 없으면 False 권장)
ALLOW_ID_NONE_IN_CODE_FLOW = False

# ---------------- Utilities ----------------
def _b64url_decode(s: str) -> bytes:
    if not isinstance(s, (str, bytes)): raise ValueError("not a string")
    if isinstance(s, str): s = s.encode("utf-8")
    s += b"=" * ((4 - (len(s) % 4)) % 4)
    s = s.replace(b"-", b"+").replace(b"_", b"/")
    import base64
    return base64.b64decode(s)

def parse_jwt(jwt: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    "서명 검증 없이 header, payload만 파싱"
    parts = (jwt or "").split(".")
    if len(parts) < 2:
        raise ValueError("Invalid JWT format")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    return header, payload

def _qfrag(url: Optional[str]) -> Dict[str,str]:
    if not url: return {}
    p = urlparse(url)
    q = parse_qs(p.query)
    f = parse_qs(p.fragment) if p.fragment else {}
    out = {}
    for src in (q,f):
        for k,v in src.items():
            if v: out[k]=v[0]
    return out

def _detect_flow(params: Dict[str,Any]) -> str:
    rt = (params.get("response_type") or "").lower().replace("+"," ")
    toks = set(rt.split())
    scope = (params.get("scope") or "").lower()
    if "openid" not in scope: return "unknown"
    if "id_token" in toks and "code" in toks: return "hybrid"
    if "id_token" in toks: return "implicit"
    if "code" in toks: return "code"
    return "unknown"

def _kid_weird(kid: str) -> bool:
    if not kid: return False
    if len(kid) > 128: return True
    if any(ch in kid for ch in ("/","\\","?","#",":")): return True
    if kid.lower().startswith("http"): return True
    return False

# ---------------- Data classes ----------------
@dataclass
class AuthorizationRequest:
    url: Optional[str]=None
    params: Optional[Dict[str,Any]]=None
    def __init__(self, url=None, params=None, **_):
        self.url = url
        self.params = params or (_qfrag(url) if url else {})

@dataclass
class AuthorizationResponse:
    location: Optional[str]=None
    form: Optional[Dict[str,Any]]=None
    params: Optional[Dict[str,Any]]=None
    def __init__(self, location=None, form=None, params=None, **_):
        self.location = location
        self.form = form or {}
        self.params = params or (_qfrag(location) if location else {})

@dataclass
class TokenResponse:
    json: Optional[Dict[str,Any]]=None
    def __init__(self, json=None, **_):
        self.json = json or {}

@dataclass
class FlowBundle:
    discovery: Dict[str,Any]
    authorization_request: AuthorizationRequest
    authorization_response: AuthorizationResponse
    token_response: TokenResponse
    refresh_token_response: TokenResponse
    found_jwts: List[str]
    def __init__(self, **d):
        self.discovery = d.get("discovery") or {}
        self.authorization_request = AuthorizationRequest(**(d.get("authorization_request") or {}))
        self.authorization_response = AuthorizationResponse(**(d.get("authorization_response") or {}))
        self.token_response = TokenResponse(**(d.get("token_response") or {}))
        self.refresh_token_response = TokenResponse(**(d.get("refresh_token_response") or {}))
        self.found_jwts = list(d.get("found_jwts") or [])

# ---------------- Core check ----------------
def run_checks(raw: Dict[str,Any],
               allowed_algs: Optional[set]=None,
               strict_at_typ: bool=STRICT_AT_TYP,
               allow_id_none_in_code_flow: bool=ALLOW_ID_NONE_IN_CODE_FLOW) -> Dict[str,Any]:

    fb = FlowBundle(**raw)
    ar = fb.authorization_request.params or {}
    flow_type = _detect_flow(ar)

    failures, warnings = [], []
    def fail(code,title,detail,evidence=None): failures.append({"code":code,"title":title,"detail":detail,"evidence":evidence})
    def warn(code,title,detail,evidence=None): warnings.append({"code":code,"title":title,"detail":detail,"evidence":evidence})

    allowed = allowed_algs or set(DEFAULT_ALLOWED_ALGS)

    # 수집된 JWT들
    observed_tokens = []  # list of dict: {"kind": "id_token|access_token|found", "header":{}, "payload":{}}
    # 1) authorization_response/form/query에서 id_token 발견(Implicit/Hybrid)
    id_from_auth = fb.authorization_response.params.get("id_token") or fb.authorization_response.form.get("id_token")
    if id_from_auth:
        try:
            h,p = parse_jwt(id_from_auth)
            observed_tokens.append({"kind":"id_token(authz)","header":h,"payload":p})
        except Exception as e:
            fail("A0","Invalid ID Token format (authorization_response)",str(e),{"prefix":id_from_auth[:40]})
    # 2) token_response의 id_token/access_token
    tr = fb.token_response.json or {}
    if tr.get("id_token"):
        try:
            h,p = parse_jwt(tr["id_token"])
            observed_tokens.append({"kind":"id_token(token)","header":h,"payload":p})
        except Exception as e:
            fail("A0","Invalid ID Token format (token_response)",str(e),{"prefix":tr["id_token"][:40]})
    if tr.get("access_token"):
        # Access Token이 꼭 JWT란 보장은 없음 → 실패로 두지 않고, 파싱 실패 시 스킵
        try:
            h,p = parse_jwt(tr["access_token"])
            observed_tokens.append({"kind":"access_token","header":h,"payload":p})
        except Exception:
            pass
    # 3) 임의 JWT
    for j in fb.found_jwts:
        try:
            h,p = parse_jwt(j)
            observed_tokens.append({"kind":"found","header":h,"payload":p})
        except Exception:
            continue

    # ========== Checklist containers ==========
    A,B,C = {},{},{}  # A: Algorithm/typ, B: Key source & headers, C: Policy/binding/mix
    checklist = {"A":A, "B":B, "C":C}

    # ---------------- A. Algorithm / typ 점검 ----------------
    # A1 alg 존재 & 화이트리스트 핀닝
    a1_ok = True
    for t in observed_tokens:
        alg = (t["header"].get("alg") or "").upper()
        if not alg:
            a1_ok = False
            fail("A1", "alg missing", "JWT 보호헤더 alg는 MUST 존재.", {"token_kind": t["kind"], "header": t["header"]})
        elif alg not in allowed:
            # none/HS* 포함해 집합 밖은 모두 Fail (정책 핀닝)
            a1_ok = False
            fail("A2", "alg not allowed (pinning violation)",
                 f"허용 목록 밖 alg '{alg}'. 허용={sorted(list(allowed))}",
                 {"token_kind": t["kind"], "alg": alg})
    A["alg_pinned_allowlist"] = {"result": "Pass" if a1_ok else "Fail", "observed": [ (t["kind"], t["header"].get("alg")) for t in observed_tokens ]}

    # A2 alg="none" 금지 (AT-JWT 항상 금지, ID 토큰은 프런트채널 금지/코드플로우 예외)
    a2_fail = False
    for t in observed_tokens:
        alg = (t["header"].get("alg") or "").upper()
        if alg == "NONE":
            if t["kind"].startswith("id_token") and flow_type=="code" and allow_id_none_in_code_flow:
                # 예외적으로 허용(등록 명시 전제) → 경고만 남김
                warn("A3", "ID Token alg=none observed in code flow (policy exception)",
                     "등록에 명시된 경우에만 제한적으로 허용. 기본은 금지 권장.", {"token_kind": t["kind"]})
            else:
                a2_fail = True
                fail("A3", "alg=none not allowed",
                     "alg 'none'은 무결성 붕괴. AT-JWT는 항상 금지, ID 토큰도 프런트채널 금지(코드플로우+등록 명시 예외 한정).",
                     {"token_kind": t["kind"]})
    A["alg_none_forbidden"] = {"result": "Fail" if a2_fail else "Pass"}

    # A3 Access Token typ 확인 (RFC 9068)
    a3_ok = True
    a3_adv = False
    for t in observed_tokens:
        if t["kind"] != "access_token": continue
        typ = (t["header"].get("typ") or "")
        if typ.lower() != "at+jwt":
            if strict_at_typ:
                a3_ok = False
                fail("A4", "Access Token typ not 'at+jwt'", "RFC 9068에 따라 typ='at+jwt' 확인이 권장/요구됨.", {"header": t["header"]})
            else:
                a3_adv = True
                warn("A4", "Access Token typ not 'at+jwt'",
                     "RFC 9068 권고/요구. 공급자에 따라 'JWT'만 넣기도 함 — 정책에 맞게 판단.", {"header": t["header"]})
    A["access_token_typ_atjwt"] = {"result": ("Fail" if not a3_ok else ("Advisory" if a3_adv else "Pass"))}

    # A4 HS* 사용 경고 및 혼용 감시
    kinds_by_alg = {}
    for t in observed_tokens:
        alg = (t["header"].get("alg") or "").upper()
        kinds_by_alg.setdefault(alg, set()).add(t["kind"])
        if alg.startswith("HS"):
            warn("A5", "HS* 알고리즘 사용 관찰", "동일 발행자 환경에서 HS ↔ RS/ES/PS 혼용은 구현 혼동 표면.", {"token_kind": t["kind"], "alg": alg})
    if len([a for a in kinds_by_alg.keys() if a.startswith(("RS","PS","ES"))])>0 and any(a.startswith("HS") for a in kinds_by_alg):
        warn("A6", "알고리즘 혼용 관찰", f"관찰 집합: {list(kinds_by_alg.keys())}", {"by_alg": {a:list(k) for a,k in kinds_by_alg.items()}})
    A["hs_usage_and_mixing"] = {"result": "Advisory"}

    # ---------------- B. 키 출처 & 헤더 기반 키 주입 ----------------
    # B1 jku/x5u/jwk/x5c 존재 여부
    b1_fail = False; b1_adv = False
    for t in observed_tokens:
        h = t["header"]
        hit_fail = False
        for f in ("jku","jwk","x5u"):
            if f in h:
                hit_fail = True
                b1_fail = True
        if hit_fail:
            fail("B1", "Header-supplied key reference present (jku/jwk/x5u)",
                 "키 출처는 discovery.jwks_uri로 고정. 헤더 기반 URL/객체는 키 주입/SSRF 표면.", {"token_kind": t["kind"], "header": h})
        if "x5c" in h:
            b1_adv = True
            warn("B2", "x5c 체인 동봉 관찰", "일부 공급자 관행이지만 키 출처 혼동 유발 가능 — jwks_uri 고정 권장.", {"token_kind": t["kind"]})
        # kid 위생
        kid = h.get("kid")
        if _kid_weird(kid):
            warn("B3", "kid 값 비정상 패턴", "내부 인덱스 전용이어야 하며 경로/URL 등 금지.", {"kid": kid, "token_kind": t["kind"]})
    B["header_key_references"] = {"result": "Fail" if b1_fail else ("Advisory" if b1_adv else "Pass")}

    # B2 jwks_uri 존재 및 HTTPS
    disc = fb.discovery or {}
    jwks_uri = disc.get("jwks_uri")
    if not jwks_uri:
        warn("B4", "jwks_uri missing", "키 출처 고정을 위해 jwks_uri 제공 권장.", {})
        B["jwks_uri_https"] = {"result":"Advisory", "note":"missing"}
    else:
        scheme = urlparse(jwks_uri).scheme.lower()
        if scheme != "https":
            fail("B4", "jwks_uri must be https", "키 출처는 HTTPS로 고정되어야 함.", {"jwks_uri": jwks_uri})
            B["jwks_uri_https"] = {"result":"Fail", "observed":{"jwks_uri": jwks_uri}}
        else:
            B["jwks_uri_https"] = {"result":"Pass", "observed":{"jwks_uri": jwks_uri}}

    # ---------------- C. 정책/바인딩/crit ----------------
    # C1 crit 헤더 처리 엄수(모르면 거부)
    c1_fail = False
    KNOWN_CRIT = {"b64"}  # (예: detached payload에서 사용). 실제 처리 미확인 환경에선 Fail로 두는 것이 안전.
    for t in observed_tokens:
        crit = t["header"].get("crit")
        if not crit: continue
        # 리스트가 아닌 값/알 수 없는 확장값 → Fail
        if not isinstance(crit, list) or any((c not in KNOWN_CRIT) for c in crit):
            c1_fail = True
            fail("C1", "Unsupported 'crit' header parameter(s)",
                 "이해하지 못한 'crit' 파라미터가 있으면 MUST reject.", {"token_kind": t["kind"], "crit": crit})
    C["crit_header_handling"] = {"result":"Fail" if c1_fail else "Pass"}

    # C2 발행자 단위 혼용 탐지(인퍼런스)
    by_iss_algs = {}
    for t in observed_tokens:
        iss = (t["payload"] or {}).get("iss")
        alg = (t["header"].get("alg") or "").upper()
        if iss:
            by_iss_algs.setdefault(iss,set()).add(alg)
    if any(len(v)>1 for v in by_iss_algs.values()):
        warn("C2","동일 발행자 내 알고리즘 혼용 관찰","운영 정책 상 백엔드·클라이언트 혼동 위험. 단일 핀닝 권장.", {"by_iss": {k:list(v) for k,v in by_iss_algs.items()}})
    C["issuer_algorithm_mixing"] = {"result":"Advisory"}

    # 최종 ok
    ok = len(failures)==0

    # 관찰값 요약
    observed = {
        "flow_type": flow_type,
        "allowed_algs": sorted(list(allowed)),
        "tokens": [
            {"kind": t["kind"],
             "alg": t["header"].get("alg"),
             "typ": t["header"].get("typ"),
             "kid": t["header"].get("kid"),
             "extra_headers": {k:v for k,v in t["header"].items() if k in ("jku","x5u","jwk","x5c","crit")}
            } for t in observed_tokens
        ]
    }

    return {
        "ok": ok,
        "failures": failures,
        "warnings": warnings,
        "flow_type": flow_type,
        "observed": observed,
        "checklist": checklist
    }

# ---------------- Pretty report ----------------
def pretty_report(res: Dict[str,Any]) -> str:
    j = res; out = []
    out.append(f"Flow: {j.get('flow_type')}  Overall: {'PASS' if j.get('ok') else 'FAIL'}\n")
    def dump(title, sec):
        out.append(f"== {title} ==")
        for k,v in sec.items():
            out.append(f"- {k}: {v.get('result')}")
            note = v.get("observed") or v.get("note")
            if note: out.append(f"  • {note}")
        out.append("")
    dump("A. Algorithm & typ", j["checklist"]["A"])
    dump("B. Key Source & Headers", j["checklist"]["B"])
    dump("C. Policy & Binding", j["checklist"]["C"])

    if j.get("failures"):
        out.append("Failures:")
        for f in j["failures"]:
            out.append(f" - [{f['code']}] {f['title']} :: {f['detail']} :: evidence={f.get('evidence')}")
        out.append("")
    if j.get("warnings"):
        out.append("Warnings:")
        for w in j["warnings"]:
            out.append(f" - [{w['code']}] {w['title']} :: {w['detail']} :: evidence={w.get('evidence')}")
        out.append("")
    return "\n".join(out)

if __name__ == "__main__":
    import sys
    try:
        raw = json.load(sys.stdin)
    except Exception:
        sys.stderr.write("Provide a JSON flow bundle via stdin.\n")
        raise
    print(pretty_report(run_checks(raw)))

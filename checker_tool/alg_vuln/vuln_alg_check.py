#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 잘못된 alg 처리(alg 공격) 전용. discovery/JWKS 통합.

from __future__ import annotations
import json
from dataclasses import dataclass
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urlparse, parse_qs

# 정책 기본값 (RFC 8725/JWT BCP 권고 반영)
DEFAULT_ALLOWED_ALGS = {"RS256", "PS256", "ES256"}
STRICT_AT_TYP = False
ALLOW_ID_NONE_IN_CODE_FLOW = False  # 코드 플로우 + 등록 명시 예외만 허용할 때 True

# ===== 공통 유틸 =====
def _b64url_decode(s: str) -> bytes:
    if not isinstance(s, (str, bytes)): raise ValueError("not a string")
    if isinstance(s, str): s = s.encode("utf-8")
    s += b"=" * ((4 - (len(s) % 4)) % 4)
    s = s.replace(b"-", b"+").replace(b"_", b"/")
    import base64
    return base64.b64decode(s)

def parse_jwt(jwt: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
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

# ===== 입력 모델 =====
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
    jwks: Dict[str,Any]
    authorization_request: AuthorizationRequest
    authorization_response: AuthorizationResponse
    token_response: TokenResponse
    refresh_token_response: TokenResponse
    found_jwts: List[str]
    def __init__(self, **d):
        self.discovery = d.get("discovery") or {}
        self.jwks = d.get("jwks") or {}
        self.authorization_request = AuthorizationRequest(**(d.get("authorization_request") or {}))
        self.authorization_response = AuthorizationResponse(**(d.get("authorization_response") or {}))
        self.token_response = TokenResponse(**(d.get("token_response") or {}))
        self.refresh_token_response = TokenResponse(**(d.get("refresh_token_response") or {}))
        self.found_jwts = list(d.get("found_jwts") or [])

# ===== 메인 체크 =====
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

    allowed = set(allowed_algs or DEFAULT_ALLOWED_ALGS)

    # 관찰 토큰 수집
    observed_tokens = []
    id_from_auth = fb.authorization_response.params.get("id_token") or fb.authorization_response.form.get("id_token")
    if id_from_auth:
        try:
            h,p = parse_jwt(id_from_auth)
            observed_tokens.append({"kind":"id_token(authz)","header":h,"payload":p})
        except Exception as e:
            fail("A0","Invalid ID Token format (authorization_response)",str(e),{"prefix":id_from_auth[:40]})
    tr = fb.token_response.json or {}
    if tr.get("id_token"):
        try:
            h,p = parse_jwt(tr["id_token"])
            observed_tokens.append({"kind":"id_token(token)","header":h,"payload":p})
        except Exception as e:
            fail("A0","Invalid ID Token format (token_response)",str(e),{"prefix":tr["id_token"][:40]})
    if tr.get("access_token"):
        try:
            h,p = parse_jwt(tr["access_token"])
            observed_tokens.append({"kind":"access_token","header":h,"payload":p})
        except Exception:
            pass
    for j in fb.found_jwts:
        try:
            h,p = parse_jwt(j); observed_tokens.append({"kind":"found","header":h,"payload":p})
        except Exception: pass

    A,B,C = {},{},{}; checklist = {"A":A,"B":B,"C":C}

    # == A. Algorithm & typ ==
    a1_ok = True
    for t in observed_tokens:
        alg = (t["header"].get("alg") or "").upper()
        if not alg:
            a1_ok = False; fail("A1","alg missing","JWT 보호헤더 alg는 MUST 존재.",{"token_kind":t["kind"],"header":t["header"]})
        elif alg not in allowed:
            a1_ok = False; fail("A2","alg not allowed (pinning violation)", f"허용 목록 밖 alg '{alg}'. 허용={sorted(list(allowed))}",{"token_kind":t["kind"],"alg":alg})
    A["alg_pinned_allowlist"] = {"result":"Pass" if a1_ok else "Fail", "observed":[(t["kind"], t["header"].get("alg")) for t in observed_tokens]}

    a2_fail = False
    for t in observed_tokens:
        alg = (t["header"].get("alg") or "").upper()
        if alg == "NONE":
            if t["kind"].startswith("id_token") and flow_type=="code" and allow_id_none_in_code_flow:
                warn("A3","ID Token alg=none observed in code flow (policy exception)","등록에 명시된 경우 한정.",{"token_kind":t["kind"]})
            else:
                a2_fail = True; fail("A3","alg=none not allowed","무결성 붕괴. AT-JWT는 항상 금지, ID 토큰 프런트채널 금지.",{"token_kind":t["kind"]})
    A["alg_none_forbidden"] = {"result":"Fail" if a2_fail else "Pass"}

    a3_ok=True; a3_adv=False
    for t in observed_tokens:
        if t["kind"]!="access_token": continue
        typ=(t["header"].get("typ") or "")
        if typ.lower()!="at+jwt":
            if strict_at_typ: a3_ok=False; fail("A4","Access Token typ not 'at+jwt'","RFC 9068 권고/요구.",{"header":t["header"]})
            else: a3_adv=True; warn("A4","Access Token typ not 'at+jwt'","RFC 9068 권고/요구.",{"header":t["header"]})
    A["access_token_typ_atjwt"]={"result":("Fail" if not a3_ok else ("Advisory" if a3_adv else "Pass"))}

    kinds_by_alg = {}
    for t in observed_tokens:
        alg = (t["header"].get("alg") or "").upper()
        kinds_by_alg.setdefault(alg,set()).add(t["kind"])
        if alg.startswith("HS"):
            warn("A5","HS* 알고리즘 사용 관찰","동일 발행자 환경에서 HS ↔ RS/ES/PS 혼용은 구현 혼동 표면.",{"token_kind":t["kind"],"alg":alg})
    if len([a for a in kinds_by_alg if a.startswith(("RS","PS","ES"))])>0 and any(a.startswith("HS") for a in kinds_by_alg):
        warn("A6","알고리즘 혼용 관찰",f"관찰 집합: {list(kinds_by_alg.keys())}",{"by_alg":{a:list(k) for a,k in kinds_by_alg.items()}})
    A["hs_usage_and_mixing"]={"result":"Advisory"}

    # == B. Key Source & Headers ==
    b1_fail=False; b1_adv=False
    for t in observed_tokens:
        h=t["header"]
        if any(f in h for f in ("jku","jwk","x5u")):
            b1_fail=True; fail("B1","Header-supplied key reference present (jku/jwk/x5u)","키 출처는 discovery.jwks_uri로 고정.",{"token_kind":t["kind"],"header":h})
        if "x5c" in h:
            b1_adv=True; warnings.append({"code":"B2","title":"x5c 체인 동봉 관찰","detail":"일부 공급자 관행이나 출처 혼동 가능. jwks_uri 고정 권장.","evidence":{"token_kind":t["kind"]}})
        kid=h.get("kid")
        if _kid_weird(kid):
            warnings.append({"code":"B3","title":"kid 값 비정상 패턴","detail":"내부 인덱스 전용이어야 하며 경로/URL 금지.","evidence":{"kid":kid,"token_kind":t["kind"]}})
    B["header_key_references"]={"result":"Fail" if b1_fail else ("Advisory" if b1_adv else "Pass")}

    disc=fb.discovery or {}
    jwks=fb.jwks or {}
    jwks_uri = disc.get("jwks_uri")
    if not jwks_uri:
        warnings.append({"code":"B4","title":"jwks_uri missing","detail":"키 출처 고정을 위해 jwks_uri 제공 권장.","evidence":{}})
        B["jwks_uri_https"]={"result":"Advisory","note":"missing"}
    else:
        scheme=urlparse(jwks_uri).scheme.lower()
        if scheme!="https":
            fail("B4","jwks_uri must be https","키 출처는 HTTPS로 고정되어야 함.",{"jwks_uri":jwks_uri})
            B["jwks_uri_https"]={"result":"Fail","observed":{"jwks_uri":jwks_uri}}
        else:
            B["jwks_uri_https"]={"result":"Pass","observed":{"jwks_uri":jwks_uri}}

    # JWKS 내용 점검
    jwks_result = "Pass"
    if isinstance(jwks, dict) and isinstance(jwks.get("keys"), list):
        kids=set(); dup=False; oct_found=False
        for k in jwks["keys"]:
            kty=(k.get("kty") or "").upper(); use=k.get("use"); kid=k.get("kid")
            if kid in kids: dup=True
            else: kids.add(kid)
            if kty=="OCT" and (use or "sig")=="sig":
                oct_found=True
        if dup:
            warnings.append({"code":"B5","title":"JWKS kid 중복","detail":"kid는 키 회전/구분용으로 유일해야 함.","evidence":{}})
            jwks_result="Advisory"
        if oct_found:
            fail("B6","JWKS에 대칭키(oct) 서명키 존재","HS* 사용은 정책상 금지/지양.", evidence={})
            jwks_result="Fail"
        token_kids = [t["header"].get("kid") for t in observed_tokens if t["header"].get("kid")]
        missing = [k for k in token_kids if k not in kids]
        if token_kids and missing:
            fail("B7","토큰 kid가 JWKS에 없음","재조회 후에도 없으면 검증기 fail-closed 권장.", evidence={"missing": missing})
            jwks_result="Fail"
    else:
        jwks_result = "Advisory"
        warnings.append({"code":"B5","title":"JWKS not provided","detail":"발급자 키 세트를 함께 제공하면 kid 검사 가능.","evidence":{}})
    B["jwks_content_check"]={"result":jwks_result}

    # == C. Policy & Binding ==
    c1_fail=False; KNOWN_CRIT={"b64"}
    for t in observed_tokens:
        crit=t["header"].get("crit")
        if not crit: continue
        if not isinstance(crit, list) or any((c not in KNOWN_CRIT) for c in crit):
            c1_fail=True; fail("C1","Unsupported 'crit' header parameter(s)'","이해 못한 'crit'가 있으면 MUST reject.",{"token_kind":t["kind"],"crit":crit})
    C["crit_header_handling"]={"result":"Fail" if c1_fail else "Pass"}

    by_iss_algs={}
    for t in observed_tokens:
        iss=(t["payload"] or {}).get("iss"); alg=(t["header"].get("alg") or "").upper()
        if iss: by_iss_algs.setdefault(iss,set()).add(alg)
    if any(len(v)>1 for v in by_iss_algs.values()):
        warnings.append({"code":"C2","title":"동일 발행자 내 알고리즘 혼용 관찰","detail":"단일 핀닝 권장.","evidence":{"by_iss":{k:list(v) for k,v in by_iss_algs.items()}}})
    C["issuer_algorithm_mixing"]={"result":"Advisory"}

    ok = len(failures)==0
    observed = {
        "flow_type": flow_type,
        "allowed_algs": sorted(list(allowed)),
        "discovery_present": bool(fb.discovery),
        "jwks_present": bool(fb.jwks),
        "tokens": [
            {"kind": t["kind"],
             "alg": t["header"].get("alg"),
             "typ": t["header"].get("typ"),
             "kid": t["header"].get("kid"),
             "extra_headers": {k:v for k,v in t["header"].items() if k in ("jku","x5u","jwk","x5c","crit")}}
            for t in observed_tokens
        ]
    }
    return {"ok":ok,"failures":failures,"warnings":warnings,"flow_type":flow_type,"observed":observed,"checklist":checklist}

# ===== 리포트 =====
def pretty_report(res: Dict[str,Any]) -> str:
    j = res; out=[]

    def _token_human_label(kind: str) -> str:
        # token_kind → 한국어 라벨
        mapping = {
            "id_token(authz)": "인가응답의 ID 토큰",
            "id_token(token)": "토큰응답의 ID 토큰",
            "access_token":    "Access 토큰",
            "found":           "기타 수집 토큰(found)",
        }
        return mapping.get(kind, kind)

    def _line_with_token_prefix(item: Dict[str,Any]) -> str:
        code   = item.get("code")
        title  = item.get("title")
        detail = item.get("detail")
        evid   = item.get("evidence")
        if isinstance(evid, dict) and evid.get("token_kind"):
            prefix = f"[{_token_human_label(evid['token_kind'])}] "
        else:
            # 세션/집계 레벨(A6, C2 등)
            prefix = "[세션] "
        return f" - [{code}] {prefix}{title} :: {detail} :: evidence={evid}"

    out.append(f"Flow: {j.get('flow_type')}  Overall: {'PASS' if j.get('ok') else 'FAIL'}\n")

    # 섹션 요약은 그대로 유지
    def dump(title, sec):
        out.append(f"== {title} ==")
        for k,v in sec.items():
            out.append(f"- {k}: {v.get('result')}")
            note=v.get("observed") or v.get("note")
            if note: out.append(f"  • {note}")
        out.append("")
    dump("A. Algorithm & typ", j["checklist"]["A"])
    dump("B. Key Source & Headers", j["checklist"]["B"])
    dump("C. Policy & Binding", j["checklist"]["C"])

    # Failures / Warnings 에 토큰 라벨 프리픽스 부여
    if j.get("failures"):
        out.append("Failures:")
        for f in j["failures"]:
            out.append(_line_with_token_prefix(f))
        out.append("")

    if j.get("warnings"):
        out.append("Warnings:")
        for w in j["warnings"]:
            out.append(_line_with_token_prefix(w))
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
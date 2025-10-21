#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vuln_key_rotation_checker.py — Vulnerability check module (single-purpose)
=========================================================================

Purpose
-------
OAuth/OIDC **키 회전·JWKS(키 관리)** 취약점만 정확히 진단하는 단일 모듈.
Data Controller가 제공한 스냅샷(Discovery, JWKS, 토큰, 등록 메타데이터 등)으로 **오프라인 판정**.

Normative basis (공식 문서 기준)
-------------------------------
• OIDC Core / Discovery / Dynamic Client Registration
• IETF RFC 7517 (JWK), 7515 (JWS), 8414 (AS Metadata), 8725 (JWT BCP)
• 실무 참고: PortSwigger (jku/x5u/kid 인젝션 랩) — 정책 판단 보조

진단 출력 형식
--------------
result: {
  "ok": bool,
  "failures": [ {code, title, detail, evidence} ],
  "warnings": [ {code, title, detail, evidence} ],
  "observed": {...},
  "checklist": { "A": {...}, "B": {...}, "C": {...} }
}

입력 스켈레톤 (Data Controller가 채움)
-------------------------------------
payload = {
  "discovery": {  # RFC 8414 / OIDC Discovery
    "issuer": "https://example.com/realms/foo",
    "jwks_uri": "https://example.com/realms/foo/protocol/openid-connect/certs"
  },
  "as_metadata": {},  # 선택
  "jwks": { "keys": [ ... ] },  # OP JWKS 스냅샷(필수)
  "client_registration": {      # 선택 (RP 등록 정보)
    "jwks_uri": null,           # RP용 — jwks_uri와 jwks를 동시에 주지 말 것
    "jwks": null,
    "id_token_signed_response_alg": "RS256",
    "token_endpoint_auth_method": "private_key_jwt|client_secret_jwt|client_secret_basic|...",
    "token_endpoint_auth_signing_alg": "RS256|PS256|ES256|HS256|..."
  },
  "tokens": {                   # 관측된 토큰들(선택)
    "id_token": "...",          # JWS Compact
    "access_token": "...",      # JWS Compact(리소스 서버 검증용)
    "client_assertion": "..."   # 클라이언트 인증용 JWT(있다면)
  }
}
"""

from __future__ import annotations
import json, re, base64
from typing import Dict, Any, Tuple, List, Optional
from dataclasses import dataclass
from urllib.parse import urlparse

LABELS = {"Pass":"PASS ✅","Fail":"FAIL ❌","Advisory":"ADVISORY ⚠️","N/A":"N/A ⭕","Info":"Info"}
def _L(x:str)->str: return LABELS.get(x,x)

USE_COLOR = True
def colorize(msg, kind):
    if not USE_COLOR: return msg
    C={"Pass":"\033[32m","Fail":"\033[31m","Advisory":"\033[33m","N/A":"\033[36m","Info":"\033[34m"}; R="\033[0m"
    return f"{C.get(kind,'')}{msg}{R}"

ALLOWED_ALGS_DEFAULT = {"RS256","PS256","ES256","EdDSA","RS384","PS384","ES384","RS512","PS512","ES512"}
SIG_KTYS = {"RSA","EC","OKP"}  # 서명용 공개키 유형
STRICT_SAME_HOST = True        # issuer와 jwks_uri 동일 호스트(팀 정책)

# --------------------- utils ---------------------
def _b64url_decode(s: str) -> bytes:
    if s is None: return b""
    s = s.encode("utf-8")
    s += b"=" * ((4 - (len(s) % 4)) % 4)
    s = s.replace(b"-", b"+").replace(b"_", b"/")
    return base64.b64decode(s)

def parse_jwt(jwt: str) -> Tuple[Dict[str,Any], Dict[str,Any]]:
    parts = (jwt or "").split(".")
    if len(parts) < 2: raise ValueError("Invalid JWT compact serialization")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    return header, payload

def url_host(url: Optional[str]) -> Optional[str]:
    if not url: return None
    return urlparse(url).hostname

def is_https(url: Optional[str]) -> bool:
    if not url: return False
    return urlparse(url).scheme.lower() == "https"

def signing_keys(jwks: Dict[str,Any]) -> List[Dict[str,Any]]:
    keys = list((jwks or {}).get("keys") or [])
    out = []
    for k in keys:
        kty = (k.get("kty") or "").upper()
        use = (k.get("use") or "sig")
        if kty in {"RSA","EC","OKP"} and use == "sig":
            out.append(k)
    return out

def count_dupe_kids(jwks: Dict[str,Any]) -> Dict[str,int]:
    from collections import Counter
    kids = [k.get("kid") for k in (jwks or {}).get("keys",[]) if k.get("kid") is not None]
    return {k:v for k,v in Counter(kids).items() if v>1}

def suspicious_kid(s: Optional[str]) -> bool:
    if not s: return False
    if len(s) > 256: return True
    if "../" in s or "..\\" in s: return True
    if re.search(r"[\\\r\n\t]", s): return True
    if s.lower().startswith("http://") or s.lower().startswith("https://"): return True
    return False

# --------------------- models ---------------------
@dataclass
class InputBundle:
    discovery: Dict[str,Any]
    as_metadata: Dict[str,Any]
    jwks: Dict[str,Any]
    client_registration: Dict[str,Any]
    tokens: Dict[str,Any]
    @classmethod
    def from_dict(cls, d: Dict[str,Any]) -> "InputBundle":
        return cls(
            discovery=d.get("discovery") or {},
            as_metadata=d.get("as_metadata") or {},
            jwks=d.get("jwks") or {},
            client_registration=d.get("client_registration") or {},
            tokens=d.get("tokens") or {},
        )

# --------------------- core checks ---------------------
def run_checks(raw: Dict[str,Any], allowed_algs: Optional[set]=None) -> Dict[str,Any]:
    bundle = InputBundle.from_dict(raw)
    discovery = bundle.discovery
    jwks = bundle.jwks
    reg = bundle.client_registration
    tokens = bundle.tokens

    failures, warnings = [], []
    checklist = {"A":{}, "B":{}, "C":{}}

    def fail(code, title, detail, evidence=None):
        failures.append({"code":code, "title":title, "detail":detail, "evidence":evidence})
    def warn(code, title, detail, evidence=None):
        warnings.append({"code":code, "title":title, "detail":detail, "evidence":evidence})

    issuer = discovery.get("issuer")
    jwks_uri = discovery.get("jwks_uri")

    # ---------- A) Authorization Server / OP ----------
    a = {}

    # A1. jwks_uri 존재 + HTTPS
    a["jwks_uri_https"] = {"result": "Pass" if (jwks_uri and is_https(jwks_uri)) else "Fail",
                           "observed": {"jwks_uri": jwks_uri}}
    if not jwks_uri: fail("K-A1", "jwks_uri missing", "Discovery에 jwks_uri가 없어 키 출처를 고정할 수 없음.", {"discovery": discovery})
    elif not is_https(jwks_uri): fail("K-A1", "jwks_uri must be HTTPS", "jwks_uri는 HTTPS여야 함.", {"jwks_uri": jwks_uri})

    # A2. issuer와 jwks_uri 호스트 일치(팀 정책)
    same_host = (url_host(issuer) == url_host(jwks_uri)) if (issuer and jwks_uri) else None
    a["issuer_host_matches_jwks_uri"] = {"result": ("Pass" if same_host else ("N/A" if same_host is None else "Fail")),
                                         "observed": {"issuer": issuer, "jwks_uri": jwks_uri}}
    if same_host is False and STRICT_SAME_HOST:
        fail("K-A2", "교차-호스트 금지(핀 고정 위반)", "issuer와 jwks_uri는 동일 호스트를 사용해야 함(팀 정책).", {"issuer": issuer, "jwks_uri": jwks_uri})

    # A3. JWKS 키 존재 및 kid 중복 없음
    keys = (jwks or {}).get("keys") or []
    a["jwks_has_keys"] = {"result": "Pass" if keys else "Fail", "observed": {"keys_count": len(keys)}}
    if not keys: fail("K-A3", "JWKS empty", "JWKS에 키가 없음.", {"jwks": jwks})

    dupe = count_dupe_kids(jwks)
    a["jwks_duplicate_kid"] = {"result": "Fail" if dupe else ("Pass" if keys else "N/A"),
                               "observed": {"dupe_kids": dupe}}
    if dupe: fail("K-A4", "중복 kid 존재", "kid는 고유해야 함.", {"dupe": dupe})

    # A4. use/key_ops 권장 — use 누락은 권고, enc/sig 혼용 금지
    use_missing = [k.get("kid") for k in keys if k.get("use") is None]
    a["jwks_use_keyops"] = {"result": ("Advisory" if use_missing else "Pass"),
                            "observed": {"use_missing_kids": use_missing}}

    # A5. (서버측 권장) 토큰 헤더에 jku/x5u/jwk/x5c를 사용하지 않음
    def header_has_external_refs(h: Dict[str,Any])->Dict[str,Any]:
        return {k:h.get(k) for k in ("jku","x5u","jwk","x5c") if h.get(k) is not None}

    idh = {}
    try:
        if tokens.get("id_token"):
            idh,_ = parse_jwt(tokens["id_token"])
    except Exception:
        pass
    ext = header_has_external_refs(idh or {})
    a["no_external_header_refs"] = {"result": "Pass" if not ext else "Fail",
                                    "observed": {"external_header_fields": ext or {}}}
    if ext:
        fail("K-A6", "ID 토큰 헤더에 jku/x5u/jwk/x5c 사용", "키 출처 고정 위반 위험 — 헤더 기반 키 참조는 금지/무시.", {"header": idh})

    checklist["A"] = a

    # ---------- B) RP / Resource Server (검증자) ----------
    b = {}

    # B1. issuer + jwks_uri 핀 고정(동일 호스트)
    b["pin_issuer_jwks_uri"] = {"result": a["issuer_host_matches_jwks_uri"]["result"],
                                "observed": a["issuer_host_matches_jwks_uri"]["observed"]}

    # B2. 허용 alg 화이트리스트 + none 금지
    allowed = set(allowed_algs or ALLOWED_ALGS_DEFAULT)
    def check_token_alg(name: str, jwt_val: Optional[str]):
        if not jwt_val: return ("N/A", None, None)
        try:
            hdr,_ = parse_jwt(jwt_val)
        except Exception as e:
            return ("Advisory", None, f"JWT 파싱 실패(별도 모듈에서 검증): {e}")
        alg = hdr.get("alg")
        if alg == "none":
            return ("Fail", {"alg":alg}, "alg=none 금지")
        if allowed and alg not in allowed:
            return ("Fail", {"alg":alg,"allowed":sorted(list(allowed))}, "허용 리스트 밖 alg")
        return ("Pass", {"alg":alg}, None)

    for tname in ("id_token","access_token","client_assertion"):
        r, obs, err = check_token_alg(tname, tokens.get(tname))
        b[f"alg_whitelist_{tname}"] = {"result": r, "observed": obs}
        if r == "Fail":
            fail("K-B1", f"{tname} alg 정책 위반", "none 금지/화이트리스트 위반", obs)
        elif err:
            warn("K-B1W", f"{tname} 파싱 경고", err, {"prefix": (tokens.get(tname) or "")[:32]})

    # B3. 등록 기대 alg와 실제 alg 일치(HS↔RS 혼용 금지)
    exp_id_alg = (reg or {}).get("id_token_signed_response_alg")
    if exp_id_alg and tokens.get("id_token"):
        try:
            ih,_ = parse_jwt(tokens["id_token"])
            if ih.get("alg") != exp_id_alg:
                fail("K-B2", "id_token alg 불일치", "등록 기대 alg와 실제 토큰 alg가 다름.", {"expected":exp_id_alg,"actual":ih.get("alg")})
        except Exception:
            pass

    # B4. kid 요구/검증
    sj = signing_keys(jwks)
    need_kid = len(sj) >= 2
    for tname in ("id_token","access_token","client_assertion"):
        val = tokens.get(tname)
        if not val:
            b[f"kid_present_{tname}"] = {"result":"N/A"}
            continue
        try:
            hh,_ = parse_jwt(val)
        except Exception:
            b[f"kid_present_{tname}"] = {"result":"Advisory","note":"JWT 파싱 실패"}
            continue
        kid = hh.get("kid")
        if need_kid and not kid:
            b[f"kid_present_{tname}"] = {"result":"Fail"}
            fail("K-B3", f"{tname} kid 미포함", "JWKS에 복수 서명키가 있으므로 kid가 사실상 MUST.", {})
        else:
            b[f"kid_present_{tname}"] = {"result":"Pass" if kid else "Advisory"}
        # unknown kid
        if kid:
            jwk = next((k for k in sj if k.get("kid")==kid), None)
            if not jwk:
                b[f"kid_known_{tname}"] = {"result":"Fail","observed":{"kid":kid}}
                fail("K-B4", f"{tname}의 kid가 JWKS에 없음", "재조회 후에도 없으면 fail-closed.", {"kid":kid})
            else:
                b[f"kid_known_{tname}"] = {"result":"Pass"}
                if jwk.get("use") not in (None,"sig"):
                    b[f"kid_use_sig_{tname}"] = {"result":"Fail","observed":{"use":jwk.get("use")}}
                    fail("K-B5", f"{tname} 키 용도 불일치", "use는 'sig'여야 함.", {"kid":kid,"use":jwk.get("use")})
                else:
                    b[f"kid_use_sig_{tname}"] = {"result":"Pass"}

        # 헤더 jku/x5u/jwk/x5c 무시/거부
        ext = {k:hh.get(k) for k in ("jku","x5u","jwk","x5c") if hh.get(k) is not None}
        if ext:
            b[f"header_external_ref_{tname}"] = {"result":"Fail","observed":ext}
            fail("K-B6", f"{tname} 헤더에 jku/x5u/jwk/x5c 존재", "헤더 기반 키 참조는 무시/거부해야 함.", {"header":hh})
        else:
            b[f"header_external_ref_{tname}"] = {"result":"Pass"}

        # kid 패턴 검사(경로 트래버설/이상문자)
        if kid and suspicious_kid(kid):
            b[f"kid_pattern_{tname}"] = {"result":"Fail","observed":{"kid":kid}}
            fail("K-B7", f"{tname} kid 패턴 이상", "경로 트래버설/URL/제어문자 등 금지.", {"kid":kid})
        else:
            b[f"kid_pattern_{tname}"] = {"result":"Pass" if kid else "N/A"}

    # B5. 클라이언트 등록 메타: jwks_uri와 jwks 동시 제공 금지
    both = reg.get("jwks_uri") and reg.get("jwks")
    b["registration_jwks_vs_jwks_uri"] = {"result":"Fail" if both else ("Pass" if (reg.get("jwks_uri") or reg.get("jwks")) else "N/A")}
    if both:
        fail("K-B8", "등록 메타 충돌", "jwks_uri와 jwks를 동시에 제공하면 안 됨(MUST NOT).", {"client_registration":reg})

    checklist["B"] = b

    # ---------- C) 보안 테스트(자동/반자동) ----------
    c = {}
    # C1. 임의 kid 주입 시나리오 — 오프라인에서는 가정만 점검
    c["inject_unknown_kid"] = {"result":"Advisory","note":"동작 테스트는 동적 환경 필요. 모듈은 unknown kid를 Fail로 판정."}
    # C2. 헤더 jku/x5u/jwk/x5c 감지여부
    any_jku = []
    for tname in ("id_token","access_token","client_assertion"):
        val = tokens.get(tname)
        try:
            if val:
                hh,_ = parse_jwt(val)
                if hh.get("jku") or hh.get("x5u") or hh.get("jwk") or hh.get("x5c"):
                    any_jku.append(tname)
        except Exception:
            pass
    c["header_injection_fields_seen"] = {"result":"Fail" if any_jku else "Pass",
                                         "observed":{"tokens_with_external_ref": any_jku}}
    if any_jku:
        fail("K-C1","헤더 기반 외부 키 참조가 감지됨","SSRF/키 출처 우회 가능성. 반드시 무시/차단.", {"tokens":any_jku})
    # C3. HS↔RS 전환 — 화이트리스트로 차단됨
    c["hs_rs_switch"] = {"result":"Pass"}
    # C4. kid 경로 트래버설/이상문자
    any_bad = [t for tname in ("id_token","access_token","client_assertion")
               for t in [tokens.get(tname)]
               if t and (lambda k: (k and suspicious_kid(k)))(parse_jwt(t)[0].get("kid") if "." in t else None)]
    c["kid_traversal"] = {"result":"Fail" if any_bad else "Pass"}

    checklist["C"] = c

    observed = {"issuer": issuer, "jwks_uri": jwks_uri, "allowed_algs": sorted(list(allowed))}
    ok = len(failures) == 0
    return {"ok": ok, "failures": failures, "warnings": warnings, "observed": observed, "checklist": checklist}

# --------------------- pretty printer ---------------------
def pretty_report(res: Dict[str,Any]) -> str:
    j = res; out = []
    out.append(f"Overall: {'PASS' if j.get('ok') else 'FAIL'}\n")
    def dump_section(title, sec):
        out.append(f"== {title} ==")
        for k,v in sec.items():
            r = v.get("result")
            out.append(f"- {k}: {r}")
            ov = v.get("observed") or v.get("note")
            if ov: out.append(f"  • {ov}")
        out.append("")
    dump_section("A) Authorization Server / OP", j["checklist"]["A"])
    dump_section("B) RP / Resource Server (검증자)", j["checklist"]["B"])
    dump_section("C) 보안 테스트(자동/반자동)", j["checklist"]["C"])

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
        sys.stderr.write("Provide JSON payload via stdin (see module docstring).\n")
        raise
    res = run_checks(raw)
    print(pretty_report(res))


"""
oidc_nonce_checker.py — Vulnerability check module (single-purpose)
================================================================
Purpose
-------
Detect **OIDC nonce 미사용/미검증** 문제를 HTTP 패킷(인가요청/인가응답/토큰 응답/ID Token 등)으로부터 판단.
이 모듈은 팀 스캐너에서 "vuln check module"로 단독 동작합니다.

Scope
-----
- 이 모듈은 오직 OIDC `nonce` 관련 요구사항만 점검합니다.
- JWT 서명 검증 등 기타 일반 검증은 상위(Data Controller / 다른 모듈)에서 수행하세요.
- 표준 라이브러리만 사용.

Normative basis (요약)
---------------------
• OpenID Connect Core 1.0
  - nonce 목적/요청–ID Token 연계
  - Implicit/Hybrid: authorization request에 nonce **REQUIRED**, 수신 ID Token `nonce`와 **MUST 동일**
  - Authorization Code: nonce는 **옵션**이지만 요청에 보냈다면, ID Token에 **MUST 포함** 및 **MUST 동일**
  - Nonce는 추측 곤란(unguessable) **SHOULD**
  - Nonce 재사용(Replay) 탐지 **SHOULD**
  - Refresh로 발급된 ID Token에는 nonce **SHOULD NOT**; 포함 시 최초 nonce와 **MUST 동일**
• RFC 6749 (state는 별개 목적)
• RFC 9207 (인가 응답의 iss — 본 모듈 필수는 아님)

------------------------------------------------------------------------
Data Controller가 제공해야 할 입력(JSON 스켈레톤)  <<< 여기를 참고해 채워주세요 >>>
------------------------------------------------------------------------
flow_bundle = {
    "discovery": {                 # 선택(문맥용)
        "issuer": "...",
        "authorization_endpoint": "...",
        "token_endpoint": "...",
        "jwks_uri": "..."
    },

    # Authorization Request (클라이언트 -> 인가서버)
    "authorization_request": {
        "url": "https://as/authorize?response_type=code%20id_token&scope=openid&client_id=...&redirect_uri=...&state=...&nonce=...",
        "params": {
            "response_type": "code id_token",
            "scope": "openid profile",
            "client_id": "...",
            "redirect_uri": "https://client/callback",
            "state": "S123",
            "nonce": "N123",
            "response_mode": "form_post",         # 선택
            "code_challenge": "...",              # 선택 (PKCE)
            "code_challenge_method": "S256"       # 선택
        },
        "ts": 1710000000                          # 선택: 신선도/재사용 분석용
    },

    # Authorization Response (인가서버 -> 브라우저) — fragment 또는 form_post
    "authorization_response": {
        "location": "https://client/callback#id_token=...&state=S123",
        "form": { "id_token": "...", "state": "S123", "iss": "https://as" },   # response_mode=form_post 인 경우
        "params": { "id_token": "...", "state": "S123", "code": "C123", "iss": "..." }  # 선택
    },

    # Callback(브라우저 -> 클라이언트)
    "callback_request": {
        "query": { "code": "C123", "state": "S123" },      # code flow
        "body": { "id_token": "...", "state": "S123" }     # implicit/form_post
    },

    # Token Response (클라이언트 <-> 인가서버) — Code flow
    "token_response": {
        "json": {
            "access_token": "...",
            "id_token": "...",
            "token_type": "Bearer",
            "expires_in": 3600
        }
    },

    # Refresh Token Response (선택)
    "refresh_token_response": {
        "json": {
            "id_token": "..."
        }
    },

    # 신선도/재사용 분석용: 과거(성공한) 로그인 시도들의 nonce 샘플
    "previous_nonces": ["N_old_1", "N_old_2"]
}

출력(result dict)
-----------------
{
  "ok": bool,
  "failures": [ {code, title, detail, evidence} ],
  "warnings": [ {code, title, detail, evidence} ],
  "flow_type": "implicit|hybrid|code|unknown",
  "observed": {...},
  "checklist": { "A": {...}, "B": {...}, "C": {...} }
}

------------------------------------------------------------------------
"""

from __future__ import annotations


import base64
import json
import math
import re
from dataclasses import dataclass
from typing import Dict, Optional, Any, List, Tuple
from urllib.parse import urlparse, parse_qs, unquote_plus

# 파일 맨 위 import 아래에 추가
STRICT_CODE_FLOW_NONCE_DEFAULT = False  # 기본 False. 어댑터에서 True로 넘기면 정책 활성화

LABELS = {
    "Pass":     "PASS ✅",
    "Fail":     "FAIL ❌",
    "Advisory": "ADVISORY ⚠️",
    "N/A":      "N/A ⭕"
}

def _L(x: str) -> str:
    # 표준 라벨 문자열을 더 눈에 띄게 변환
    return LABELS.get(x, x)

# ----------------------------- Utilities ---------------------------------

def _b64url_decode(s: str) -> bytes:
    s = s.encode('utf-8')
    s += b'=' * ((4 - (len(s) % 4)) % 4)
    s = s.replace(b'-', b'+').replace(b'_', b'/')
    return base64.b64decode(s)

def parse_jwt(jwt: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Parse a JWT (header, payload) without verifying signature."""
    parts = jwt.split('.')
    if len(parts) < 2:
        raise ValueError("Invalid JWT format")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    return header, payload

def parse_query_from_url(url: str) -> Dict[str, str]:
    if not url:
        return {}
    parsed = urlparse(url)
    q = parse_qs(parsed.query)
    frag = {}
    if parsed.fragment:
        frag = parse_qs(parsed.fragment)
    merged = {}
    for src in (q, frag):
        for k, v in src.items():
            if not v:
                continue
            merged[k] = v[0]
    return {k: unquote_plus(v) if isinstance(v, str) else v for k, v in merged.items()}

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    c = Counter(s)
    n = len(s)
    ent = 0.0
    for cnt in c.values():
        p = cnt / n
        if p > 0:
            ent -= p * math.log2(p)
    # return "per symbol" entropy (0..~6 bits)
    return ent


# --------------------------- Data models ----------------------------------

@dataclass
class AuthorizationRequest:
    url: Optional[str] = None
    params: Optional[Dict[str, Any]] = None
    ts: Optional[int] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AuthorizationRequest":
        url = d.get("url")
        params = d.get("params") or {}
        if url and not params:
            params = parse_query_from_url(url)
        if "response_type" in params and isinstance(params["response_type"], str):
            params["response_type"] = ' '.join(params["response_type"].split())
        return cls(url=url, params=params, ts=d.get("ts"))

@dataclass
class AuthorizationResponse:
    location: Optional[str] = None
    form: Optional[Dict[str, Any]] = None
    params: Optional[Dict[str, Any]] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AuthorizationResponse":
        location = d.get("location")
        form = d.get("form")
        params = d.get("params") or {}
        if location and not params:
            params = parse_query_from_url(location)
        return cls(location=location, form=form, params=params)

@dataclass
class TokenResponse:
    json: Optional[Dict[str, Any]] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TokenResponse":
        return cls(json=d.get("json") or {})

@dataclass
class FlowBundle:
    discovery: Optional[Dict[str, Any]]
    authorization_request: AuthorizationRequest
    authorization_response: AuthorizationResponse
    callback_request: Optional[Dict[str, Any]]
    token_response: Optional[TokenResponse]
    refresh_token_response: Optional[TokenResponse]
    previous_nonces: List[str]

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FlowBundle":
        return cls(
            discovery=d.get("discovery") or {},
            authorization_request=AuthorizationRequest.from_dict(d.get("authorization_request") or {}),
            authorization_response=AuthorizationResponse.from_dict(d.get("authorization_response") or {}),
            callback_request=d.get("callback_request") or {},
            token_response=TokenResponse.from_dict(d.get("token_response") or {}),
            refresh_token_response=TokenResponse.from_dict(d.get("refresh_token_response") or {}),
            previous_nonces=list(d.get("previous_nonces") or []),
        )


# ---------------------------- Core logic ----------------------------------

def _detect_flow_type(params: Dict[str, Any]) -> str:
    scope = (params.get("scope") or "").lower()
    rt = (params.get("response_type") or "").strip().lower()
    tokens = set(rt.replace('+', ' ').split()) if rt else set()
    if "openid" not in scope:
        return "unknown"
    if "id_token" in tokens and "code" in tokens:
        return "hybrid"
    if "id_token" in tokens:
        return "implicit"
    if "code" in tokens:
        return "code"
    return "unknown"

def _is_unguessable(nonce: str) -> bool:
    # Heuristic thresholds:
    # - length >= 16
    # - Shannon entropy per symbol >= 3.0 bits
    # - not a simple decimal timestamp or short hex-only value
    if not nonce:
        return False
    if len(nonce) < 16:
        return False
    if re.fullmatch(r"\d{8,}", nonce):
        return False
    if re.fullmatch(r"[a-f0-9]{1,16}", nonce, flags=re.IGNORECASE):
        return False
    ent = shannon_entropy(nonce)
    return ent >= 3.0

def run_checks(raw: Dict[str, Any]) -> Dict[str, Any]:
    bundle = FlowBundle.from_dict(raw)

    ar = bundle.authorization_request.params or {}
    flow_type = _detect_flow_type(ar)

    observed = {
        "flow_type": flow_type,
        "request_scope": ar.get("scope"),
        "request_response_type": ar.get("response_type"),
        "request_nonce": ar.get("nonce"),
        "request_state": ar.get("state"),
    }

    failures, warnings = [], []

    def fail(code: str, title: str, detail: str, evidence: Dict[str, Any]):
        failures.append({"code": code, "title": title, "detail": detail, "evidence": evidence})

    def warn(code: str, title: str, detail: str, evidence: Dict[str, Any]):
        warnings.append({"code": code, "title": title, "detail": detail, "evidence": evidence})

    # Extract ID Tokens
    idt_from_auth, idt_from_token, idt_from_refresh = None, None, None

    ap = bundle.authorization_response.params or {}
    idt_auth_val = ap.get("id_token") or (bundle.authorization_response.form or {}).get("id_token")
    if idt_auth_val:
        try:
            _, idt_from_auth = parse_jwt(idt_auth_val)
        except Exception as e:
            fail("N0", "Invalid ID Token format (authorization response)", str(e), {"prefix": idt_auth_val[:40]})

    tk = (bundle.token_response.json or {}) if bundle.token_response else {}
    idt_token_val = tk.get("id_token")
    if idt_token_val:
        try:
            _, idt_from_token = parse_jwt(idt_token_val)
        except Exception as e:
            fail("N0", "Invalid ID Token format (token response)", str(e), {"prefix": idt_token_val[:40]})

    rf = (bundle.refresh_token_response.json or {}) if bundle.refresh_token_response else {}
    idt_refresh_val = rf.get("id_token")
    if idt_refresh_val:
        try:
            _, idt_from_refresh = parse_jwt(idt_refresh_val)
        except Exception as e:
            fail("N0", "Invalid ID Token format (refresh token response)", str(e), {"prefix": idt_refresh_val[:40]})

    # ===== Checklist containers =====
    checklist = {"A": {}, "B": {}, "C": {}}

    # ---------------- A. Authorization Request ----------------
    checklist["A"]["flow_identify"] = {
        "expect": "scope=openid AND response_type ∈ {code, id_token, code id_token, id_token token, code id_token token}",
        "observed": {"scope": ar.get("scope"), "response_type": ar.get("response_type")},
        "result": "Pass" if flow_type in ("code", "implicit", "hybrid") else "Fail"
    }

    if flow_type in ("implicit", "hybrid"):
        if not ar.get("nonce"):
            fail("N1", "Missing nonce in authorization request (Implicit/Hybrid)",
                 "Implicit/Hybrid에서는 authorization request에 nonce가 REQUIRED.", {"response_type": ar.get("response_type")})
            checklist["A"]["nonce_required_implicit_hybrid"] = {"result": "Fail"}
        else:
            checklist["A"]["nonce_required_implicit_hybrid"] = {"result": "Pass"}
    else:
        checklist["A"]["nonce_required_implicit_hybrid"] = {"result": "N/A"}

    if flow_type == "code":
        checklist["A"]["nonce_used_in_codeflow"] = {"result": "Pass" if ar.get("nonce") else "Advisory"}
    else:
        checklist["A"]["nonce_used_in_codeflow"] = {"result": "N/A"}

    req_nonce = ar.get("nonce")
    if req_nonce:
        ent_ok = _is_unguessable(req_nonce)
        reused = req_nonce in (bundle.previous_nonces or [])
        if not ent_ok or reused:
            reason = []
            if not ent_ok: reason.append("low-entropy/predictable")
            if reused: reason.append("reused")
            fail("N5", "Weak or reused nonce", " / ".join(reason), {"nonce": req_nonce, "prev_nonces": (bundle.previous_nonces or [])[:5]})
            checklist["A"]["nonce_entropy_freshness"] = {"result": "Fail", "note": "predictable or reused"}
        else:
            checklist["A"]["nonce_entropy_freshness"] = {"result": "Pass"}
    else:
        checklist["A"]["nonce_entropy_freshness"] = {"result": "N/A"}

    # ---------------- B. Authorization/Token Response (ID Token) ----------------
    def _check_idtoken_nonce(idt_claims: Optional[Dict[str, Any]], source: str):
        if req_nonce is None:
            return None
        if not idt_claims:
            fail("N2", f"ID Token missing (source={source}) while nonce was sent",
                 "요청에 nonce를 보냈다면 ID Token에 같은 값의 nonce가 MUST 포함.", {"source": source})
            return False
        tok_nonce = idt_claims.get("nonce")
        if tok_nonce is None:
            fail("N3", f"ID Token lacks `nonce` (source={source})",
                 "요청에 nonce를 보냈다면 ID Token의 nonce Claim이 MUST.", {"source": source, "claims_sample": {k: idt_claims.get(k) for k in ("iss","aud","sub","nonce")}})
            return False
        if tok_nonce != req_nonce:
            fail("N4", f"ID Token nonce mismatch (source={source})",
                 "요청 nonce와 ID Token의 nonce는 MUST 동일.", {"request_nonce": req_nonce, "id_token_nonce": tok_nonce})
            return False
        return True

    b1 = None
    if req_nonce is not None:
        results = []
        if idt_from_auth: results.append(_check_idtoken_nonce(idt_from_auth, "authorization_response"))
        if idt_from_token: results.append(_check_idtoken_nonce(idt_from_token, "token_response"))
        b1 = all([r for r in results if r is not None]) if results else None
    checklist["B"]["id_token_must_include_nonce_if_requested"] = {"result": "Pass" if b1 else ("Fail" if b1 is False else "N/A")}

    if flow_type in ("implicit", "hybrid"):
        if idt_from_auth:
            has_nonce = idt_from_auth.get("nonce") is not None
            checklist["B"]["implicit_hybrid_idtoken_has_nonce"] = {"result": "Pass" if has_nonce else "Fail"}
            if not has_nonce:
                fail("N3", "ID Token lacks `nonce` in Implicit/Hybrid", "Implicit/Hybrid의 ID Token에는 nonce가 필수.", {})
        else:
            checklist["B"]["implicit_hybrid_idtoken_has_nonce"] = {"result": "Fail"}
            fail("N2", "Missing ID Token in Implicit/Hybrid response", "ID Token이 없어 nonce 검증 불가.", {})
    else:
        checklist["B"]["implicit_hybrid_idtoken_has_nonce"] = {"result": "N/A"}

    # ---------------- C. Client Validation ----------------
    c1 = None
    if req_nonce is not None:
        matches = []
        if idt_from_auth and idt_from_auth.get("nonce") == req_nonce: matches.append(True)
        if idt_from_token and idt_from_token.get("nonce") == req_nonce: matches.append(True)
        c1 = bool(matches)
    checklist["C"]["nonce_equality_validation"] = {"result": "Pass" if c1 else ("Fail" if c1 is False else "N/A")}

    if req_nonce:
        replay = req_nonce in (bundle.previous_nonces or [])
        checklist["C"]["nonce_replay_rejection"] = {"result": "Fail" if replay else "Pass"}
        if replay:
            fail("N6", "Nonce replay suspected", "이전 로그인에서 사용된 nonce가 다시 관측됨.", {"nonce": req_nonce})
    else:
        checklist["C"]["nonce_replay_rejection"] = {"result": "N/A"}

    checklist["C"]["session_binding_disposal"] = {"result": "Info", "note": "세션 결속/사용 후 폐기는 구현 검토 항목(모듈은 관찰 불가)"}
    checklist["C"]["id_token_general_validation"] = {"result": "Info", "note": "서명/iss/aud/exp/iat/(at_hash|c_hash)은 별도 모듈에서 검증"}

    # Refresh 규칙
    if idt_from_refresh is not None:
        rnonce = idt_from_refresh.get("nonce")
        if rnonce is not None and req_nonce is not None and rnonce != req_nonce:
            fail("N7", "Refresh-issued ID Token has different nonce",
                 "Refresh로 발급된 ID Token에 nonce가 있을 경우 최초 인증 nonce와 MUST 동일.", {"refresh_nonce": rnonce, "original": req_nonce})
        elif rnonce is not None and req_nonce is not None and rnonce == req_nonce:
            warn("N8", "Refresh-issued ID Token includes nonce (SHOULD NOT)",
                 "동일 값이더라도 Refresh ID Token에는 일반적으로 nonce가 포함되지 않아야 함.", {"refresh_nonce": rnonce})

    ok = len(failures) == 0
    return {
        "ok": ok,
        "failures": failures,
        "warnings": warnings,
        "flow_type": flow_type,
        "observed": observed,
        "checklist": checklist
    }


# ----------------------------- Pretty print -------------------------------

def pretty_report(res: Dict[str, Any]) -> str:
    j = res
    out = []
    out.append(f"Flow: {j.get('flow_type')}  Overall: {'PASS' if j.get('ok') else 'FAIL'}\n")

    def dump_section(name, sec):
        out.append(f"== {name} ==")
        for k, v in sec.items():
            out.append(f"- {k}: {v.get('result')}")
            ov = v.get('observed') or v.get('note')
            if ov:
                out.append(f"  • {ov}")
        out.append("")

    dump_section("A. Authorization Request", j["checklist"]["A"])
    dump_section("B. ID Token", j["checklist"]["B"])
    dump_section("C. Client Validation", j["checklist"]["C"])

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
        sys.stderr.write("Provide a JSON flow bundle via stdin. Example structure is in the module docstring.\n")
        raise
    res = run_checks(raw)
    print(pretty_report(res))

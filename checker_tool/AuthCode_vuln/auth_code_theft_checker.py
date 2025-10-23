
"""
auth_code_theft_checker.py — Authorization Code Theft Vulnerability module
===========================================================================
Scope
-----
Detects *authorization code theft* risks in OAuth 2.0 / OIDC code flow,
grouped as A/B/C sections to align with the team's OIDC nonce tool.

Normative anchors (mapping refs; enforcement is out-of-band):
- RFC 6749 §3.1.2, §4.1.2, §4.1.3, §10 (redirect_uri, code, state)
- RFC 7636 (PKCE) — S256 only
- RFC 8252 (native apps loopback/claimed-https)
- RFC 9207 (iss in authorization response) — Mix-Up mitigation
- OIDC Core: "redirect_uri Simple String Comparison", Form Post Response Mode
- OAuth 2.0 Form Post Response Mode (OIDF)
- BCP 9700 (best practices) — general hardening guidance

Note: Per user request, the informational check "sender_constrained_tokens (mTLS/DPoP)"
has been REMOVED from Section C.
"""

from __future__ import annotations

import json, re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

MODULE_KEY = "authcode"

def _parse_query(url: str) -> Dict[str, str]:
    if not url:
        return {}
    p = urlparse(url)
    q = parse_qs(p.query)
    frag = parse_qs(p.fragment) if p.fragment else {}
    merged = {}
    for src in (q, frag):
        for k, v in src.items():
            if v: merged[k] = v[0]
    return merged

def _is_loopback(host: str) -> bool:
    if not host: return False
    h = host.lower()
    return h in ("127.0.0.1","localhost","::1") or h.startswith("127.")

def _has_wildcard(s: str) -> bool:
    return bool(re.search(r"[\\*\\{\\}]", s or ""))

def _looks_high_entropy(s: str) -> bool:
    # Heuristic only; per team rule we won't emit numeric entropy.
    if not s: return False
    unique = len(set(s))
    return (len(s) >= 16) and (unique >= 8)

def _discovery_extract(disc: Dict[str, Any]) -> Tuple[Optional[str], Optional[bool]]:
    """
    Accept raw OIDC discovery doc or the team's 'summary.json' shape.
    Returns (issuer, iss_param_supported).
    """
    if not isinstance(disc, dict):
        return None, None
    issuer = disc.get("issuer") or (disc.get("discovery_core") or {}).get("issuer") or disc.get("issuer_inferred")
    iss_supported = disc.get("authorization_response_iss_parameter_supported")
    if iss_supported is None:
        iss_supported = (disc.get("discovery_core") or {}).get("authorization_response_iss_parameter_supported")
    return issuer, iss_supported

@dataclass
class AuthorizationRequest:
    url: Optional[str] = None
    params: Optional[Dict[str, Any]] = None
    ts: Optional[int] = None
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AuthorizationRequest":
        url = d.get("url")
        params = d.get("params") or {}
        if url and not params: params = _parse_query(url)
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
        if location and not params: params = _parse_query(location)
        return cls(location=location, form=form, params=params)

@dataclass
class TokenRequest:
    body: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, Any]] = None
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TokenRequest":
        return cls(body=d.get("body") or {}, headers=d.get("headers") or {})

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
    token_request: Optional[TokenRequest]
    token_response: Optional[TokenResponse]
    previous_nonces: List[str]
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FlowBundle":
        return cls(
            discovery=d.get("discovery") or {},
            authorization_request=AuthorizationRequest.from_dict(d.get("authorization_request") or {}),
            authorization_response=AuthorizationResponse.from_dict(d.get("authorization_response") or {}),
            callback_request=d.get("callback_request") or {},
            token_request=TokenRequest.from_dict(d.get("token_request") or {}),
            token_response=TokenResponse.from_dict(d.get("token_response") or {}),
            previous_nonces=list(d.get("previous_nonces") or []),
        )

def _detect_flow_type(params: Dict[str, Any]) -> str:
    scope = (params.get("scope") or "").lower()
    rt = (params.get("response_type") or "").lower()
    parts = set(rt.replace('+',' ').split())
    if "openid" not in scope:
        return "unknown"
    if "code" in parts and "id_token" in parts: return "hybrid"
    if "id_token" in parts: return "implicit"
    if "code" in parts: return "code"
    return "unknown"

def run_checks(raw: Dict[str, Any]) -> Dict[str, Any]:
    bundle = FlowBundle.from_dict(raw)
    ar = bundle.authorization_request.params or {}
    ap = bundle.authorization_response.params or {}
    tr = (bundle.token_request.body or {}) if bundle.token_request else None
    flow_type = _detect_flow_type(ar)

    # Discovery context
    issuer_cfg, iss_supported = _discovery_extract(bundle.discovery or {})

    failures: List[Dict[str,Any]] = []
    warnings: List[Dict[str,Any]] = []
    checklist = {"A":{}, "B":{}, "C":{}}

    def fail(code, title, detail, evidence=None):
        failures.append({"code":code,"title":title,"detail":detail,"evidence":evidence})
    def warn(code, title, detail, evidence=None):
        warnings.append({"code":code,"title":title,"detail":detail,"evidence":evidence})

    # ---------------- A. Authorization / Redirect ----------------
    redirect_uri = ar.get("redirect_uri")
    ru_obs = {"redirect_uri": redirect_uri}
    # A1 redirect_uri safety (absolute, https except loopback, no fragment, no wildcard)
    if not redirect_uri:
        checklist["A"]["redirect_uri_present"] = {"result":"Fail", "observed":ru_obs}
        fail("C1A", "Missing redirect_uri in authorization request",
             "Authorization Request MUST include redirect_uri for registered clients.", ru_obs)
    else:
        pu = urlparse(redirect_uri)
        ok_abs = bool(pu.scheme and pu.netloc)
        ok_fragment = pu.fragment == ""
        ok_scheme = (pu.scheme.lower() == "https") or (pu.scheme.lower()=="http" and _is_loopback(pu.hostname or ""))
        ok_wild = not _has_wildcard(redirect_uri)
        res = "Pass" if (ok_abs and ok_fragment and ok_scheme and ok_wild) else "Fail"
        note = []
        if not ok_abs: note.append("절대 URI 필요")
        if not ok_fragment: note.append("fragment 금지")
        if not ok_scheme: note.append("HTTPS 강제(네이티브 loopback 예외)")
        if not ok_wild: note.append("와일드카드 금지")
        checklist["A"]["redirect_uri_safety"] = {"result":res, "note":"; ".join(note) if note else None, "observed":ru_obs}
        if res=="Fail":
            fail("C1", "Unsafe redirect_uri", "등록·정확 문자열 일치 및 HTTPS(네이티브 loopback 예외), 와일드카드/fragment 금지.", {"parsed":redirect_uri})

    # A2 response_mode=form_post preference + code exposure in URL
    resp_mode = (ar.get("response_mode") or "").lower()
    code_in_url = bool(ap.get("code") or (bundle.authorization_response.location and "code=" in bundle.authorization_response.location))
    if resp_mode == "form_post":
        checklist["A"]["form_post_used"] = {"result":"Pass"}
    else:
        if code_in_url:
            checklist["A"]["form_post_used"] = {"result":"Fail", "note":"code exposed in URL"}
            fail("C2", "Authorization code in URL (front-channel)",
                 "response_mode=form_post를 사용해 로그/Referer/히스토리 누출을 차단하세요.", 
                 {"location": bundle.authorization_response.location})
        else:
            checklist["A"]["form_post_used"] = {"result":"Advisory", "note":"response_mode가 form_post 아님"}

    # A3 Mix-Up mitigation: iss in authorization response + discovery match
    iss = ap.get("iss")
    if iss:
        checklist["A"]["iss_in_authorization_response"] = {"result":"Pass"}
    else:
        if iss_supported is True:
            checklist["A"]["iss_in_authorization_response"] = {"result":"Fail", "note":"discovery가 iss 지원을 광고함"}
            fail("C3", "Missing iss in authorization response (RFC 9207)",
                 "인가 응답에 'iss'를 포함해 발신자(AS)를 식별하고 Mix-Up을 방지하세요.", {"observed_params": list(ap.keys())})
        else:
            checklist["A"]["iss_in_authorization_response"] = {"result":"Advisory", "note":"discovery에서 iss 지원 미광고 — 다중 AS 환경에선 권장"}

    if issuer_cfg:
        if not iss:
            checklist["A"]["iss_matches_discovery"] = {"result":"Fail", "note":"iss 부재 — discovery.issuer와 대조 불가", "observed":{"discovery_issuer": issuer_cfg}}
        elif iss == issuer_cfg:
            checklist["A"]["iss_matches_discovery"] = {"result":"Pass", "note":f"iss == discovery.issuer ({issuer_cfg})"}
        else:
            checklist["A"]["iss_matches_discovery"] = {"result":"Fail", "note":f"iss({iss}) ≠ discovery.issuer({issuer_cfg})"}
            fail("C3D", "iss mismatch with discovery.issuer",
                 "응답 발신자 식별값이 discovery와 달라 Mix-Up 위험.", {"iss": iss, "discovery_issuer": issuer_cfg})
    else:
        checklist["A"]["iss_matches_discovery"] = {"result":"N/A", "note":"discovery.issuer 미제공"}

    # A4 state presence & apparent entropy
    st = ar.get("state")
    if st:
        checklist["A"]["state_presence"] = {"result":"Pass", "note":("고엔트로피/예측 불가" if _looks_high_entropy(st) else "엔트로피 불충분 의심")}
    else:
        checklist["A"]["state_presence"] = {"result":"Fail"}
        fail("C6A", "Missing state", "상관관계 강화를 위해 고엔트로피 state 사용.", None)

    # ---------------- B. PKCE & /token Binding --------------------
    pkce_supported_methods = (bundle.discovery.get("code_challenge_methods_supported")
                              or (bundle.discovery.get("discovery_core") or {}).get("code_challenge_methods_supported")
                              or []) if isinstance(bundle.discovery, dict) else []
    if "plain" in [m.lower() for m in pkce_supported_methods]:
        warn("C4H", "Provider supports 'plain' PKCE", "서버가 plain을 지원 — 다운그레이드 위험, S256만 허용하도록 구성 권장.", {"discovery": pkce_supported_methods})

    ccm = (ar.get("code_challenge_method") or "").upper()
    cc = ar.get("code_challenge")
    if cc and ccm == "S256":
        checklist["B"]["pkce_s256_in_request"] = {"result":"Pass"}
    elif cc and ccm == "PLAIN":
        checklist["B"]["pkce_s256_in_request"] = {"result":"Fail", "note":"plain 허용은 다운그레이드"}
        fail("C4", "PKCE downgrade to plain", "PKCE는 S256만 허용.", {"code_challenge_method": ccm})
    else:
        checklist["B"]["pkce_s256_in_request"] = {"result":"Fail", "note":"code_challenge 누락 또는 method≠S256"}
        fail("C4", "PKCE missing", "코드 플로우에 PKCE(S256) 필수.", {"response_type": ar.get("response_type")})

    if cc:
        if not tr:
            checklist["B"]["token_has_code_verifier"] = {"result":"N/A", "note":"token_request body 관찰 불가"}
        elif tr.get("code_verifier"):
            checklist["B"]["token_has_code_verifier"] = {"result":"Pass"}
        else:
            checklist["B"]["token_has_code_verifier"] = {"result":"Fail"}
            fail("C4B", "Missing code_verifier at /token", "/token에 code_verifier 필수.", {"token_request_keys": list(tr.keys())})
    else:
        checklist["B"]["token_has_code_verifier"] = {"result":"N/A"}

    if redirect_uri:
        if not tr:
            checklist["B"]["token_resent_redirect_uri"] = {"result":"N/A", "note":"token_request body 관찰 불가"}
        else:
            tr_redirect = tr.get("redirect_uri")
            if tr_redirect is None:
                checklist["B"]["token_resent_redirect_uri"] = {"result":"Fail", "note":"redirect_uri 미재제출"}
                fail("C5", "redirect_uri not re-submitted at /token", "RFC 6749 §4.1.3: 동일 redirect_uri 재제출(MUST).", {})
            elif tr_redirect != redirect_uri:
                checklist["B"]["token_resent_redirect_uri"] = {"result":"Fail", "note":"불일치"}
                fail("C5", "redirect_uri mismatch at /token", "인가요청과 동일 값이어야 함.", {"auth": redirect_uri, "token": tr_redirect})
            else:
                checklist["B"]["token_resent_redirect_uri"] = {"result":"Pass"}
    else:
        checklist["B"]["token_resent_redirect_uri"] = {"result":"N/A"}

    # ---------------- C. Leakage minimization & hardening -------------
    if code_in_url:
        checklist["C"]["front_channel_leak_risk"] = {"result":"Fail", "note":"URL에 code 존재(로그/Referer/히스토리 유출 위험)"}
    else:
        checklist["C"]["front_channel_leak_risk"] = {"result":"Pass"}

    subresources = (bundle.callback_request or {}).get("subresources") or []
    external_loaded = [u for u in subresources if u and urlparse(u).netloc]
    if code_in_url and external_loaded:
        checklist["C"]["referer_leak_risk"] = {"result":"Fail", "note":f"콜백에서 외부 서브리소스 {len(external_loaded)}개 로드"}
        warn("C6", "Referer may leak code to third-party domains",
             "콜백에서 외부 리소스를 최소화하고 Referrer-Policy를 엄격히 설정.", {"samples": external_loaded[:3]})
    else:
        checklist["C"]["referer_leak_risk"] = {"result":"Advisory" if code_in_url else "N/A"}

    if ar.get("request_uri") or ar.get("request"):
        checklist["C"]["jar_par_usage"] = {"result":"Pass", "note":"요청 객체 관찰(무결성은 별도 검증)"}
    else:
        par_ep = (bundle.discovery or {}).get("pushed_authorization_request_endpoint") or \
                 ((bundle.discovery or {}).get("discovery_core") or {}).get("pushed_authorization_request_endpoint")
        if par_ep:
            checklist["C"]["jar_par_usage"] = {"result":"Advisory", "note":"서버가 PAR 제공 — 사용 권장"}
        else:
            checklist["C"]["jar_par_usage"] = {"result":"Advisory", "note":"JAR/PAR 미사용(권장)"}

    ok = len(failures)==0
    observed = {
        "flow_type": flow_type,
        "redirect_uri": redirect_uri,
        "response_mode": ar.get("response_mode"),
        "iss_in_response": bool(iss),
        "issuer_from_discovery": issuer_cfg,
        "pkce": {"present": bool(ar.get("code_challenge")), "method": ar.get("code_challenge_method")},
        "token_request_keys": list(tr.keys()) if tr else [],
        "state_present": bool(st),
        "code_in_url": code_in_url
    }
    return {
        "ok": ok,
        "failures": failures,
        "warnings": warnings,
        "flow_type": flow_type,
        "observed": observed,
        "checklist": checklist
    }

def pretty_report(res: Dict[str, Any]) -> str:
    j = res
    out = []
    out.append(f"Flow: {j.get('flow_type')}  Overall: {'PASS' if j.get('ok') else 'FAIL'}\n")

    def dump_section(title, sec):
        out.append(f"== {title} ==")
        for k,v in sec.items():
            line = f"- {k}: {v.get('result')}"
            out.append(line)
            note = v.get("note") or v.get("observed")
            if note: out.append(f"  • {note}")
        out.append("")
    out.append("")
    dump_section("A. Authorization / Redirect", j["checklist"]["A"])
    dump_section("B. PKCE & /token Binding", j["checklist"]["B"])
    dump_section("C. Leakage & Hardening", j["checklist"]["C"])

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

def to_markdown(res: Dict[str, Any]) -> str:
    txt = pretty_report(res)
    return "```text\n" + txt.replace("```","\\`\\`\\`") + "\n```"

if __name__ == "__main__":
    import sys, json as _json
    try:
        raw = _json.load(sys.stdin)
    except Exception:
        sys.stderr.write("Provide flow_bundle JSON via stdin.\n")
        raise
    print(pretty_report(run_checks(raw)))

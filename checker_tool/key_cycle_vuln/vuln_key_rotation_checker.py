"""
OAuth 키 회전·JWKS 취약(키 관리 부실) 전용 진단 모듈
- 공식문서 기준:
  * OpenID Connect Core/Discovery/Registration
  * RFC 7517 (JWK), RFC 8414 (AS Metadata), RFC 8725 (JWT BCP), RFC 7523 (client_assertion)
- 목적: 이 취약점 한 가지만 정확히 진단.
- 입력: Data Controller가 수집한 Discovery/JWKS/토큰/등록메타데이터 스냅샷 (아래 주입 지점 참조)
- 출력: dict(report) — findings 리스트와 요약 스코어 포함
"""

from __future__ import annotations
import json, base64, re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

SEV_HIGH = "HIGH"
SEV_MED  = "MEDIUM"
SEV_LOW  = "LOW"
SEV_INFO = "INFO"

def b64url_json(segment: str) -> Dict[str, Any]:
    """JWS compact header/payload decoding (검증용; 서명검증은 수행하지 않음)"""
    padding = "=" * ((4 - len(segment) % 4) % 4)
    data = base64.urlsafe_b64decode(segment + padding)
    try:
        return json.loads(data.decode("utf-8"))
    except Exception:
        return {}

def parse_jwt_header(jwt: str) -> Dict[str, Any]:
    parts = jwt.split(".")
    if len(parts) < 2:
        return {}
    return b64url_json(parts[0])

def host_eq(h1: str, h2: str) -> bool:
    return (h1 or "").lower().strip(".") == (h2 or "").lower().strip(".")

def add(findings: List[Dict[str, Any]], severity: str, title: str, desc: str, evidence: Any = None, spec: Optional[str] = None):
    findings.append({
        "severity": severity,
        "title": title,
        "description": desc,
        "evidence": evidence,
        "spec_ref": spec
    })

def check_key_rotation(inputs: Dict[str, Any]) -> Dict[str, Any]:
    """
    핵심 엔트리포인트.
    inputs 스키마는 하단 '예시 주입' 및 동봉 텍스트 파일 참고.

    반환: {
      "summary": {...},
      "findings": [ {severity,title,description,evidence,spec_ref}, ... ]
    }
    """
    findings: List[Dict[str, Any]] = []

    # --------------------[ DATA CONTROLLER INPUT HERE ]--------------------
    # ① Discovery 스냅샷 (OP/AS 메타데이터)
    discovery = inputs.get("discovery")  # dict: {discovery_url,http_status,body_json,tls_verified,redirect_chain}
    # ----------------------------------------------------------------------

    # --------------------[ DATA CONTROLLER INPUT HERE ]--------------------
    # ② JWKS 조회 이벤트들 (여러 번 있을 수 있음; 최신이 맨 뒤라고 가정하지 않음)
    jwks_fetches: List[Dict[str, Any]] = inputs.get("jwks_fetches", [])
    # 각 항목 예: {requested_url, final_url, http_status, scheme, host, redirect_chain, headers, jwks_json}
    # ----------------------------------------------------------------------

    # --------------------[ DATA CONTROLLER INPUT HERE ]--------------------
    # ③ 토큰 원문 목록 (id_token, access_token, client_assertion 등)
    tokens: List[Dict[str, Any]] = inputs.get("tokens", [])
    # 각 항목 예: {token_type, jwt, obtained_from?, observed_at?}
    # ----------------------------------------------------------------------

    # --------------------[ DATA CONTROLLER INPUT HERE ]--------------------
    # ④ (선택) 클라이언트 등록 메타데이터
    client_reg: Optional[Dict[str, Any]] = inputs.get("client_registration")
    # ----------------------------------------------------------------------

    # --------------------[ DATA CONTROLLER INPUT HERE ]--------------------
    # ⑤ (선택) 정책/설정 (허용 알고리즘 화이트리스트 등)
    allowed_algs: Optional[List[str]] = inputs.get("allowed_algs")
    issuer_hint: Optional[str] = inputs.get("issuer_hint")
    # ----------------------------------------------------------------------

    # ---- Discovery / jwks_uri 기본 검증 ----
    jwks_uri = None
    issuer_host = None
    if discovery and isinstance(discovery.get("body_json"), dict):
        body = discovery["body_json"]
        jwks_uri = body.get("jwks_uri")
        issuer = body.get("issuer")
        if issuer:
            issuer_host = urlparse(issuer).hostname

        # REQUIRED & HTTPS
        if not jwks_uri:
            add(findings, SEV_HIGH, "jwks_uri 누락",
                "Discovery 메타데이터에 jwks_uri가 없습니다. (REQUIRED)",
                {"discovery_url": discovery.get("discovery_url")},
                "OIDC Discovery / RFC 8414")
        else:
            p = urlparse(jwks_uri)
            if p.scheme.lower() != "https":
                add(findings, SEV_HIGH, "jwks_uri가 HTTPS가 아님",
                    f"jwks_uri={jwks_uri}",
                    {"jwks_uri": jwks_uri},
                    "OIDC Discovery / RFC 8414 (HTTPS 권고/요구)")
    else:
        add(findings, SEV_HIGH, "Discovery 스냅샷 없음",
            "Discovery 메타데이터가 없으면 키 출처를 신뢰할 수 없습니다.",
            None, "OIDC Discovery / RFC 8414")

    # TLS/호스트 검증
    if discovery:
        if discovery.get("tls_verified") is False:
            add(findings, SEV_HIGH, "TLS 검증 실패",
                "Discovery 응답의 인증서/호스트 검증 실패.",
                None, "TLS trust; OIDC Discovery")

        # 교차 호스트 리다이렉트
        chain = discovery.get("redirect_chain") or []
        if chain:
            try:
                first = urlparse(chain[0]["from"]).hostname
                last  = urlparse(chain[-1]["to"]).hostname
                if first and last and not host_eq(first, last):
                    add(findings, SEV_MED, "Discovery 교차-호스트 리다이렉트",
                        f"{first} → {last}",
                        {"redirect_chain": chain},
                        "Supply chain hardening")
            except Exception:
                pass

    # ---- JWKS 조회 검증 ----
    # 최신 스냅샷(들)에서 키 목록 수집
    all_jwks_keys: List[Dict[str, Any]] = []
    any_etag = False
    any_cache = False
    cross_host_redirect = False
    for fetch in jwks_fetches:
        scheme = (fetch.get("scheme") or "").lower()
        host   = fetch.get("host")
        if scheme != "https":
            add(findings, SEV_HIGH, "JWKS가 HTTPS로 제공되지 않음",
                f"{fetch.get('final_url')}", fetch, "OIDC Discovery / RFC 8414")
        # 교차 호스트 리다이렉트 감지
        chain = fetch.get("redirect_chain") or []
        if chain:
            try:
                first = urlparse(chain[0]["from"]).hostname
                last  = urlparse(chain[-1]["to"]).hostname
                if first and last and not host_eq(first, last):
                    cross_host_redirect = True
            except Exception:
                pass
        hdrs = {k.lower(): v for k,v in (fetch.get("headers") or {}).items()}
        any_etag |= "etag" in hdrs
        any_cache |= "cache-control" in hdrs
        jwks = fetch.get("jwks_json") or {}
        keys = jwks.get("keys") or []
        all_jwks_keys.extend(keys)
    if cross_host_redirect:
        add(findings, SEV_MED, "JWKS 교차-호스트 리다이렉트",
            "jwks_uri가 다른 호스트로 리다이렉트 됨. 가능하면 동일 호스트로 고정.",
            None, "OIDC Discovery hardening")
    if not all_jwks_keys:
        add(findings, SEV_HIGH, "JWKS 키 없음",
            "JWKS에서 공개키를 찾지 못함.", None, "JWK (RFC 7517)")
    if not any_etag and not any_cache:
        add(findings, SEV_LOW, "JWKS 캐시 힌트 부재",
            "ETag/Cache-Control 헤더가 없어서 회전 시 동기화가 비효율적일 수 있음.",
            None, "운영 권고")

    # JWKS 키 지도: kid -> [keys...]
    by_kid: Dict[str, List[Dict[str, Any]]] = {}
    for k in all_jwks_keys:
        kid = k.get("kid") or ""
        by_kid.setdefault(kid, []).append(k)

    # 용도/혼용 점검
    uses = { (k.get("kid") or ""): k.get("use") for k in all_jwks_keys }
    # 같은 kid로 여러 항목이 있거나, use 미지정이 많은 경우 경고
    for kid, arr in by_kid.items():
        if kid and len(arr) > 1:
            add(findings, SEV_MED, "중복 kid",
                f"같은 kid={kid}에 여러 키 항목 존재", {"kid": kid, "count": len(arr)},
                "JWK kid uniqueness (RFC 7517 §4.5 권고)")
    if len(all_jwks_keys) > 1 and any(k.get("use") is None for k in all_jwks_keys):
        add(findings, SEV_LOW, "키 용도(use/key_ops) 미지정",
            "여러 키가 동시에 제공되는데 일부 키에 use/key_ops가 없음(혼용 방지 차원에서 권장).",
            None, "OIDC Discovery / 운영 권고")

    # ---- 토큰(JWT) 헤더 기반 점검 ----
    def check_token(token_type: str, jwt: str):
        if not jwt or jwt.count(".") < 2:
            add(findings, SEV_HIGH, f"{token_type}: JWT 형식 아님",
                "JWS Compact 형식이 아님", {"jwt": jwt[:40]+"..." if jwt else None}, "JOSE")
            return
        header = parse_jwt_header(jwt)
        alg = header.get("alg")
        kid = header.get("kid")
        jku = header.get("jku")
        x5u = header.get("x5u")
        jwk_inline = header.get("jwk")
        x5c = header.get("x5c")

        # alg none 금지
        if alg == "none":
            add(findings, SEV_HIGH, f"{token_type}: alg=none 금지",
                "서명 없는 토큰은 허용되지 않음(OIDC ID 토큰은 반드시 서명).",
                {"header": header}, "OIDC Core / JWT BCP")

        # 허용 alg 화이트리스트
        if allowed_algs and alg not in allowed_algs:
            add(findings, SEV_MED, f"{token_type}: 허용 알고리즘 외 사용",
                f"alg={alg}, 허용={allowed_algs}",
                {"header": header}, "JWT BCP (RFC 8725)")

        # 헤더의 원격 키/인증서 참조 금지(특히 ID 토큰)
        if token_type == "id_token":
            if any([jku, x5u, jwk_inline, x5c]):
                add(findings, SEV_HIGH, "ID 토큰 헤더에 jku/x5u/jwk/x5c 존재",
                    "ID 토큰에서 헤더 키-URL/인라인 키는 SHOULD NOT.",
                    {"header": header}, "OIDC Core (헤더 키 참조 비권장)")

        # jku/x5u 스킴 확인
        for label, url in [("jku", jku), ("x5u", x5u)]:
            if url:
                scheme = urlparse(url).scheme.lower()
                if scheme != "https":
                    add(findings, SEV_HIGH, f"{token_type}: {label}가 HTTPS 아님",
                        f"{label}={url}", {"header": header}, "JWT BCP / OIDC 보안 권고")

        # kid 존재성: JWKS 키가 여러 개인데 헤더 kid 없음 → 권고 위반
        if len(all_jwks_keys) > 1 and not kid:
            add(findings, SEV_MED, f"{token_type}: kid 누락(여러 키 환경)",
                "여러 키가 제공될 때는 kid 포함이 사실상 필요.",
                {"header": header}, "OIDC Core §10.1 / RFC 7517 §4.5")

        # kid 매칭
        if kid:
            if kid not in by_kid:
                add(findings, SEV_HIGH, f"{token_type}: 알 수 없는 kid",
                    "현재 JWKS에 해당 kid가 없음 → 재조회 필요(없으면 거부).",
                    {"kid": kid}, "OIDC Core §10.1.1 (재조회 권고)")
        else:
            # 단일 키면 허용 가능
            if len(all_jwks_keys) == 1:
                pass

    for t in tokens:
        # ----------------[ DATA CONTROLLER INPUT HERE ]----------------
        token_type = t.get("token_type")       # "id_token" | "access_token" | "client_assertion"
        jwt = t.get("jwt")                     # JWS Compact 원문
        # --------------------------------------------------------------
        if token_type and jwt:
            check_token(token_type, jwt)

    # ---- 클라이언트 등록 메타데이터 점검 ----
    if client_reg:
        jwks_uri_reg = client_reg.get("jwks_uri")
        jwks_inline = client_reg.get("jwks")
        if jwks_uri_reg and jwks_inline:
            add(findings, SEV_HIGH, "등록 메타데이터에 jwks_uri와 jwks 동시 제공",
                "동시에 제공하면 안 됨(MUST NOT).", client_reg, "OIDC Registration")
        if jwks_uri_reg:
            if urlparse(jwks_uri_reg).scheme.lower() != "https":
                add(findings, SEV_HIGH, "등록 메타데이터의 jwks_uri가 HTTPS 아님",
                    jwks_uri_reg, client_reg, "OIDC Registration/Discovery")

        # client_assertion 관련 기대 alg
        expected = client_reg.get("token_endpoint_auth_signing_alg")
        if expected and allowed_algs and expected not in allowed_algs:
            add(findings, SEV_INFO, "등록 alg와 스캐너 허용 alg 상이",
                f"expected={expected}, allowed={allowed_algs}",
                None, "운영 정보")

    # ---- 요약 스코어/권고 ----
    sev_rank = {SEV_HIGH:3, SEV_MED:2, SEV_LOW:1, SEV_INFO:0}
    score = sum(sev_rank[f["severity"]] for f in findings)
    summary = {
        "issue_count": len(findings),
        "score": score,
        "has_critical": any(f["severity"]==SEV_HIGH for f in findings),
        "note": "점수는 위험 신호의 단순 합산(운영 참고용)."
    }
    return {"summary": summary, "findings": findings}


# -------------------------- 사용 예시 (주입 가이드) --------------------------
if __name__ == "__main__":
    # ⚠️ 여기 블록은 Data Controller가 데이터를 주입해서 단독 실행할 때 쓰는 예시입니다.
    demo_inputs = {
        # ===== [DATA CONTROLLER INPUT HERE] Discovery 주입 =====
        "discovery": {
            "discovery_url": "https://issuer.example/.well-known/openid-configuration",
            "http_status": 200,
            "body_json": {
                "issuer": "https://issuer.example",
                "jwks_uri": "https://issuer.example/keys"
            },
            "tls_verified": True,
            "redirect_chain": []
        },
        # ===== [DATA CONTROLLER INPUT HERE] JWKS 조회들 =====
        "jwks_fetches": [
            {
                "requested_url": "https://issuer.example/keys",
                "final_url": "https://issuer.example/keys",
                "http_status": 200,
                "scheme": "https",
                "host": "issuer.example",
                "redirect_chain": [],
                "headers": {"Cache-Control": "max-age=3600", "ETag": "W/\"abc\""},
                "jwks_json": {"keys": [
                    {"kty":"RSA","kid":"k1","use":"sig","n":"...","e":"AQAB","alg":"RS256"}
                ]}
            }
        ],
        # ===== [DATA CONTROLLER INPUT HERE] 토큰 원문들 =====
        "tokens": [
            {"token_type":"id_token","jwt":"<ID_TOKEN_JWS_COMPACT>"},
            {"token_type":"client_assertion","jwt":"<CLIENT_ASSERTION_JWS_COMPACT>"}
        ],
        # ===== [DATA CONTROLLER INPUT HERE] (선택) 등록 메타데이터 =====
        "client_registration": {
            # "jwks_uri":"https://client.example/jwks.json",
            # "jwks": {"keys":[...]},  # 둘 동시 제공 금지
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "RS256"
        },
        # ===== [DATA CONTROLLER INPUT HERE] (선택) 정책 =====
        "allowed_algs": ["RS256","ES256"]
    }

    report = check_key_rotation(demo_inputs)
    print(json.dumps(report, ensure_ascii=False, indent=2))

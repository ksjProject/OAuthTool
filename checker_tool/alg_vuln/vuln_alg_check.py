
"""
vuln_alg_check.py — "잘못된 alg 처리 (alg 공격)" 전용 진단 모듈
(공식문서 기준: RFC 7515/7519/8725, RFC 9068, OIDC Core/Discovery, RFC 9101/9126, RFC 9449)

모듈 역할:
- Data Controller가 모은 HTTP 패킷/토큰 조각을 입력으로 받아, alg 관련 취약 구성을
  정적 진단한다(alg=none, 알고리즘 혼동 표면, 헤더 키 주입, typ 미설정/오용 등).
- 서명 검증은 하지 않는다(키 없음). 대신 공식 프로파일/BCP 기준 '거부 신호'를 탐지.

입력(예상 스키마: Data Controller 보장)
{
  "found_jwts": [ "xxx.yyy.zzz", ... ],  # 임의 수집된 JWT 문자열
  "oauth_tokens": [                      # 요청/응답에서 추출한 토큰들
    {
      "key": "access_token|id_token|refresh_token|authorization|...",
      "value": "<JWT or opaque>",
      "where": "request.headers.authorization|response.body.json|...",
      "url": "<observed URL>",
      "kind": "access_token|id_token|refresh_token|authorization_bearer|unknown_jwt|other"
    }
  ]
}

Data Controller 쪽 TODO (여기에 데이터를 넣으세요):
- HTTP 요청/응답에서 아래 항목을 수집해 이 모듈로 그대로 전달
  * Authorization 헤더의 Bearer 토큰
  * 토큰 엔드포인트 응답 JSON의 access_token / id_token / refresh_token
  * 인가 응답 파라미터(code, state) 및 관련 토큰
  * userinfo 호출의 Authorization 헤더
  * 쿠키/스토리지 등에서 발견되는 임의 JWT(found_jwts)
"""

import json, base64, re
from typing import Dict, Any, Tuple, Optional, List

BASE64URL_RE = re.compile(r'^[A-Za-z0-9_-]+$')

def b64url_decode(segment: str) -> bytes:
    pad = '=' * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)

def try_parse_jwt(token: str):
    parts = token.split('.')
    if len(parts) < 2:
        return None, None, "not_jws"
    try:
        h_raw = b64url_decode(parts[0]).decode('utf-8', 'ignore')
        p_raw = b64url_decode(parts[1]).decode('utf-8', 'ignore')
        header = json.loads(h_raw)
        payload = json.loads(p_raw)
        return header, payload, None
    except Exception as e:
        return None, None, f"parse_error:{type(e).__name__}"

def is_b64url(s: str) -> bool:
    return bool(BASE64URL_RE.fullmatch(s))

def detect_header_risks(header: dict) -> List[dict]:
    findings = []
    alg = header.get("alg")
    typ = header.get("typ") or header.get("type")
    kid = header.get("kid")
    jku = header.get("jku")
    jwk = header.get("jwk")
    x5u = header.get("x5u")
    x5c = header.get("x5c")
    crit = header.get("crit")

    if alg is None:
        findings.append({"rule":"ALG_MISSING","severity":"high",
                         "why":"alg 헤더가 없음 (RFC 7515 필수)."})
    elif str(alg).lower() == "none":
        findings.append({"rule":"ALG_NONE","severity":"high",
                         "why":"alg=none(Unsecured). RFC 8725는 기본 거부 권고, RFC 9068 AT-JWT는 MUST NOT."})

    if alg and isinstance(alg, str) and alg.upper().startswith("HS"):
        findings.append({"rule":"ALG_HMAC_WARNING","severity":"medium",
                         "why":"HS* 사용. OIDC/AT 프로파일 맥락에 따라 키 혼동 공격 표면 증가—알고리즘·키 고정 필요(RFC 8725 §3.1)."})

    if typ is None:
        findings.append({"rule":"TYP_ABSENT","severity":"low",
                         "why":"typ 미지정. BCP는 혼동 방지 위해 명시 권고, RFC 9068은 AT-JWT에 at+jwt 요구."})

    if jku is not None:
        findings.append({"rule":"HDR_JKU_PRESENT","severity":"high",
                         "why":"헤더의 jku 사용. OIDC Core는 ID 토큰에서 사용 지양(SHOULD NOT); SSRF/키주입 우려(RFC 8725)."})
    if jwk is not None:
        findings.append({"rule":"HDR_JWK_PRESENT","severity":"high",
                         "why":"헤더에 jwk 임베드. 신뢰 도메인 외 키 주입 위험—사전 합의된 jwks_uri만 사용 권고."})
    if x5u is not None:
        findings.append({"rule":"HDR_X5U_PRESENT","severity":"high",
                         "why":"헤더의 x5u 사용. 외부 URL 추종은 SSRF 위험(RFC 8725)."})
    if x5c is not None:
        findings.append({"rule":"HDR_X5C_PRESENT","severity":"medium",
                         "why":"헤더 x5c 사용. 체인 검증 정책 필요—신뢰루트/발급자 바인딩 확인 필수."})

    if kid is not None:
        kid_s = str(kid)
        if any(p in kid_s for p in ["..", "/", "\\"]):
            findings.append({"rule":"KID_PATHLIKE","severity":"high",
                             "why":"kid에 경로/탐색 패턴 존재. 파일 경로 조합 등 인젝션 표면."})
        if len(kid_s) > 256:
            findings.append({"rule":"KID_TOO_LONG","severity":"medium",
                             "why":"비정상적으로 긴 kid. 동적 조회/SSRF 표면 가능."})
        if not is_b64url(kid_s.replace(":", "").replace("-", "_")):
            findings.append({"rule":"KID_CHARS","severity":"low",
                             "why":"kid에 비표준 문자 포함. 내부 인덱스만으로 사용 권장."})

    if crit is not None:
        findings.append({"rule":"CRIT_PRESENT","severity":"medium",
                         "why":"crit 존재. 수신자가 모르는 파라미터가 crit에 있으면 거부해야 함(RFC 7515). 구현 확인 필요."})

    return findings

def classify_context(entry: dict, header: dict, payload: dict) -> str:
    kind = entry.get("kind") or ""
    key = entry.get("key") or ""
    typ = (header or {}).get("typ") or (payload or {}).get("typ")
    if kind in {"access_token"} or key == "access_token":
        return "access_token"
    if kind in {"id_token"} or key == "id_token" or typ == "ID":
        return "id_token"
    if kind in {"refresh_token"} or key == "refresh_token" or typ in ("Offline", "Refresh"):
        return "refresh_token"
    if key == "authorization" or kind == "authorization_bearer":
        return "bearer_header"
    return "unknown"

def policy_checks(context: str, header: dict, payload: dict) -> List[dict]:
    findings = []
    alg = (header or {}).get("alg")
    typ = (header or {}).get("typ")
    if context == "access_token":
        if alg and str(alg).lower() == "none":
            findings.append({"rule":"AT_NONE_FORBIDDEN","severity":"high",
                             "why":"Access Token JWT에서 alg=none은 RFC 9068에 의해 금지(MUST NOT)."})
        if typ not in ("at+jwt",):
            findings.append({"rule":"AT_TYP_NOT_ATJWT","severity":"medium",
                             "why":"Access Token JWT의 typ는 at+jwt가 권장/요구(RFC 9068 §2.1). 관측 typ=%r" % (typ,)})
        if alg and str(alg).upper().startswith("HS"):
            findings.append({"rule":"AT_HS_USED","severity":"medium",
                             "why":"AT-JWT에 HS* 사용. 비대칭 서명 권장 및 RS256 지원 요구(RFC 9068)."})
    elif context == "id_token":
        if alg and str(alg).lower() == "none":
            findings.append({"rule":"ID_TOKEN_NONE_FORBIDDEN","severity":"high",
                             "why":"OIDC ID Token의 alg=none은 프런트채널에서 금지. 코드 플로우+사전등록 예외만."})
    return findings

def analyze(data: Dict[str, Any]) -> Dict[str, Any]:
    findings_all = []
    tokens_scanned = 0
    algs_by_iss = {}

    for entry in data.get("oauth_tokens", []):
        token = entry.get("value","")
        if token.count('.') < 2:
            continue
        header, payload, err = try_parse_jwt(token)
        tokens_scanned += 1
        if err:
            findings_all.append({"where": entry.get("where"), "url": entry.get("url"),
                                 "kind": entry.get("kind"), "key": entry.get("key"),
                                 "error": err})
            continue
        iss = (payload or {}).get("iss")
        alg = (header or {}).get("alg")
        if iss and alg:
            algs_by_iss.setdefault(iss, set()).add(str(alg))

        ctx = classify_context(entry, header, payload)
        f = detect_header_risks(header)
        f += policy_checks(ctx, header, payload)

        findings_all.append({
            "where": entry.get("where"),
            "url": entry.get("url"),
            "kind": entry.get("kind"),
            "key": entry.get("key"),
            "context": ctx,
            "header": header,
            "payload_typ": (payload or {}).get("typ"),
            "alg": alg,
            "findings": f
        })

    for token in data.get("found_jwts", []):
        if token.count('.') < 2:
            continue
        header, payload, err = try_parse_jwt(token)
        tokens_scanned += 1
        entry = {"where":"found_jwts","url":"(unknown)","kind":"unknown_jwt","key":"found_jwt"}
        if err:
            findings_all.append({"where": entry["where"], "url": entry["url"],
                                 "kind": entry["kind"], "key": entry["key"], "error": err})
            continue
        iss = (payload or {}).get("iss")
        alg = (header or {}).get("alg")
        if iss and alg:
            algs_by_iss.setdefault(iss, set()).add(str(alg))

        ctx = classify_context(entry, header, payload)
        f = detect_header_risks(header)
        f += policy_checks(ctx, header, payload)

        findings_all.append({
            "where": entry["where"], "url": entry["url"], "kind": entry["kind"], "key": entry["key"],
            "context": ctx, "header": header, "payload_typ": (payload or {}).get("typ"),
            "alg": alg, "findings": f
        })

    issuer_mixed = []
    for iss, algs in algs_by_iss.items():
        families = set(("HS" if a.upper().startswith("HS") else
                        "RS" if a.upper().startswith("RS") else
                        "ES" if a.upper().startswith("ES") else
                        "PS" if a.upper().startswith("PS") else
                        a.upper()) for a in algs)
        if ("HS" in families) and (("RS" in families) or ("ES" in families) or ("PS" in families)):
            issuer_mixed.append({"iss": iss,
                                 "algs": sorted(algs),
                                 "why": "동일 발행자에서 대칭(HS*)과 비대칭(RS*/ES*/PS*) 혼용 관측. 검증자가 alg를 신뢰하면 키 혼동 공격 표면."})

    summary = {
        "tokens_scanned": tokens_scanned,
        "issuer_mixed_alg_families": issuer_mixed,
        "high_severity_count": sum(1 for e in findings_all for f in e.get("findings",[]) if f["severity"]=="high"),
        "medium_severity_count": sum(1 for e in findings_all for f in e.get("findings",[]) if f["severity"]=="medium"),
        "low_severity_count": sum(1 for e in findings_all for f in e.get("findings",[]) if f["severity"]=="low"),
    }

    return {"summary": summary, "details": findings_all}

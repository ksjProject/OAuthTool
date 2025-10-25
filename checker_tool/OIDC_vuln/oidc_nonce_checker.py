# -*- coding: utf-8 -*-
"""
oidc_nonce_checker.py — OIDC nonce 미사용/미검증 취약점 자동 진단 모듈

Purpose
- OIDC Authorization Code 플로우 기준으로 nonce 관련 취약점을 점검합니다.
- 입력은 adapter가 만든 flow_bundle(JSON dict) 하나입니다.

Checks (요지)
A. Authorization Request
  - flow_identify: scope/response_type으로 플로우 확인
  - nonce_used_in_codeflow: (팀 정책) Code Flow에서도 nonce 요구(N1C)
  - nonce_entropy_freshness: 길이/엔트로피/재사용 의심(N5/N6)

B. ID Token
  - id_token_must_include_nonce_if_requested: 요청에 nonce 보냈다면 ID Token에 nonce MUST 포함(N2)
  - (Code에서는 존재만 확인하고, 동등성은 C에서 수행)

C. Client Validation
  - nonce_equality_validation: 요청 값 == id_token.nonce(MUST)(N4)
  - nonce_replay_rejection: 이전 관측 nonce 재사용 차단(SHOULD)(N6)
  - iss_matches_discovery: ID Token iss == discovery.issuer (D1)
  - aud_includes_client: ID Token aud에 client_id 포함
  - alg_supported_by_discovery: header.alg ∈ discovery.id_token_signing_alg_values_supported
  - kid_found_in_jwks: header.kid ∈ jwks.keys[*].kid

Advisory
  - [A1] PKCE 미사용 추정 (code_challenge(S256) 부재 시 경고)

Labels
  - FAIL 하나라도 있으면 Overall=FAIL
  - FAIL 없고 Advisory 있으면 Overall=ADVISORY
  - 둘 다 없으면 Overall=PASS
"""

import base64
import json
import math
import os  # ← 추가: 파일 fallback 로드를 위해 사용
from typing import Any, Dict, List, Tuple, Optional

# ======= 외부 참조 파일 기본 경로 (요청 반영) =======
DISCOVERY_DIR = r"C:\Users\com\Desktop\OAuthTool\discovery_artifacts"

# ========= 공통 유틸 =========

def _b64url_decode(data: str) -> bytes:
    pad = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)

def _parse_jwt(token: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """서명 검증 없이 header/payload만 파싱."""
    header_b64, payload_b64, *_ = token.split(".")
    header = json.loads(_b64url_decode(header_b64))
    payload = json.loads(_b64url_decode(payload_b64))
    return header, payload

def _shannon_entropy_bits(s: str) -> float:
    """문자열의 샤논 엔트로피(bit) x 길이 = 총 추정 비트."""
    if not s:
        return 0.0
    from collections import Counter
    cnt = Counter(s)
    H = 0.0
    n = len(s)
    for c in cnt.values():
        p = c / n
        H -= p * math.log(p, 2)
    return H * n  # 총 비트수

def _get(d: Dict, *path, default=None):
    cur = d
    for p in path:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur

# ========= 정책/기준 =========

STRICT_CODE_NONCE = True    # 팀 정책: 코드 플로우에서도 nonce 필수
NONCE_MIN_LEN = 16          # 길이 기준
NONCE_MIN_BITS = 128.0      # 엔트로피 총 비트 기준 (예: 128비트 이상 권고)

# ========= 체크 구현 =========

def _flow_identify(bundle: Dict) -> Tuple[str, Dict[str, Any]]:
    params = _get(bundle, "authorization_request", "params", default={}) or {}
    scope = params.get("scope", "")
    rt = params.get("response_type", "")
    flow = "code" if "code" in rt else ("implicit/hybrid" if any(x in rt for x in ["id_token", "token"]) else "unknown")
    return flow, {"scope": scope, "response_type": rt}

def _nonce_from_request(bundle: Dict) -> Optional[str]:
    return _get(bundle, "authorization_request", "params", "nonce")

def _client_id(bundle: Dict) -> Optional[str]:
    return _get(bundle, "authorization_request", "params", "client_id")

def _id_token(bundle: Dict) -> Optional[str]:
    return _get(bundle, "token_response", "json", "id_token")

def _previous_nonces(bundle: Dict) -> List[str]:
    return _get(bundle, "previous_nonces", default=[]) or []

def _discovery(bundle: Dict) -> Dict[str, Any]:
    """flow_bundle에 discovery 없으면 고정 경로에서 fallback 로드."""
    d = bundle.get("discovery") or {}
    if not d:
        try:
            with open(os.path.join(DISCOVERY_DIR, "openid_configuration.json"), "r", encoding="utf-8") as f:
                d = json.load(f)
        except Exception:
            d = {}
    return d

def _jwks(bundle: Dict) -> Dict[str, Any]:
    """flow_bundle에 jwks 없으면 고정 경로에서 fallback 로드."""
    j = bundle.get("jwks") or {}
    if not j:
        try:
            with open(os.path.join(DISCOVERY_DIR, "jwks.json"), "r", encoding="utf-8") as f:
                j = json.load(f)
        except Exception:
            j = {}
    return j

def run_checks(bundle: Dict) -> Dict[str, Any]:
    issues: List[Dict[str, Any]] = []
    checklist: Dict[str, Dict[str, Any]] = {"A": {}, "B": {}, "C": {}}

    flow, evidence_fi = _flow_identify(bundle)
    checklist["A"]["flow_identify"] = {"result": "Pass", "evidence": evidence_fi}

    req_nonce = _nonce_from_request(bundle)
    idt = _id_token(bundle)

    # A. Authorization Request
    if flow == "code":
        if STRICT_CODE_NONCE and not req_nonce:
            issues.append({
                "level": "FAIL",
                "code": "N1C",
                "title": "nonce 미포함(Code, strict 정책)",
                "reason": "Code 플로우에서도 nonce가 없으면 세션 결속/재생 탐지 약화.",
                "remedy": "인가요청에 강한 난수 'nonce' 포함, 콜백/ID Token과 동일 비교 후 1회용 저장/폐기.",
                "evidence": {"response_type": _get(bundle, "authorization_request", "params", "response_type"),
                            "scope": _get(bundle, "authorization_request", "params", "scope")}
            })
            checklist["A"]["nonce_used_in_codeflow"] = {"result": "Fail"}
        else:
            checklist["A"]["nonce_used_in_codeflow"] = {"result": "Pass"}
    else:
        checklist["A"]["nonce_used_in_codeflow"] = {"result": "N/A"}

    # 엔트로피/신선도
    if req_nonce:
        bits = _shannon_entropy_bits(req_nonce)
        length_ok = len(req_nonce) >= NONCE_MIN_LEN
        entropy_ok = bits >= NONCE_MIN_BITS
        if not length_ok or not entropy_ok:
            issues.append({
                "level": "FAIL",
                "code": "N5",
                "title": "nonce 엔트로피/길이 부족",
                "reason": f"길이>={NONCE_MIN_LEN}, 엔트로피>={int(NONCE_MIN_BITS)}비트 권장.",
                "remedy": "CSPRNG 기반 128비트 이상 난수 사용(Base64url 등).",
                "evidence": {"length": len(req_nonce), "entropy_bits": round(bits, 2)}
            })
            checklist["A"]["nonce_entropy_freshness"] = {"result": "Fail", "entropy_bits": bits}
        else:
            checklist["A"]["nonce_entropy_freshness"] = {"result": "Pass", "entropy_bits": bits}
    else:
        checklist["A"]["nonce_entropy_freshness"] = {"result": "N/A"}

    # B. ID Token
    if req_nonce:
        if not idt:
            issues.append({
                "level": "FAIL",
                "code": "N2",
                "title": "ID Token 미수신",
                "reason": "요청에 nonce를 보냈는데 ID Token이 수신되지 않음.",
                "remedy": "권한 부여 서버에서 code 교환 시 ID Token을 발급/반환하도록 구성을 점검.",
                "evidence": {"openid_scope": "openid" in (evidence_fi["scope"] or ""), "id_token_present": False}
            })
            checklist["B"]["id_token_must_include_nonce_if_requested"] = {"result": "Fail"}
        else:
            # 단순 존재만 PASS (동등성은 C 섹션에서)
            try:
                _, payload = _parse_jwt(idt)
                has = "nonce" in payload
            except Exception:
                has = False
            checklist["B"]["id_token_must_include_nonce_if_requested"] = {"result": "Pass" if has else "Fail"}
            if not has:
                issues.append({
                    "level": "FAIL",
                    "code": "N3",
                    "title": "ID Token nonce 미포함",
                    "reason": "요청에 nonce를 보냈다면 ID Token에 nonce 클레임 MUST 포함.",
                    "remedy": "Authorization Server(ID Token 생성 시) nonce 클레임 포함.",
                    "evidence": {"id_token_has_nonce": has}
                })
    else:
        checklist["B"]["id_token_must_include_nonce_if_requested"] = {"result": "N/A"}

    # C. Client Validation
    # nonce equality
    if req_nonce and idt:
        try:
            _, payload = _parse_jwt(idt)
            idt_nonce = payload.get("nonce")
        except Exception:
            idt_nonce = None

        if idt_nonce is None:
            checklist["C"]["nonce_equality_validation"] = {"result": "Fail"}
        elif idt_nonce == req_nonce:
            checklist["C"]["nonce_equality_validation"] = {"result": "Pass"}
        else:
            checklist["C"]["nonce_equality_validation"] = {"result": "Fail"}
            issues.append({
                "level": "FAIL",
                "code": "N4",
                "title": "ID Token nonce 불일치",
                "reason": "요청의 nonce와 ID Token의 nonce가 동일해야 함.",
                "remedy": "콜백에서 세션 저장 값과 ID Token nonce를 동등 비교하여 불일치 시 거부.",
                "evidence": {"request_nonce": req_nonce, "id_token_nonce": idt_nonce}
            })
    else:
        checklist["C"]["nonce_equality_validation"] = {"result": "N/A"}

    # nonce replay (이전 관측 목록과 비교)
    prev = set(_previous_nonces(bundle))
    if req_nonce:
        if req_nonce in prev:
            checklist["C"]["nonce_replay_rejection"] = {"result": "Fail"}
            issues.append({
                "level": "FAIL",
                "code": "N6",
                "title": "nonce 재사용 탐지",
                "reason": "이전에 관측된 nonce가 재사용됨(재생 공격 가능).",
                "remedy": "nonce를 1회용으로 저장하고 사용 후 즉시 폐기.",
                "evidence": {"reused": True}
            })
        else:
            checklist["C"]["nonce_replay_rejection"] = {"result": "Pass"}
    else:
        checklist["C"]["nonce_replay_rejection"] = {"result": "N/A"}

    # iss/aud/alg/kid 연계
    disc = _discovery(bundle)
    jwks = _jwks(bundle)

    if idt:
        try:
            header, payload = _parse_jwt(idt)
        except Exception:
            header, payload = {}, {}

        # iss
        iss = payload.get("iss")
        if disc.get("issuer") and iss:
            checklist["C"]["iss_matches_discovery"] = {
                "result": "Pass" if iss == disc["issuer"] else "Fail",
                "issuer": iss
            }
            if iss != disc["issuer"]:
                issues.append({
                    "level": "FAIL",
                    "code": "D1",
                    "title": "iss 누락/불일치",
                    "reason": "ID Token의 iss가 discovery.issuer와 불일치.",
                    "remedy": "issuer 값을 discovery와 동일하게 설정하고 불일치 시 오류 처리.",
                    "evidence": {"iss": iss, "discovery.issuer": disc.get("issuer")}
                })
        else:
            checklist["C"]["iss_matches_discovery"] = {"result": "N/A"}

        # aud
        aud = payload.get("aud")
        cid = _client_id(bundle)
        aud_ok = False
        if aud and cid:
            if isinstance(aud, list):
                aud_ok = cid in aud
            else:
                aud_ok = (cid == aud)
            checklist["C"]["aud_includes_client"] = {"result": "Pass" if aud_ok else "Fail"}
        else:
            checklist["C"]["aud_includes_client"] = {"result": "N/A"}

        # alg
        alg = header.get("alg")
        supported = disc.get("id_token_signing_alg_values_supported")
        if alg and isinstance(supported, list):
            checklist["C"]["alg_supported_by_discovery"] = {
                "result": "Pass" if alg in supported else "Fail",
                "alg": alg
            }
        else:
            checklist["C"]["alg_supported_by_discovery"] = {"result": "N/A"}

        # kid
        kid = header.get("kid")
        if kid and isinstance(jwks.get("keys"), list):
            found = any(k.get("kid") == kid for k in jwks["keys"])
            checklist["C"]["kid_found_in_jwks"] = {"result": "Pass" if found else "Fail"}
        else:
            checklist["C"]["kid_found_in_jwks"] = {"result": "N/A"}
    else:
        for k in ["iss_matches_discovery", "aud_includes_client", "alg_supported_by_discovery", "kid_found_in_jwks"]:
            checklist["C"][k] = {"result": "N/A"}

    # Advisory: PKCE
    params = _get(bundle, "authorization_request", "params", default={}) or {}
    cc = params.get("code_challenge")
    ccm = params.get("code_challenge_method")
    if cc is None or (ccm or "").upper() != "S256":
        issues.append({
            "level": "ADVISORY",
            "code": "A1",
            "title": "PKCE 미사용 추정",
            "reason": "코드 플로우는 PKCE(S256) 사용이 안전합니다.",
            "remedy": "code_challenge(S256)/code_verifier 사용.",
            "evidence": {"code_challenge": bool(cc), "code_challenge_method": ccm}
        })

    # Overall
    label = "PASS"
    if any(i["level"] == "FAIL" for i in issues):
        label = "FAIL"
    elif any(i["level"] == "ADVISORY" for i in issues):
        label = "ADVISORY"

    return {
        "label": label,
        "flow_type": flow,
        "checklist": {
            "A": checklist["A"],
            "B": checklist["B"],
            "C": checklist["C"],
        },
        "issues": issues
    }

def pretty_report(res: Dict[str, Any]) -> str:
    """사람이 읽기 좋은 텍스트 리포트."""
    out: List[str] = []
    out.append("===== REPORT =====")
    out.append("")
    out.append(f"Flow: {res.get('flow_type')}   Overall: {res.get('label')}")
    out.append("")
    # A
    out.append("== A. Authorization Request ==")
    for k in ["flow_identify", "nonce_used_in_codeflow", "nonce_entropy_freshness"]:
        item = res["checklist"]["A"].get(k)
        if item:
            if k == "flow_identify":
                out.append(f"- {k}: {item['result']}")
                out.append(f"  • {item['evidence']}")
            else:
                out.append(f"- {k}: {item['result']}")
    out.append("")
    # B
    out.append("== B. ID Token ==")
    for k in ["id_token_must_include_nonce_if_requested"]:
        item = res["checklist"]["B"].get(k)
        if item:
            out.append(f"- {k}: {item['result']}")
    out.append("")
    # C
    out.append("== C. Client Validation ==")
    for k in [
        "nonce_equality_validation",
        "nonce_replay_rejection",
        "iss_matches_discovery",
        "aud_includes_client",
        "alg_supported_by_discovery",
        "kid_found_in_jwks",
    ]:
        item = res["checklist"]["C"].get(k)
        if item:
            out.append(f"- {k}: {item['result']}")
    out.append("")
    # Failures / Advisories
    fails = [i for i in res["issues"] if i["level"] == "FAIL"]
    advis = [i for i in res["issues"] if i["level"] == "ADVISORY"]
    if fails:
        out.append("Failures:")
        for f in fails:
            out.append(f" - [{f['code']}] {f['title']}")
            out.append(f"   - 이유: {f['reason']}")
            out.append(f"   - 조치: {f['remedy']}")
            if f.get("evidence") is not None:
                out.append(f"   - 증거: {f['evidence']}")
        out.append("")
    if advis:
        out.append("Advisories:")
        for a in advis:
            out.append(f" - [{a['code']}] {a['title']}")
            out.append(f"   - 이유: {a['reason']}")
            out.append(f"   - 조치: {a['remedy']}")
        out.append("")
    return "\n".join(out)

def run(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """run_checks와 동일. (호환용)"""
    return run_checks(bundle)

# 모듈 단독 실행 (stdin으로 flow_bundle을 받을 때 사용)
if __name__ == "__main__":
    import sys
    try:
        raw = json.load(sys.stdin)
    except Exception:
        sys.stderr.write("Provide a JSON flow bundle via stdin.\n")
        raise
    res = run_checks(raw)
    print(pretty_report(res))

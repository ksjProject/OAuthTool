
"""
oidc_nonce_checker.py — cleaner report + 128-bit total entropy enforcement
- Consumes discovery/JWKS from flow_bundle (if present) to add basic issuer/alg/kid checks
- Drop-in for adapter_to_checker.py
"""
from datetime import datetime, timezone
from typing import Dict, Any, List
import re, json

# ---- Policy thresholds ----
MIN_NONCE_LEN = 16                      # 최소 길이
MIN_ENTROPY_PER_CHAR = 3.0              # 문자당 Shannon 엔트로피 (bits/char)
MIN_TOTAL_BITS = 128                    # ✅ 총 엔트로피(추정) 최소 128비트

# ---- Utilities ----
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from math import log2
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    H = 0.0
    L = len(s)
    for c in freq.values():
        p = c / L
        H -= p * log2(p)
    return H  # bits/char

def estimate_nonce_bits(s: str) -> Dict[str, Any]:
    """
    총 엔트로피 비트수(추정)를 계산.
    - shannon 기반 추정: H_per_char * len(s)
    - 인코딩 기반 상한: hex(4*L), base64url(6*L)
    - 보수적으로 두 값의 min 사용
    """
    L = len(s)
    Hc = shannon_entropy(s)            # bits/char
    shannon_bits = Hc * L

    if re.fullmatch(r"[0-9a-fA-F]+", s):
        enc_bits = 4 * L               # hex: 1 char ~= 4 bits
        method = "min(shannon,hex)"
    elif re.fullmatch(r"[A-Za-z0-9_-]+", s):
        enc_bits = 6 * L               # base64url: 1 char ~= 6 bits (대략)
        method = "min(shannon,base64url)"
    else:
        enc_bits = shannon_bits
        method = "shannon"

    total_bits = min(shannon_bits, enc_bits)
    return {
        "length": L,
        "entropy_per_char": Hc,
        "total_bits_est": total_bits,
        "method": method
    }

def infer_flow(response_type: str, resp: dict, token: dict) -> str:
    rt = (response_type or "").replace(" ", "")
    if rt in ("id_token", "token", "id_tokentoken"):
        return "implicit"
    if "id_token" in rt and "code" in rt:
        return "hybrid"
    if rt == "code" or "code" in rt:
        return "code"
    if (resp or {}).get("id_token") and not (resp or {}).get("code"):
        return "implicit"
    return "code"

def _pass(): return {"result": "Pass"}
def _fail(note=""): return {"result": "Fail", "note": note}
def _na(): return {"result": "N/A"}

# ---- Core checker ----
def run(flow_bundle: Dict[str, Any], policy: Dict[str, Any] | None = None) -> Dict[str, Any]:
    policy = policy or {}
    strict_code_nonce = bool(policy.get("strict_code_nonce", True))
    min_total_bits = int(policy.get("min_total_bits", MIN_TOTAL_BITS))

    now = datetime.now(timezone.utc).isoformat()

    req = (flow_bundle.get("authorization_request") or {}).get("params") or {}
    resp = (flow_bundle.get("authorization_response") or {}).get("params") or {}
    token = flow_bundle.get("token") or {}
    refresh = flow_bundle.get("refresh") or {}
    id_header = token.get("id_token_header") or {}
    id_payload = token.get("id_token_payload") or {}
    refresh_payload = refresh.get("id_token_payload") or {}

    previous_nonces = flow_bundle.get("previous_nonces") or []
    response_type = (req.get("response_type") or "").strip()
    flow = flow_bundle.get("flow") or infer_flow(response_type, resp, token)
    openid_scope = bool(flow_bundle.get("openid_scope"))

    discovery = flow_bundle.get("discovery") or {}
    jwks = (flow_bundle.get("jwks") or {}).get("keys", [])
    issuer_expected = flow_bundle.get("issuer_expected")

    req_nonce = req.get("nonce")
    client_id = req.get("client_id") or req.get("client") or req.get("clientId")
    id_token_present = bool(token.get("id_token"))
    id_nonce = id_payload.get("nonce")
    refresh_nonce = refresh_payload.get("nonce")

    # Data holders
    issues: List[Dict[str, Any]] = []
    checklist = {"A": {}, "B": {}, "C": {}}
    stats = {"now_utc": now, "flow": flow, "strict_code_nonce": strict_code_nonce}

    # === A. Authorization Request ===
    checklist["A"]["flow_identify"] = _pass()
    checklist["A"]["flow_identify"]["observed"] = str({"scope": req.get("scope"), "response_type": response_type})

    # nonce_required_implicit_hybrid
    if flow in ("implicit", "hybrid"):
        if req_nonce:
            checklist["A"]["nonce_required_implicit_hybrid"] = _pass()
        else:
            checklist["A"]["nonce_required_implicit_hybrid"] = _fail("Implicit/Hybrid에서 nonce는 REQUIRED")
            issues.append({
                "code": "N1", "level": "FAIL",
                "title": "nonce 미포함(Implicit/Hybrid)",
                "detail": "Implicit/Hybrid 플로우에서 인가요청에 nonce가 필요합니다.",
                "evidence": {"flow": flow, "response_type": response_type}
            })
    else:
        checklist["A"]["nonce_required_implicit_hybrid"] = _na()

    # nonce_used_in_codeflow (team policy)
    if flow == "code":
        if req_nonce:
            checklist["A"]["nonce_used_in_codeflow"] = _pass()
        else:
            if strict_code_nonce:
                checklist["A"]["nonce_used_in_codeflow"] = _fail("팀 정책: code에서도 nonce 요구")
                issues.append({
                    "code": "N1C", "level": "FAIL",
                    "title": "nonce 미포함(Code, strict 정책)",
                    "detail": "팀 정책(strict_code_nonce=True)에 따라 code 플로우에서도 nonce가 필요합니다.",
                    "evidence": {"response_type": response_type, "scope": req.get("scope")}
                })
            else:
                checklist["A"]["nonce_used_in_codeflow"] = {"result": "Advisory", "note": "권장: code에서도 nonce 사용"}

    # nonce_entropy_freshness (length/entropy/totalbits + reuse check)
    if req_nonce:
        bits = estimate_nonce_bits(str(req_nonce))
        stats["req_nonce_len"] = bits["length"]
        stats["req_nonce_entropy_bits_per_char"] = bits["entropy_per_char"]
        stats["req_nonce_total_bits_est"] = round(bits["total_bits_est"], 1)
        stats["req_nonce_bits_method"] = bits["method"]

        weak_len = bits["length"] < MIN_NONCE_LEN
        weak_entropy = bits["entropy_per_char"] < MIN_ENTROPY_PER_CHAR
        weak_total = bits["total_bits_est"] < min_total_bits

        if weak_len or weak_entropy or weak_total:
            reasons = []
            if weak_len: reasons.append(f"길이<{MIN_NONCE_LEN}")
            if weak_entropy: reasons.append(f"엔트로피/문자<{MIN_ENTROPY_PER_CHAR}")
            if weak_total: reasons.append(f"총엔트로피<{min_total_bits}비트")
            checklist["A"]["nonce_entropy_freshness"] = _fail(", ".join(reasons))
            issues.append({
                "code": "N5", "level": "FAIL",
                "title": "약한 nonce(길이/엔트로피/총비트 기준 미달)",
                "detail": "요청 nonce의 무작위성이 약하거나 총 엔트로피가 기준 미만입니다.",
                "evidence": {
                    "length": bits["length"],
                    "entropy_per_char": round(bits["entropy_per_char"], 3),
                    "total_bits_est": round(bits["total_bits_est"], 1),
                    "min_len": MIN_NONCE_LEN,
                    "min_entropy_per_char": MIN_ENTROPY_PER_CHAR,
                    "min_total_bits": min_total_bits
                }
            })
        else:
            checklist["A"]["nonce_entropy_freshness"] = _pass()
    else:
        checklist["A"]["nonce_entropy_freshness"] = _na()

    # === B. ID Token (수신/클레임) ===
    # 요청에 nonce 보냈다면 ID Token MUST 포함 + payload에 nonce MUST
    if req_nonce:
        if not id_token_present:
            checklist["B"]["id_token_must_include_nonce_if_requested"] = _fail("ID Token 미수신(N2)")
            issues.append({
                "code": "N2", "level": "FAIL",
                "title": "ID Token 미수신",
                "detail": "요청에 nonce를 보냈으나 ID Token이 수신되지 않았습니다.",
                "evidence": {"openid_scope": openid_scope, "id_token_present": id_token_present}
            })
        else:
            if id_nonce is None:
                checklist["B"]["id_token_must_include_nonce_if_requested"] = _fail("ID Token에 nonce 없음(N3)")
                issues.append({
                    "code": "N3", "level": "FAIL",
                    "title": "ID Token nonce 미포함",
                    "detail": "ID Token payload에 nonce 클레임이 없습니다.",
                    "evidence": {"has_req_nonce": True, "flow": flow}
                })
            else:
                checklist["B"]["id_token_must_include_nonce_if_requested"] = _pass()
    else:
        checklist["B"]["id_token_must_include_nonce_if_requested"] = _pass()  # 요청에 없으면 강제하지 않음

    # Implicit/Hybrid에서 수신한 ID Token에는 nonce 필수
    if flow in ("implicit", "hybrid"):
        if id_token_present and (id_nonce is not None):
            checklist["B"]["implicit_hybrid_idtoken_has_nonce"] = _pass()
        else:
            checklist["B"]["implicit_hybrid_idtoken_has_nonce"] = _fail("Implicit/Hybrid의 ID Token에 nonce 필수(N3/N2)")
            issues.append({
                "code": "N3", "level": "FAIL",
                "title": "ID Token nonce 미포함(Implicit/Hybrid)",
                "detail": "Implicit/Hybrid에서는 수신한 ID Token에 nonce가 포함되어야 합니다.",
                "evidence": {"flow": flow, "id_token_present": id_token_present, "id_nonce": id_nonce}
            })
    else:
        checklist["B"]["implicit_hybrid_idtoken_has_nonce"] = _na()

    # === C. Client Validation ===
    # nonce equality
    if req_nonce and (id_nonce is not None):
        if str(req_nonce) == str(id_nonce):
            checklist["C"]["nonce_equality_validation"] = _pass()
        else:
            checklist["C"]["nonce_equality_validation"] = _fail("요청 nonce ≠ ID Token nonce(N4)")
            issues.append({
                "code": "N4", "level": "FAIL",
                "title": "nonce 불일치",
                "detail": "요청 nonce와 ID Token의 nonce가 다릅니다.",
                "evidence": {"req_nonce_sample": str(req_nonce)[:8], "id_nonce_sample": str(id_nonce)[:8]}
            })
    else:
        checklist["C"]["nonce_equality_validation"] = _na()

    # nonce replay rejection
    if req_nonce and previous_nonces:
        if str(req_nonce) in {str(x) for x in previous_nonces}:
            checklist["C"]["nonce_replay_rejection"] = _fail("같은 nonce 재관측(N6)")
            issues.append({
                "code": "N6", "level": "FAIL",
                "title": "nonce 재사용(Re-Use)",
                "detail": "같은 nonce가 재관측되었습니다(Re-Play 의심).",
                "evidence": {"req_nonce_sample": str(req_nonce)[:8], "previous_count": len(previous_nonces)}
            })
        else:
            checklist["C"]["nonce_replay_rejection"] = _pass()
    else:
        checklist["C"]["nonce_replay_rejection"] = _pass() if req_nonce else _na()

    # ---- Discovery-aware checks (no signature verification, just consistency) ----
    # iss consistency
    if issuer_expected and id_payload.get("iss"):
        if str(id_payload["iss"]) == str(issuer_expected):
            checklist["C"]["iss_matches_discovery"] = _pass()
        else:
            checklist["C"]["iss_matches_discovery"] = _fail("ID Token iss가 discovery와 불일치")
            issues.append({
                "code": "D1", "level": "FAIL",
                "title": "iss 불일치",
                "detail": "ID Token의 iss가 discovery/openid-configuration의 issuer와 다릅니다.",
                "evidence": {"id_iss": id_payload.get("iss"), "expected_iss": issuer_expected}
            })
    elif issuer_expected and not id_payload.get("iss"):
        checklist["C"]["iss_matches_discovery"] = _fail("ID Token에 iss 없음")
        issues.append({
            "code": "D1", "level": "FAIL",
            "title": "iss 누락",
            "detail": "ID Token에 iss 클레임이 없습니다.",
        })
    else:
        checklist["C"]["iss_matches_discovery"] = _na()

    # aud includes client_id
    if client_id and id_payload.get("aud") is not None:
        aud = id_payload["aud"]
        ok_aud = (aud == client_id) or (isinstance(aud, list) and client_id in aud)
        if ok_aud:
            checklist["C"]["aud_includes_client"] = _pass()
        else:
            checklist["C"]["aud_includes_client"] = _fail("aud에 client_id 없음")
            issues.append({
                "code": "D2", "level": "FAIL",
                "title": "aud 불일치",
                "detail": "ID Token aud가 요청 client_id를 포함하지 않습니다.",
                "evidence": {"aud": aud, "client_id": client_id}
            })
    else:
        checklist["C"]["aud_includes_client"] = _na()

    # header alg supported?
    supported_algs = set(discovery.get("id_token_signing_alg_values_supported", []) or [])
    alg = (id_header or {}).get("alg")
    if id_token_present and alg:
        if supported_algs and alg not in supported_algs:
            checklist["C"]["alg_supported_by_discovery"] = _fail("discovery가 허용하지 않은 alg")
            issues.append({
                "code": "D3", "level": "FAIL",
                "title": "alg 미지원",
                "detail": "ID Token header.alg가 discovery에서 선언된 목록에 없습니다.",
                "evidence": {"alg": alg, "supported": sorted(list(supported_algs))[:5]}
            })
        else:
            checklist["C"]["alg_supported_by_discovery"] = _pass()
    else:
        checklist["C"]["alg_supported_by_discovery"] = _na()

    # kid in JWKS?
    kid = (id_header or {}).get("kid")
    if kid and jwks:
        known_kids = {k.get("kid") for k in jwks if k.get("kid")}
        if kid in known_kids:
            checklist["C"]["kid_found_in_jwks"] = _pass()
        else:
            checklist["C"]["kid_found_in_jwks"] = _fail("JWKS에 kid 없음")
            issues.append({
                "code": "D4", "level": "FAIL",
                "title": "kid 미발견",
                "detail": "ID Token header.kid가 JWKS keys에 존재하지 않습니다.",
                "evidence": {"kid": kid, "jwks_kids_count": len(known_kids)}
            })
    else:
        checklist["C"]["kid_found_in_jwks"] = _na()

    # Advisories (권고)
    if not req.get("code_challenge_method") and flow == "code":
        issues.append({"code":"A1","level":"ADVISORY","title":"PKCE 미사용 추정",
                       "detail":"code_challenge_method가 없어 PKCE 미사용으로 추정됩니다."})
    resp_mode = req.get("response_mode")
    if flow in ("implicit", "hybrid") and resp_mode != "form_post":
        issues.append({"code":"A2","level":"ADVISORY","title":"form_post 권고",
                       "detail":"프런트채널 누출 완화를 위해 response_mode=form_post 권장."})

    # Refresh ID Token rules (N7/N8)
    if refresh and refresh.get("id_token"):
        r_nonce = refresh_nonce
        if r_nonce is not None:
            if id_nonce is None:
                issues.append({"code":"N8","level":"ADVISORY","title":"Refresh ID Token에 nonce 포함",
                               "detail":"원본에 nonce가 없어 비교 불가. refresh 응답에는 nonce 제외 권장."})
            else:
                if str(r_nonce) != str(id_nonce):
                    issues.append({"code":"N7","level":"FAIL","title":"Refresh nonce 불일치",
                                   "detail":"Refresh ID Token의 nonce가 원본과 다릅니다(MUST 동일).",
                                   "evidence":{"id_nonce_sample":str(id_nonce)[:8],"refresh_nonce_sample":str(r_nonce)[:8]}})
                else:
                    issues.append({"code":"N8","level":"ADVISORY","title":"Refresh에 nonce 포함(동일)",
                                   "detail":"SHOULD NOT 포함. 혼동 여지."})

    # Final label
    label = "PASS"
    for it in issues:
        if it["level"] == "FAIL":
            label = "FAIL"; break
        if it["level"] == "ADVISORY":
            label = "ADVISORY"
    ok = (label == "PASS")

    result = {
        "ok": ok,
        "label": label,
        "flow_type": flow,
        "issues": issues,
        "checklist": checklist,
        "stats": stats,
        "policy": {"strict_code_nonce": strict_code_nonce, "min_total_bits": min_total_bits}
    }
    return result

# ---- Pretty report (hide Info rows) ----
def pretty_report(res: Dict[str, Any]) -> str:
    j = res
    out = []
    out.append("===== REPORT =====\n")
    out.append(f"Flow: {j.get('flow_type')}  Overall: {'PASS' if j.get('ok') else j.get('label')}\n")

    def dump_section(name, sec):
        out.append(f"== {name} ==")
        for k, v in sec.items():
            if v.get("result") == "Info":
                continue
            out.append(f"- {k}: {v.get('result')}")
            note = v.get("note") or v.get("observed")
            if note and v.get("result") != "Info":
                out.append(f"  • {note}")
        out.append("")

    dump_section("A. Authorization Request", j["checklist"]["A"])
    dump_section("B. ID Token", j["checklist"]["B"])
    dump_section("C. Client Validation", j["checklist"]["C"])

    WHY = {
        "N1C": "Code 플로우에서 nonce가 없으면 세션 결속이 약화되어 ID Token 치환/재생 탐지가 어렵습니다(팀 정책).",
        "N1":  "Implicit/Hybrid에서는 nonce가 REQUIRED입니다. 누락 시 프런트채널 토큰 주입/재생에 취약합니다.",
        "N2":  "nonce를 보냈지만 ID Token이 없어 nonce 검증 경로가 사라졌습니다.",
        "N3":  "ID Token에 nonce가 없어 요청과의 세션 결속을 확인할 수 없습니다.",
        "N4":  "요청 nonce와 ID Token nonce가 달라 중간자/치환 가능성이 있습니다.",
        "N5":  "nonce가 짧거나 예측 가능하거나 총 엔트로피(추정)가 128비트 미만입니다.",
        "N6":  "같은 nonce 재관측(Replay) 의심.",
        "N7":  "Refresh 발급 ID Token의 nonce가 원본과 달라 세션 혼동/치환 위험이 있습니다.",
        "N8":  "Refresh ID Token에 nonce 포함은 권장되지 않습니다(SHOULD NOT).",
        "D1":  "ID Token의 iss가 discovery/openid-configuration의 issuer와 불일치합니다.",
        "D2":  "ID Token aud가 요청한 client_id를 포함하지 않습니다.",
        "D3":  "ID Token header.alg가 discovery에서 지원하지 않는 값입니다.",
        "D4":  "ID Token header.kid가 JWKS keys에서 발견되지 않았습니다.",
        "A1":  "코드 플로우는 PKCE(S256)를 사용하는 것이 안전합니다.",
        "A2":  "Implicit/Hybrid에서는 response_mode=form_post를 권장합니다.",
    }
    FIX = {
        "N1C": "인가요청에 강한 난수 'nonce' 포함 + 콜백에서 ID Token의 nonce와 동일 비교(1회용 저장/폐기).",
        "N1":  "Implicit/Hybrid 요청에 'nonce'를 반드시 포함하고 동일성 검증을 구현하세요.",
        "N2":  "scope에 'openid'를 포함했다면 토큰 교환 시 ID Token을 수신하고 nonce 검증을 수행하세요.",
        "N3":  "IdP/클라이언트가 ID Token에 nonce를 포함하도록 설정, 미포함 시 오류로 처리.",
        "N4":  "요청 시 저장한 nonce를 서버 세션과 바인딩하고 ID Token의 nonce와 반드시 동일 비교(불일치 시 거부).",
        "N5":  "길이 16+ 및 총 엔트로피 128비트 이상의 urlsafe 랜덤 사용, 고정 패턴·숫자-only·짧은 hex 금지.",
        "N6":  "nonce는 1회용으로 관리하고 재관측 시 세션을 차단.",
        "N7":  "Refresh 응답의 ID Token에 nonce가 오면 원본과 동일해야 하며, 가능하면 제외하도록 설정.",
        "N8":  "Refresh 응답에서 nonce를 제외하도록 IdP/클라이언트 설정을 조정(권고).",
        "D1":  "issuer 값을 discovery의 issuer로 고정하고 불일치 시 오류 처리(믹스업 방지).",
        "D2":  "클라이언트 설정의 client_id를 aud에 포함하도록 IdP/클라이언트 구성을 점검.",
        "D3":  "IdP가 공표한 서명 알고리즘만 허용하도록 검증 로직/설정을 조정.",
        "D4":  "JWKS 키집합을 최신으로 동기화하고 header.kid가 존재하는지 확인.",
        "A1":  "PKCE(S256) 사용: code_challenge/Method 설정 및 토큰 교환 시 code_verifier 제출.",
        "A2":  "response_mode=form_post로 전환해 프런트채널 노출을 줄이세요.",
    }

    fails = [x for x in j.get("issues", []) if x.get("level") == "FAIL"]
    advis = [x for x in j.get("issues", []) if x.get("level") == "ADVISORY"]

    if fails:
        out.append("Failures:")
        for f in fails:
            out.append(f" - [{f['code']}] {f['title']}")
            out.append(f"    - 이유: {WHY.get(f['code'], f.get('detail',''))}")
            fix = FIX.get(f["code"])
            if fix:
                out.append(f"    - 조치: {fix}")
            ev = f.get("evidence")
            if ev:
                safe = {}
                for k, v in ev.items():
                    val = str(v)
                    safe[k] = val[:64] + ('…' if len(val) > 64 else '')
                out.append(f"    - 증거: {json.dumps(safe, ensure_ascii=False)}")
        out.append("")
    if advis:
        out.append("Advisories:")
        for a in advis:
            out.append(f" - [{a['code']}] {a['title']}")
            why = WHY.get(a["code"])
            if why:
                out.append(f"    - 이유: {why}")
            fix = FIX.get(a["code"])
            if fix:
                out.append(f"    - 조치: {fix}")
        out.append("")

    return "\n".join(out)

# --- backward-compat shim for older adapters ---
def run_checks(flow_bundle, policy=None):
    return run(flow_bundle, policy=policy)

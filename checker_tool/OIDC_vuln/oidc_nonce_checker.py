
"""
oidc_nonce_checker.py — Code-flow centric
- Removed implicit/hybrid-specific checks:
  1) A.nonce_required_implicit_hybrid
  2) B.implicit_hybrid_idtoken_has_nonce
- Keeps: flow identify, strict nonce for code-flow, entropy/replay, ID Token presence/nonce, equality,
         issuer/audience/alg/kid consistency, PKCE advisory, 128-bit total entropy.
- Hides Info rows in pretty_report.
"""
from datetime import datetime, timezone
from typing import Dict, Any, List
import re, json

# ---- Policy thresholds ----
MIN_NONCE_LEN = 16                      # 최소 길이
MIN_ENTROPY_PER_CHAR = 3.0              # 문자당 Shannon 엔트로피 (bits/char)
MIN_TOTAL_BITS = 128                    # 총 엔트로피(추정) 최소 128비트

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

    # issuer_expected: compute here
    issuer_expected = (
        flow_bundle.get("issuer_expected")
        or (discovery.get("issuer") if isinstance(discovery, dict) else None)
        or ((flow_bundle.get("authorization_response") or {}).get("params") or {}).get("iss")
    )

    req_nonce = req.get("nonce")
    client_id = req.get("client_id") or req.get("client") or req.get("clientId")
    id_token_present = bool(token.get("id_token"))
    id_nonce = id_payload.get("nonce")
    refresh_nonce = refresh_payload.get("nonce")

    issues: List[Dict[str, Any]] = []
    checklist = {"A": {}, "B": {}, "C": {}}
    stats = {"now_utc": now, "flow": flow, "strict_code_nonce": strict_code_nonce}

    # === A. Authorization Request (code-flow centric) ===
    checklist["A"]["flow_identify"] = _pass()
    checklist["A"]["flow_identify"]["observed"] = str({"scope": req.get("scope"), "response_type": response_type})

    # Code-flow 정책: nonce 사용
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

    # nonce 엔트로피/총비트/재사용
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

    # === B. ID Token ===
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
        checklist["B"]["id_token_must_include_nonce_if_requested"] = _pass()

    # === C. Client Validation ===
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

    # ---- Discovery-aware checks ----
    # iss consistency
    if id_payload.get("iss") is None:
        checklist["C"]["iss_matches_discovery"] = _fail("ID Token에 iss 없음")
        issues.append({
            "code": "D1", "level": "FAIL",
            "title": "iss 누락",
            "detail": "ID Token에 iss 클레임이 없습니다.",
        })
    else:
        if issuer_expected:
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
    supported_algs = set((discovery.get("id_token_signing_alg_values_supported") or [])) if isinstance(discovery, dict) else set()
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

    # Advisories
    if not req.get("code_challenge_method") and flow == "code":
        issues.append({"code":"A1","level":"ADVISORY","title":"PKCE 미사용 추정",
                       "detail":"code_challenge_method가 없어 PKCE 미사용으로 추정됩니다."})

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

# ---- Pretty report ----
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

    fails = [x for x in j.get("issues", []) if x.get("level") == "FAIL"]
    advis = [x for x in j.get("issues", []) if x.get("level") == "ADVISORY"]

    if fails:
        out.append("Failures:")
        for f in fails:
            out.append(f" - [{f['code']}] {f['title']}")
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
        out.append("")

    return "\n".join(out)

# --- backward-compat shim for older adapters ---
def run_checks(flow_bundle, policy=None):
    return run(flow_bundle, policy=policy)

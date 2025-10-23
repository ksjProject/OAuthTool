# -*- coding: utf-8 -*-
"""
analyzers.py
Combined analyzers (ClientSecret / State / Consent) + human-readable report.
UTF-8 안전, Base64 디코딩/마스킹 처리, sample packets included.

Usage:
  from analyzers import analyze_and_report
  analyze_and_report(packets, session_tokens)
"""
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, parse_qsl
import json, re, base64
from collections import Counter
import re
import json
from collections import defaultdict, Counter
import re

# --- Mock helpers (replace with your real project helpers) ---
def extract_request_body_text(pkt: Dict[str, Any]) -> str:
    body_b64 = pkt.get("body_b64")
    if body_b64:
        try:
            return base64.b64decode(body_b64).decode("utf-8", errors="replace")
        except Exception:
            return "<decode-error>"
    body = pkt.get("body", "")
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    return str(body)

def extract_response_body_text(pkt: Dict[str, Any]) -> str:
    resp = pkt.get("response_body","")
    if isinstance(resp, bytes):
        return resp.decode("utf-8", errors="replace")
    return str(resp)

def mask_secret(val: str, keep: int = 4) -> str:
    if not val: return ""
    val = str(val)
    return val[:keep] + "*"*(len(val)-keep)

def looks_random_state(state: str):
    """
    state 문자열의 무작위성을 간단히 추정합니다.
    - base64url 문자군 여부 확인
    - 샤논 엔트로피(문자 분포 기반)로 총 비트수 추정
    - UUID v4면 122비트로 통과 처리
    OK 기준:
      - UUID v4  또는
      - (base64url 문자군) and (길이 ≥ 22) and (추정 엔트로피 비트 ≥ 128)
    """
    import math, re
    from collections import Counter

    if not state:
        return {"ok": False, "reason": "empty", "length": 0}

    # UUID v4 패턴 (122 bits of randomness)
    uuid_v4 = bool(re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        state, re.I
    ))
    if uuid_v4:
        return {
            "ok": True, "uuid_v4": True, "bits": 122,
            "entropy_per_char": None, "length": len(state),
            "charset_ok": True, "reason": "uuid_v4"
        }

    # base64url 허용 문자군 확인
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    charset_ok = all((c in charset) for c in state)

    n = len(state)
    counts = Counter(state)

    # 샤논 엔트로피 (per-char, bits)
    H = 0.0
    for k in counts.values():
        p = k / n
        H -= p * math.log2(p)

    # 총 엔트로피 비트수
    bits = H * n  # 이론적 최대는 n * log2(64) = 6n

    ok = (charset_ok and n >= 22 and bits >= 128)

    return {
        "ok": ok,
        "length": n,
        "entropy_per_char": H,
        "bits": bits,
        "charset_ok": charset_ok,
        "uuid_v4": False,
        "reason": (
            "ok"
            if ok else
            ("bad-charset" if not charset_ok else
             ("too-short" if n < 22 else "low-entropy"))
        )
    }

# --- Finding factory ---
def mkfind(fid: str, title: str, sev: str, desc: str, evidence: str, rec: str) -> Dict[str, Any]:
    return {"id": fid, "title": title, "severity": sev, "description": desc, "evidence": evidence, "recommendation": rec}

# --- Utility: parse query & fragment ---
def parse_query_fragment(url: str) -> Dict[str, Any]:
    try:
        p = urlparse(url)
        q = dict(parse_qsl(p.query, keep_blank_values=True))
        frag = dict(parse_qsl(p.fragment, keep_blank_values=True))
        return {"url": url, "path": p.path, "scheme": p.scheme, "query": q, "fragment": frag}
    except:
        return {"url": url, "path": "", "scheme": "", "query": {}, "fragment": {}}

# ==================== Analyzer Classes ====================

class ClientSecretAnalyzer:
    SENSITIVE_KEYS = {"client_secret", "access_token", "id_token", "refresh_token", "code"}

    def analyze(self, packets: List[Dict[str, Any]], session_tokens: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        # 1) URL query secrets
        for pkt in packets:
            if pkt.get("type") != "request": continue
            req = pkt.get("request", {})
            url = req.get("url","")
            pf = parse_query_fragment(url)
            for k in self.SENSITIVE_KEYS & set(pf["query"].keys()):
                v = pf["query"][k]
                evidence = f"Request URL: {url}\nQuery param {k}={mask_secret(v)}"
                findings.append(mkfind("5.1-QUERY-LEAK",
                                        "민감 파라미터가 URL 쿼리에 포함됨",
                                        "HIGH",
                                        "민감 파라미터가 URL(프론트채널)에 남아 브라우저 히스토리/리퍼러로 유출될 수 있습니다.",
                                        evidence,
                                        "민감 값(client_secret, token 등)은 절대 URL에 포함하지 마십시오. 서버-사이드 POST로 처리하세요."))

        # 2) Referer header leaks
        for pkt in packets:
            if pkt.get("type") != "request": continue
            req = pkt.get("request",{})
            headers = req.get("headers",{})
            ref = headers.get("Referer") or headers.get("referer")
            if not ref: continue
            pf = parse_query_fragment(ref)
            for k in self.SENSITIVE_KEYS & set(pf["query"].keys()):
                v = pf["query"][k]
                evidence = f"Request URL: {req.get('url')}\nReferer: {ref}\nLeaked: {k}={mask_secret(v)}"
                findings.append(mkfind("5.1-REFERER-LEAK",
                                        "Referer 헤더로 민감 파라미터 유출",
                                        "HIGH",
                                        "리퍼러에 민감값이 포함되어 제3자에 유출될 수 있습니다.",
                                        evidence,
                                        "Referrer-Policy 설정 및 URL에 민감 파라미터 보관 금지."))

        # 3) Token endpoint POST / Authorization Basic
        token_paths = ["/protocol/openid-connect/token", "/oauth/token", "/token"]
        def looks_token_url(u): return any(p in urlparse(u).path for p in token_paths)
        for pkt in packets:
            if pkt.get("type") != "request": continue
            req = pkt.get("request",{})
            url = req.get("url","")
            if not looks_token_url(url): continue

            body_txt = extract_request_body_text(pkt)
            if "client_secret=" in body_txt or '"client_secret"' in body_txt:
                sev = "CRITICAL" if urlparse(url).scheme != "https" else "HIGH"
                evidence = f"Token endpoint POST to {url}\nbody snippet: {body_txt[:300]}"
                findings.append(mkfind("5.1-TOKEN-BODY-SECRET",
                                        "Token 요청에서 client_secret 전송 감지",
                                        sev,
                                        "client_secret가 토큰 교환 요청의 본문에 포함되어 전송되었습니다.",
                                        evidence,
                                        "토큰 교환은 서버에서 수행되어야 하며, 항상 HTTPS를 사용하세요. client_secret은 안전한 저장소에 보관하세요."))

            # Basic Auth
            auth = req.get("headers",{}).get("Authorization","") or req.get("headers",{}).get("authorization","")
            if auth.lower().startswith("basic "):
                try:
                    enc = auth.split(None,1)[1]
                    decoded = base64.b64decode(enc + "=" * (-len(enc)%4)).decode("utf-8","replace")
                except:
                    decoded = "<decode-failed>"
                sev = "CRITICAL" if urlparse(url).scheme != "https" else "INFO"
                evidence = f"Token endpoint {url}\nAuthorization Basic (decoded mask): {mask_secret(decoded,8)}"
                findings.append(mkfind("5.1-TOKEN-AUTH-BASIC",
                                        "Token 요청에서 Authorization: Basic 사용 감지",
                                        sev,
                                        "Basic 인증(보통 client_id:client_secret)이 토큰 엔드포인트에 사용되었습니다.",
                                        evidence,
                                        "HTTPS 사용 보장 및 로그에 비밀이 남지 않도록 하십시오."))

        # 4) session_tokens
        for it in session_tokens.get("oauth_tokens",[]):
            if (it.get("key") or "").lower()=="client_secret":
                findings.append(mkfind("5.1-SESSION-TOKEN-SECRET",
                                        "session_token.json에 client_secret 기록 감지",
                                        "HIGH",
                                        "요약 파일(session_token.json)에 client_secret 항목이 기록되어 있습니다.",
                                        f"Location: {it.get('where')} url={it.get('url')} value={mask_secret(it.get('value'))}",
                                        "진단용 로그에도 민감값을 남기지 마십시오. 마스킹/암호화/접근통제 필요"))
        return findings

# ==================== State Analyzer ====================
class StateAnalyzer:
    MIN_STATE_LEN = 22  # ≈ 128비트 base64url 기준 (16바이트)

    def analyze(self, packets, session_tokens):
        findings = []
        auth_reqs = []
        callback_reqs = []

        def is_authz(u):
            return ("/authorize" in u or
                    "response_type=" in u or
                    "/protocol/openid-connect/auth" in u)

        for pkt in packets:
            if pkt.get("type") != "request":
                continue
            url = pkt.get("request", {}).get("url", "")
            if is_authz(url):
                q = parse_qs(urlparse(url).query, keep_blank_values=True)
                state = (q.get("state") or [""])[0]
                auth_reqs.append({"url": url, "state": state})
            q = parse_qs(urlparse(url).query, keep_blank_values=True)
            if "code" in q:
                state = (q.get("state") or [""])[0]
                callback_reqs.append({"url": url, "state": state})

        states = []
        for a in auth_reqs:
            st = a["state"]
            if not st:
                findings.append(mkfind(
                    "5.3-STATE-MISSING", "Authorization 요청에 state 누락", "HIGH",
                    "Authorization 요청에 state 파라미터가 없습니다. CSRF 방어가 약화됩니다.",
                    f"Request: {a['url']}",
                    "state를 반드시 포함하고 서버에서 저장/검증하십시오."
                ))
                continue

            # 기존 무작위성 검사
            metrics = looks_random_state(st)
            states.append(st)
            if not metrics.get("ok", False):
                findings.append(mkfind(
                    "5.3-STATE-LOW-ENTROPY", "state 무작위성 부족", "MEDIUM",
                    "state가 충분히 무작위적이지 않습니다 (길이/엔트로피/문자군).",
                    f"state sample (masked): {st[:8]}... metrics={metrics}",
                    "128비트 이상 무작위(base64url) 또는 강력한 UUID 사용을 권장합니다."
                ))

        cnt = Counter(states)
        for st, c in cnt.items():
            if c >= 2:
                sev = "HIGH" if c >= 3 else "MEDIUM"
                findings.append(mkfind(
                    "5.3-STATE-REUSE", "state 재사용 감지", sev,
                    "동일한 state 값이 여러 번 사용되었습니다. state는 1회성으로 생성되어야 합니다.",
                    f"state (masked): {st[:8]}... used {c} times",
                    "각 authorization 요청마다 고유 state를 생성하고 검증 후 폐기하세요."
                ))

        known = set(states)
        for cb in callback_reqs:
            st = cb["state"]
            if not st:
                findings.append(mkfind(
                    "5.3-CB-STATE-MISSING", "콜백에 state 누락", "HIGH",
                    "콜백 요청에 state가 없습니다. 요청-응답 매칭이 불가합니다.",
                    f"Callback URL: {cb['url']}",
                    "콜백에 state 포함 및 서버 세션과의 대조를 반드시 수행하세요."
                ))
            elif st not in known:
                findings.append(mkfind(
                    "5.3-CB-STATE-MISMATCH", "콜백 state 불일치(알 수 없음)", "HIGH",
                    "콜백에서 받은 state가 이전에 생성된 state와 매칭되지 않습니다.",
                    f"Callback URL: {cb['url']} state={st[:8]}...",
                    "서버 세션/스토리지와 비교하여 불일치 시 즉시 거부하세요."
                ))

        return findings

# ==================== Consent Analyzer ====================
    
class ConsentAnalyzer:
    # 기본 RISKY / PRIVACY (기존과 연동)
    RISKY = {
        "offline_access", "roles", "admin",
        "manage-account", "manage-users", "manage-clients",
        "address", "phone", "phone_number", "profile", "email"
    }
    PRIVACY = {"email", "phone_number", "address", "name", "family_name", "given_name"}

    # IDP-agnostic 패턴 (대소문자 무시)
    ADMIN_PATTERNS = [re.compile(p, re.I) for p in (
        r"^admin$",
        r"administrator",
        r"super[_-]?admin",
        r"superuser",
        r"sysadmin",
        r"platform[_-]?admin",
        r"^owner$",
        r"^root$",
    )]

    MANAGE_PREFIXES = ("manage-", "manage_", "manage:", "scim.manage", "manage")
    MANAGE_PATTERNS = [re.compile(p, re.I) for p in (
        r"^manage[-_:].*",
        r"^manage$",
        r".*:manage[:_\-]?.*",
    )]

    ROLES_PATTERNS = [re.compile(p, re.I) for p in (
        r"^roles?$",
        r"^groups?$",
        r"\bpermissions?\b",
        r"^app[_-]?roles?$",
        r"^scope:roles$",
        r"^group[_-]?membership$",
    )]

    OFFLINE_PATTERNS = [re.compile(p, re.I) for p in (
        r"offline_access",
        r"\boffline\b",
        r"refresh[_-]?token",
    )]

    PRIVACY_KEYWORDS = {
        "email", "email_verified", "phone", "phone_number", "address",
        "profile", "name", "given_name", "family_name"
    }

    def __init__(self, time_window_hours=24, behavioral_checks=False, custom_patterns=None):
        """
        time_window_hours: behavioral(운영) 감지용 윈도우(패킷에 timestamp 필요)
        behavioral_checks: 기본 False (운영 모드에서 True)
        custom_patterns: dict으로 ADMIN_PATTERNS/ROLES_PATTERNS 등 추가 가능
        """
        self.time_window_hours = time_window_hours
        self.behavioral_checks = behavioral_checks
        if custom_patterns:
            for key, pats in custom_patterns.items():
                if hasattr(self, key) and isinstance(getattr(self, key), list):
                    getattr(self, key).extend([re.compile(p, re.I) for p in pats])

    # ---------- 헬퍼 ----------
    def _match_any(self, token, patterns):
        if not token:
            return False
        for p in patterns:
            if p.search(token):
                return True
        return False

    def _is_manage_token(self, token):
        if not token:
            return False
        tl = token.lower()
        for pref in self.MANAGE_PREFIXES:
            if tl.startswith(pref):
                return True
        return self._match_any(token, self.MANAGE_PATTERNS)

    def _classify_scope_token(self, token):
        """토큰 하나를 카테고리로 분류: ADMIN / MANAGE / ROLES / OFFLINE / PRIVACY / None"""
        if not token:
            return None
        if self._match_any(token, self.ADMIN_PATTERNS):
            return "ADMIN"
        if self._is_manage_token(token):
            return "MANAGE"
        if self._match_any(token, self.ROLES_PATTERNS):
            return "ROLES"
        if self._match_any(token, self.OFFLINE_PATTERNS):
            return "OFFLINE"
        if token.lower() in self.PRIVACY_KEYWORDS:
            return "PRIVACY"
        return None

    # ---------- 분석기 ----------
    def analyze(self, packets, session_tokens):
        findings = []
        client_scope_counter = Counter()
        client_times = defaultdict(list)

        # 1) authorize 요청: scope 분석 (IDP-agnostic)
        for pkt in packets:
            if pkt.get("type") != "request":
                continue
            url = pkt.get("request", {}).get("url", "")
            p = parse_query_fragment(url)
            q = p.get("query", {})
            if "scope" not in q:
                continue

            scopes = [s for s in q["scope"].split() if s]
            risky_tokens = []
            risky_categories = set()

            for s in scopes:
                cat = self._classify_scope_token(s)
                if cat:
                    risky_tokens.append(s)
                    risky_categories.add(cat)

            if risky_tokens:
                if risky_categories & {"ADMIN", "MANAGE", "ROLES", "OFFLINE"}:
                    sev = "HIGH"
                else:
                    sev = "MEDIUM"

                findings.append(mkfind(
                    "5.5-RISKY-SCOPE",
                    "과도한/민감한 scope 요청 (IDP-agnostic)",
                    sev,
                    f"요청된 scope: {', '.join(sorted(scopes))}",
                    f"Request URL: {url}\nRisk tokens: {', '.join(sorted(set(risky_tokens)))}\nRisk categories: {', '.join(sorted(risky_categories))}",
                    "최소 권한 원칙을 적용하고, 민감 범위는 별도 동의 절차로 분리하세요."
                ))

                # 클라이언트별 집계(옵션)
                cid = q.get("client_id")
                if cid:
                    client_scope_counter[cid] += 1
                    if self.behavioral_checks:
                        ts = pkt.get("timestamp", 0)
                        client_times[cid].append(ts)

        # 2) token/userinfo 응답: 개인정보(claims) 과다 제공 검사
        for pkt in packets:
            resp = extract_response_body_text(pkt)
            if not resp:
                continue
            try:
                data = json.loads(resp)
            except Exception:
                continue
            if not isinstance(data, dict):
                continue

            claims = set(data.keys())
            privacy_claims = claims & self.PRIVACY
            if privacy_claims:
                scope = data.get("scope", "")
                scope_set = set(scope.split()) if isinstance(scope, str) and scope else set()
                over = {c for c in privacy_claims if c not in scope_set}
                if over:
                    findings.append(mkfind(
                        "5.5-OVER-SHARE",
                        "요청 scope 대비 과도한 개인정보 제공",
                        "MEDIUM",
                        f"응답에 민감 클레임({', '.join(sorted(privacy_claims))})이 포함되어 있고, scope와 불일치가 있습니다.",
                        f"Response URL: {pkt.get('request', {}).get('url')}\nClaims: {', '.join(sorted(privacy_claims))}\nResp scope: {scope}",
                        "권한-클레임 매핑을 검토하고, scope에 없는 개인정보는 응답하지 않도록 서버 설정을 변경하세요."
                    ))

            # 역할/그룹/권한 클레임 노출 검사
            for role_alias in ("roles", "groups", "permissions", "app_roles"):
                if role_alias in data:
                    findings.append(mkfind(
                        "5.5-ROLE-EXPOSE",
                        "응답에 역할/권한 정보 포함",
                        "HIGH",
                        f"응답에 '{role_alias}' 클레임이 존재합니다. 클라이언트가 역할 정보를 받을 필요가 있는지 검토하세요.",
                        f"Response URL: {pkt.get('request', {}).get('url')}\nClaim: {role_alias}",
                        "역할/권한 정보는 최소 권한 원칙에 따라 제한적으로 제공하세요."
                    ))

        # 3) session에 포함된 JWT 클레임 불일치
        for c in session_tokens.get("jwt_claims", []):
            findings.append(mkfind(
                "5.5-JWT-CLAIMS-INCONSISTENT",
                "JWT에 포함된 개인정보가 scope와 불일치",
                "MEDIUM",
                "JWT에 개인정보 클레임이 포함되어 있으나 token의 scope와 정합하지 않습니다.",
                f"JWT claims: {c}\nToken scope: {session_tokens.get('oauth_scope')}",
                "JWT에 민감 클레임을 포함시키는 경우, 해당 권한(scope)이 명확히 부여되었는지 서버에서 검증하세요."
            ))
        return findings

# ==================== Report Generator ====================
EXPECTED_CHECKS={
    "5.1":[("5.1-QUERY-LEAK","Client Secret","민감 파라미터가 URL 쿼리에 포함됨"),
           ("5.1-REFERER-LEAK","Referer Leak","Referer 헤더로 민감 파라미터 유출"),
           ("5.1-TOKEN-BODY-SECRET","Token Body Secret","Token 요청에서 client_secret 전송 감지"),
           ("5.1-TOKEN-AUTH-BASIC","Token Auth Basic","Token 요청에서 Authorization: Basic 사용 감지"),
           ("5.1-SESSION-TOKEN-SECRET","Session token secret","session_token.json에 client_secret 기록 감지")],
    "5.3":[("5.3-STATE-MISSING","State Missing","Authorization 요청에 state 누락"),
           ("5.3-STATE-LOW-ENTROPY","State Low Entropy","state 무작위성 부족"),
           ("5.3-STATE-REUSE","State Reuse","state 재사용 감지"),
           ("5.3-CB-STATE-MISSING","Callback State Missing","콜백에 state 누락"),
           ("5.3-CB-STATE-MISMATCH","Callback State Mismatch","콜백 state 불일치(알 수 없음)")],
    "5.5":[("5.5-RISKY-SCOPE","Risky Scope","과도한/민감한 scope 요청"),
           ("5.5-OVER-SHARE","Over-share Claims","요청 scope 대비 과도한 개인정보 제공"),
           ("5.5-JWT-CLAIMS-INCONSISTENT","JWT Claims Inconsistent","JWT에 포함된 개인정보가 scope와 불일치")],
}

def analyze_and_report(packets: List[Dict[str,Any]], session_tokens:Dict[str,Any]) -> Dict[str,Any]:
    analyzers=[ClientSecretAnalyzer(), StateAnalyzer(), ConsentAnalyzer()]
    all_findings=[]
    for a in analyzers:
        try:
            all_findings.extend(a.analyze(packets, session_tokens))
        except Exception as e:
            all_findings.append(mkfind("999.ERR", "Analyzer error", "INFO", "Analyzer raised exception", str(e), "Fix analyzer code."))

    # 그룹 추출 함수
    def group_from_id(fid: str) -> str:
        if not fid:
            return "5.1"
        m = re.match(r"^(\d+\.\d+)[-_]", fid)
        if m:
            return m.group(1)
        if "-" in fid:
            return fid.split("-",1)[0]
        if "." in fid:
            return fid.split(".",1)[0]
        return "5.1"

    # 기본 그룹 초기화
    groups = {gid: {"findings": [], "overall": "PASS"} for gid in EXPECTED_CHECKS}

    # Finding들을 그룹화
    for f in all_findings:
        fid = f.get("id", "")
        gid = group_from_id(fid)
        if gid not in groups:
            groups[gid] = {"findings": [], "overall": "PASS"}
        groups[gid]["findings"].append(f)

    # 그룹 상태 계산
    for gid, info in groups.items():
        info["overall"] = "VULNERABLE" if info["findings"] else "PASS"

    # 최종 보고서 구성
    report = {
        "groups": {gid: {"overall": info["overall"], "findings": info["findings"]} for gid, info in groups.items()},
        "overall": "VULNERABLE" if any(info["overall"] == "VULNERABLE" for info in groups.values()) else "PASS"
    }

    # JSON 저장
    with open("oauth_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    # 사람 읽기용 출력
    print("==================== OAuth Security Analysis Report ====================")
    for gid, checks in EXPECTED_CHECKS.items():
        print(f"[{gid}]")
        for check_id, short, desc in checks:
            match = next((x for x in all_findings if x.get("id") == check_id), None)
            if match:
                print(f"\n└─ {match['title']}\n│ Severity : {match['severity']}\n│ Description: {match['description']}\n│ Evidence:\n{match['evidence']}\n│ Recommendation: {match['recommendation']}\n")
            else:
                print(f"✅ {short} PASS")
        grp_overall = report.get("groups", {}).get(gid, {}).get("overall", "UNKNOWN")
        print(f"▶ Group overall: {grp_overall}\n")

    print(f"==================== Overall result: {report.get('overall', 'UNKNOWN')} ====================")
    print("[+] JSON report saved: oauth_report.json")
    return report

# ==================== Example harness ====================
if __name__=="__main__":
    example_packets = [
        {
            "type": "request",
            "request": {
                "url": "https://example.com/callback?client_secret=abcd1234",
                "headers": {"User-Agent": "TestAgent"}
            },
            "body_b64": base64.b64encode("grant_type=authorization_code&code=xyz".encode()).decode()
        }
    ]
    example_session_tokens = {"oauth_tokens": [], "jwt_claims": []}

    analyze_and_report(example_packets, example_session_tokens)
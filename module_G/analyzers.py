# -*- coding: utf-8 -*-
"""
analyzers.py
Combined analyzers (ClientSecret / State / Consent / FrontChannelToken) + human-readable report.
- Robust base64 decoding
- Header normalization
- URL query/fragment parsing
- PASS/FAIL/NA status per check, per group, and overall
- Human-readable console output + oauth_report.json

Usage:
  from analyzers import analyze_and_report
  analyze_and_report(packets, session_tokens)
"""

from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse, parse_qs, parse_qsl
from collections import defaultdict, Counter
import base64, json, re

# ==================== Robust Parsing Helpers ====================

def safe_b64decode(b64: str) -> bytes:
    if not b64:
        return b""
    try:
        padded = b64 + "=" * (-len(b64) % 4)
        return base64.b64decode(padded)
    except Exception:
        try:
            padded = b64 + "=" * (-len(b64) % 4)
            return base64.urlsafe_b64decode(padded)
        except Exception:
            return b""

def normalize_headers(hdrs: Dict[str, Any]) -> Dict[str, str]:
    return {(k or "").lower(): v for k, v in (hdrs or {}).items()}

def parse_query_fragment(url: str) -> Dict[str, Any]:
    try:
        p = urlparse(url)
        q = dict(parse_qsl(p.query, keep_blank_values=True))
        frag = dict(parse_qsl(p.fragment, keep_blank_values=True))
        return {"url": url, "path": p.path, "scheme": p.scheme, "query": q, "fragment": frag}
    except Exception:
        return {"url": url, "path": "", "scheme": "", "query": {}, "fragment": {}}

def mask_secret(val: str, keep: int = 4) -> str:
    if val is None:
        return ""
    s = str(val)
    if len(s) <= keep * 2:
        return s[:keep] + "..." + s[-keep:]
    return s[:keep] + "..." + s[-keep:]

def extract_request_body_text(pkt: Dict[str, Any]) -> str:
    req = pkt.get("request") or {}
    b64 = req.get("body_b64") or ""
    if not b64:
        return ""
    b = safe_b64decode(b64)
    if not b:
        return ""
    try:
        return b.decode("utf-8", "ignore")
    except Exception:
        return b.decode("latin-1", "ignore")

def extract_response_body_text(pkt: Dict[str, Any]) -> str:
    resp = pkt.get("response") or {}
    b64 = resp.get("body_b64") or ""
    if not b64:
        return ""
    b = safe_b64decode(b64)
    if not b:
        return ""
    try:
        return b.decode("utf-8", "ignore")
    except Exception:
        return b.decode("latin-1", "ignore")

# ==================== Entropy Helper ====================

def looks_random_state(state: str):
    import math, re as _re
    from collections import Counter as _C

    if not state:
        return {"ok": False, "reason": "empty", "length": 0}

    if _re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        state, _re.I
    ):
        return {
            "ok": True, "uuid_v4": True, "bits": 122,
            "entropy_per_char": None, "length": len(state),
            "charset_ok": True, "reason": "uuid_v4"
        }

    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    charset_ok = all((c in charset) for c in state)

    n = len(state)
    cnt = _C(state)

    H = 0.0
    for k in cnt.values():
        p = k / n
        H -= p * math.log2(p)

    bits = H * n
    ok = (charset_ok and n >= 22 and bits >= 128)

    return {
        "ok": ok,
        "length": n,
        "entropy_per_char": H,
        "bits": bits,
        "charset_ok": charset_ok,
        "uuid_v4": False,
        "reason": ("ok" if ok else ("bad-charset" if not charset_ok else ("too-short" if n < 22 else "low-entropy")))
    }

# ==================== Finding factory ====================

def mkfind(fid: str, title: str, sev: str, desc: str, evidence: str, rec: str) -> Dict[str, Any]:
    return {"id": fid, "title": title, "severity": sev, "description": desc, "evidence": evidence, "recommendation": rec}

# ==================== Analyzer Classes ====================

class FrontChannelTokenLeakAnalyzer:
    """
    프론트채널(URL query/fragment, Referer)로 토큰(access_token, id_token, refresh_token) 노출 진단.
    - 벡터(URL/Referer) × 토큰별 6개 체크로 분리
    - title: "Query Token Leak_access_token" / "Referer Token Leak_access_token" 형식
    - id   : "5.0-QUERY-TOKEN:access_token" / "5.0-REFERER-TOKEN:access_token"
    """

    SENSITIVE_TOKENS = ("access_token", "id_token", "refresh_token")

    TITLE_MAP = {
        ("url", "access_token"):   "Query Token Leak_access_token",
        ("url", "id_token"):       "Query Token Leak_id_token",
        ("url", "refresh_token"):  "Query Token Leak_refresh_token",
        ("referer", "access_token"):   "Referer Token Leak_access_token",
        ("referer", "id_token"):       "Referer Token Leak_id_token",
        ("referer", "refresh_token"):  "Referer Token Leak_refresh_token",
    }

    def _collect_by_token(self, pf: Dict[str, Any]) -> Dict[str, List[Tuple[str, str]]]:
        out = {t: [] for t in self.SENSITIVE_TOKENS}
        q = pf.get("query") or {}
        f = pf.get("fragment") or {}
        for t in self.SENSITIVE_TOKENS:
            if t in q: out[t].append(("query", q[t]))
            if t in f: out[t].append(("fragment", f[t]))
        return {k: v for k, v in out.items() if v}

    def analyze(self, packets: List[Dict[str, Any]], session_tokens: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        # URL(주소창)
        for pkt in packets:
            if pkt.get("type") != "request":
                continue
            req = (pkt.get("request") or {})
            url = (req.get("url") or "")
            pf = parse_query_fragment(url)
            leaks_by_token = self._collect_by_token(pf)

            for token_name, evids in sorted(leaks_by_token.items()):
                title = self.TITLE_MAP[("url", token_name)]
                lines = [f"Request URL: {url}"]
                for src, val in evids:
                    lines.append(f"{src.capitalize()} param {token_name}={mask_secret(val)}")
                findings.append(mkfind(
                    f"5.0-QUERY-TOKEN:{token_name}",
                    title,
                    "HIGH",
                    (f"{token_name}이(가) 브라우저 주소창/히스토리/로그 등에 남아 제3자에게 노출될 수 있습니다. "
                     "토큰은 프론트채널(URL)에 절대 포함하지 마세요."),
                    "\n".join(lines),
                    ("권장: Authorization Code + PKCE, 가능 시 response_mode=form_post, "
                     "토큰은 백엔드로 안전 전달(HttpOnly/SameSite 쿠키 또는 BFF 패턴) 및 프론트 비보관.")
                ))

        # Referer
        for pkt in packets:
            if pkt.get("type") != "request":
                continue
            req = (pkt.get("request") or {})
            headers = normalize_headers(req.get("headers", {}))
            ref = headers.get("referer")
            if not ref:
                continue
            pf = parse_query_fragment(ref)
            leaks_by_token = self._collect_by_token(pf)

            for token_name, evids in sorted(leaks_by_token.items()):
                title = self.TITLE_MAP[("referer", token_name)]
                lines = [f"Request URL: {req.get('url')}", f"Referer: {ref}"]
                for src, val in evids:
                    lines.append(f"Leaked via {src}: {token_name}={mask_secret(val)}")
                findings.append(mkfind(
                    f"5.0-REFERER-TOKEN:{token_name}",
                    title,
                    "HIGH",
                    (f"페이지 간 이동 시 Referer에 {token_name}이(가) 포함되어 타 도메인(광고/분석/이미지 CDN 등)으로 유출될 수 있습니다."),
                    "\n".join(lines),
                    ("권장: URL에 토큰을 넣지 않기 + 'Referrer-Policy: no-referrer' 또는 "
                     "'strict-origin-when-cross-origin' 설정.")
                ))

        return findings


class ClientSecretAnalyzer:
    TARGET_KEY = "client_secret"

    def analyze(self, packets: List[Dict[str, Any]], session_tokens: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        # 1) URL query에 client_secret
        for pkt in packets:
            if pkt.get("type") != "request":
                continue
            req = pkt.get("request", {})
            url = req.get("url", "")
            pf = parse_query_fragment(url)
            if self.TARGET_KEY in pf["query"]:
                v = pf["query"][self.TARGET_KEY]
                evidence = f"Request URL: {url}\nQuery param {self.TARGET_KEY}={mask_secret(v)}"
                findings.append(mkfind(
                    "5.1-QUERY-CLIENT-SECRET",
                    "Client Secret Query",
                    "CRITICAL",
                    "client_secret은 서버-사이드 비밀이며 URL(프론트채널)에 남겨서는 안 됩니다. 브라우저 히스토리/리퍼러로 유출될 수 있습니다.",
                    evidence,
                    "client_secret은 절대 URL에 포함하지 마십시오. 서버-사이드 POST 또는 안전한 백엔드 인증 방식으로 처리하세요."
                ))

        # 2) Referer로 client_secret 유출
        for pkt in packets:
            if pkt.get("type") != "request":
                continue
            req = pkt.get("request", {})
            headers = normalize_headers(req.get("headers", {}))
            ref = headers.get("referer")
            if not ref:
                continue
            pf = parse_query_fragment(ref)
            if self.TARGET_KEY in pf["query"]:
                v = pf["query"][self.TARGET_KEY]
                evidence = f"Request URL: {req.get('url')}\nReferer: {ref}\nLeaked: {self.TARGET_KEY}={mask_secret(v)}"
                findings.append(mkfind(
                    "5.1-REFERER-CLIENT-SECRET",
                    "Client Secret Referer",
                    "CRITICAL",
                    "Referer 헤더에 client_secret이 포함되어 제3자에게 유출될 수 있습니다.",
                    evidence,
                    "Referrer-Policy 설정(예: no-referrer) 적용 및 URL에 민감값 보관 금지."
                ))

        # 3) Token endpoint POST / Authorization Basic
        token_paths = ["/protocol/openid-connect/token", "/oauth/token", "/token"]
        def looks_token_url(u):
            try:
                path = urlparse(u).path or ""
            except Exception:
                path = ""
            return any(p in path for p in token_paths)

        for pkt in packets:
            if pkt.get("type") != "request":
                continue
            req = pkt.get("request", {})
            url = req.get("url", "")
            if not looks_token_url(url):
                continue

            body_txt = extract_request_body_text(pkt)
            if "client_secret=" in body_txt or '"client_secret"' in body_txt:
                sev = "CRITICAL" if (urlparse(url).scheme or "").lower() != "https" else "HIGH"
                evidence = f"Token endpoint POST to {url}\nbody snippet: {body_txt[:300]}"
                findings.append(mkfind(
                    "5.1-TOKEN-BODY-SECRET",
                    "Token Body Secret",
                    sev,
                    "client_secret가 토큰 교환 요청의 본문에 포함되어 전송되었습니다.",
                    evidence,
                    "토큰은 HTTP 헤더에 포함되어야 합니다."
                ))

            auth = normalize_headers(req.get("headers", {})).get("authorization", "")
            if isinstance(auth, str) and auth.lower().startswith("basic "):
                try:
                    enc = auth.split(None, 1)[1]
                    decoded = base64.b64decode(enc + "=" * (-len(enc) % 4)).decode("utf-8", "replace")
                except Exception:
                    decoded = "<decode-failed>"
                sev = "CRITICAL" if (urlparse(url).scheme or "").lower() != "https" else "INFO"
                evidence = f"Token endpoint {url}\nAuthorization Basic (decoded mask): {mask_secret(decoded,8)}"
                findings.append(mkfind(
                    "5.1-TOKEN-AUTH-BASIC",
                    "Token Auth Basic",
                    sev,
                    "Basic 인증(보통 client_id:client_secret)이 토큰 엔드포인트에 사용되었습니다.",
                    evidence,
                    "HTTPS 사용 보장 및 로그에 비밀이 남지 않도록 하십시오."
                ))

        # 4) session_tokens
        for it in session_tokens.get("oauth_tokens", []):
            if (it.get("key") or "").lower() == "client_secret":
                findings.append(mkfind(
                    "5.1-SESSION-TOKEN-SECRET",
                    "Session token secret",
                    "HIGH",
                    "요약 파일(session_token.json)에 client_secret 항목이 기록되어 있습니다.",
                    f"Location: {it.get('where')} url={it.get('url')} value={mask_secret(it.get('value'))}",
                    "진단용 로그에도 민감값을 남기지 마십시오. 마스킹/암호화/접근통제 필요"
                ))
        return findings


class StateAnalyzer:
    MIN_STATE_LEN = 22

    def analyze(self, packets, session_tokens):
        findings = []
        auth_reqs = []
        callback_reqs = []

        def is_authz(u):
            return ("/authorize" in u or "response_type=" in u or "/protocol/openid-connect/auth" in u)

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
                    "5.3-STATE-MISSING", "State Missing", "HIGH",
                    "Authorization 요청에 state 파라미터가 없습니다. CSRF 방어가 약화됩니다.",
                    f"Request: {a['url']}",
                    "state를 반드시 포함하고 서버에서 저장/검증하십시오."
                ))
                continue

            metrics = looks_random_state(st)
            states.append(st)
            if not metrics.get("ok", False):
                findings.append(mkfind(
                    "5.3-STATE-LOW-ENTROPY", "State Low Entropy", "MEDIUM",
                    "state가 충분히 무작위적이지 않습니다 (길이/엔트로피/문자군).",
                    f"state sample (masked): {st[:8]}... metrics={metrics}",
                    "128비트 이상 무작위(base64url) 또는 강력한 UUID 사용을 권장합니다."
                ))

        cnt = Counter(states)
        for st, c in cnt.items():
            if c >= 2:
                sev = "HIGH" if c >= 3 else "MEDIUM"
                findings.append(mkfind(
                    "5.3-STATE-REUSE", "State Reuse", sev,
                    "동일한 state 값이 여러 번 사용되었습니다. state는 1회성으로 생성되어야 합니다.",
                    f"state (masked): {st[:8]}... used {c} times",
                    "각 authorization 요청마다 고유 state를 생성하고 검증 후 폐기하세요."
                ))

        known = set(states)
        for cb in callback_reqs:
            st = cb["state"]
            if not st:
                findings.append(mkfind(
                    "5.3-CB-STATE-MISSING", "Callback State Missing", "HIGH",
                    "콜백 요청에 state가 없습니다. 요청-응답 매칭이 불가합니다.",
                    f"Callback URL: {cb['url']}",
                    "콜백에 state 포함 및 서버 세션과의 대조를 반드시 수행하세요."
                ))
            elif st not in known:
                findings.append(mkfind(
                    "5.3-CB-STATE-MISMATCH", "Callback State Mismatch", "HIGH",
                    "콜백에서 받은 state가 이전에 생성된 state와 매칭되지 않습니다.",
                    f"Callback URL: {cb['url']} state={st[:8]}...",
                    "서버 세션/스토리지와 비교하여 불일치 시 즉시 거부하세요."
                ))

        return findings


class ConsentAnalyzer:
    RISKY = {
        "offline_access", "roles", "admin",
        "manage-account", "manage-users", "manage-clients",
        "address", "phone", "phone_number", "profile", "email"
    }
    PRIVACY = {"email", "phone_number", "address", "name", "family_name", "given_name"}

    ADMIN_PATTERNS = [re.compile(p, re.I) for p in (
        r"^admin$", r"administrator", r"super[_-]?admin", r"superuser",
        r"sysadmin", r"platform[_-]?admin", r"^owner$", r"^root$",
    )]
    MANAGE_PREFIXES = ("manage-", "manage_", "manage:", "scim.manage", "manage")
    MANAGE_PATTERNS = [re.compile(p, re.I) for p in (r"^manage[-_:].*", r"^manage$", r".*:manage[:_\-]?.*")]
    ROLES_PATTERNS = [re.compile(p, re.I) for p in (r"^roles?$", r"^groups?$", r"\bpermissions?\b",
                                                     r"^app[_-]?roles?$", r"^scope:roles$", r"^group[_-]?membership$")]
    OFFLINE_PATTERNS = [re.compile(p, re.I) for p in (r"offline_access", r"\boffline\b", r"refresh[_-]?token")]
    PRIVACY_KEYWORDS = {"email", "email_verified", "phone", "phone_number", "address", "profile", "name", "given_name", "family_name"}

    def __init__(self, time_window_hours=24, behavioral_checks=False, custom_patterns=None):
        self.time_window_hours = time_window_hours
        self.behavioral_checks = behavioral_checks
        if custom_patterns:
            for key, pats in custom_patterns.items():
                if hasattr(self, key) and isinstance(getattr(self, key), list):
                    getattr(self, key).extend([re.compile(p, re.I) for p in pats])

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
        if not token:
            return None
        if self._match_any(token, self.ADMIN_PATTERNS): return "ADMIN"
        if self._is_manage_token(token): return "MANAGE"
        if self._match_any(token, self.ROLES_PATTERNS): return "ROLES"
        if self._match_any(token, self.OFFLINE_PATTERNS): return "OFFLINE"
        if token.lower() in self.PRIVACY_KEYWORDS: return "PRIVACY"
        return None

    def analyze(self, packets, session_tokens):
        findings = []
        client_scope_counter = Counter()
        client_times = defaultdict(list)

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
                sev = "HIGH" if (risky_categories & {"ADMIN","MANAGE","ROLES","OFFLINE"}) else "MEDIUM"
                findings.append(mkfind(
                    "5.5-RISKY-SCOPE",
                    "Risky Scope",
                    sev,
                    f"요청된 scope: {', '.join(sorted(scopes))}",
                    f"Request URL: {url}\nRisk tokens: {', '.join(sorted(set(risky_tokens)))}\nRisk categories: {', '.join(sorted(risky_categories))}",
                    "최소 권한 원칙을 적용하고, 민감 범위는 별도 동의 절차로 분리하세요."
                ))

                cid = q.get("client_id")
                if cid:
                    client_scope_counter[cid] += 1
                    if self.behavioral_checks:
                        ts = pkt.get("timestamp", 0)
                        client_times[cid].append(ts)

        return findings

# ==================== Expected Checks ====================

EXPECTED_CHECKS = {
    "5.0": [
        ("5.0-QUERY-TOKEN:access_token",   "Query Token Leak_access_token",   "URL 쿼리/프래그먼트 내 access_token 노출"),
        ("5.0-QUERY-TOKEN:id_token",       "Query Token Leak_id_token",       "URL 쿼리/프래그먼트 내 id_token 노출"),
        ("5.0-QUERY-TOKEN:refresh_token",  "Query Token Leak_refresh_token",  "URL 쿼리/프래그먼트 내 refresh_token 노출"),

        ("5.0-REFERER-TOKEN:access_token",  "Referer Token Leak_access_token",  "Referer로 access_token 유출"),
        ("5.0-REFERER-TOKEN:id_token",      "Referer Token Leak_id_token",      "Referer로 id_token 유출"),
        ("5.0-REFERER-TOKEN:refresh_token", "Referer Token Leak_refresh_token", "Referer로 refresh_token 유출"),
    ],
    "5.1": [
        ("5.1-QUERY-CLIENT-SECRET",   "Client Secret Query",    "client_secret이 URL 쿼리에 포함됨"),
        ("5.1-REFERER-CLIENT-SECRET", "Client Secret Referer",  "Referer로 client_secret 유출"),
        ("5.1-TOKEN-BODY-SECRET",     "Token Body Secret",      "Token 요청에서 client_secret 전송 감지"),
        ("5.1-TOKEN-AUTH-BASIC",      "Token Auth Basic",       "Token 요청에서 Authorization: Basic 사용 감지"),
        ("5.1-SESSION-TOKEN-SECRET",  "Session token secret",   "session_token.json에 client_secret 기록 감지"),
    ],
    "5.3": [
        ("5.3-STATE-MISSING",      "State Missing",           "Authorization 요청에 state 누락"),
        ("5.3-STATE-LOW-ENTROPY",  "State Low Entropy",       "state 무작위성 부족"),
        ("5.3-STATE-REUSE",        "State Reuse",             "state 재사용 감지"),
        ("5.3-CB-STATE-MISSING",   "Callback State Missing",  "콜백에 state 누락"),
        ("5.3-CB-STATE-MISMATCH",  "Callback State Mismatch", "콜백 state 불일치(알 수 없음)"),
    ],
    "5.5": [
        ("5.5-RISKY-SCOPE", "Risky Scope", "과도한/민감한 scope 요청"),
    ],
}

def analyze_and_report(packets: List[Dict[str,Any]], session_tokens:Dict[str,Any]) -> Dict[str,Any]:
    analyzers = [ClientSecretAnalyzer(), StateAnalyzer(), ConsentAnalyzer(), FrontChannelTokenLeakAnalyzer()]
    all_findings: List[Dict[str, Any]] = []

    token_paths = ["/protocol/openid-connect/token", "/oauth/token", "/token"]
    def looks_token_url(u):
        try:
            return any(p in (urlparse(u).path or "") for p in token_paths)
        except Exception:
            return False

    saw_any_request = False
    saw_any_query = False
    saw_any_referer = False
    saw_token_endpoint = False
    saw_auth_request = False
    saw_callback_with_code = False
    saw_scope_on_auth = False
    session_oauth_tokens_present = bool(session_tokens.get("oauth_tokens"))

    for pkt in packets:
        if pkt.get("type") != "request":
            continue
        saw_any_request = True

        req = pkt.get("request", {}) or {}
        url = req.get("url", "") or ""

        try:
            parsed = urlparse(url)
            if parsed.query or parsed.fragment:
                saw_any_query = True
        except Exception:
            pass

        hdrs = normalize_headers(req.get("headers", {}))
        if hdrs.get("referer"):
            saw_any_referer = True

        if looks_token_url(url):
            saw_token_endpoint = True

        if ("/authorize" in url) or ("response_type=" in url) or ("/protocol/openid-connect/auth" in url):
            saw_auth_request = True
            try:
                q = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
                if "scope" in q and q["scope"]:
                    saw_scope_on_auth = True
            except Exception:
                pass

        try:
            q = parse_qs(urlparse(url).query, keep_blank_values=True)
            if "code" in q:
                saw_callback_with_code = True
        except Exception:
            pass

    for a in analyzers:
        try:
            all_findings.extend(a.analyze(packets, session_tokens))
        except Exception as e:
            all_findings.append(mkfind("999.ERR", "Analyzer error", "INFO",
                                       "Analyzer raised exception", str(e), "Fix analyzer code."))

    def group_from_id(fid: str) -> str:
        if not fid:
            return "5.1"
        m = re.match(r"^(\d+\.\d+)", fid)
        if m:
            return m.group(1)
        if "-" in fid:
            return fid.split("-",1)[0]
        if "." in fid:
            return fid.split(".",1)[0]
        return "5.1"

    groups: Dict[str, Dict[str, Any]] = {gid: {"findings": [], "overall": "PASS"} for gid in EXPECTED_CHECKS}

    for f in all_findings:
        fid = f.get("id", "")
        gid = group_from_id(fid)
        if gid not in groups:
            groups[gid] = {"findings": [], "overall": "PASS"}
        groups[gid]["findings"].append(f)

    NA_RULES = {
        # 5.0 (6개)
        "5.0-QUERY-TOKEN:access_token":   lambda: (not saw_any_request) or (not saw_any_query),
        "5.0-QUERY-TOKEN:id_token":       lambda: (not saw_any_request) or (not saw_any_query),
        "5.0-QUERY-TOKEN:refresh_token":  lambda: (not saw_any_request) or (not saw_any_query),

        "5.0-REFERER-TOKEN:access_token":  lambda: (not saw_any_request) or (not saw_any_referer),
        "5.0-REFERER-TOKEN:id_token":      lambda: (not saw_any_request) or (not saw_any_referer),
        "5.0-REFERER-TOKEN:refresh_token": lambda: (not saw_any_request) or (not saw_any_referer),

        # 5.1
        "5.1-QUERY-CLIENT-SECRET":   lambda: (not saw_any_request) or (not saw_any_query),
        "5.1-REFERER-CLIENT-SECRET": lambda: (not saw_any_request) or (not saw_any_referer),
        "5.1-TOKEN-BODY-SECRET":     lambda: not saw_token_endpoint,
        "5.1-TOKEN-AUTH-BASIC":      lambda: not saw_token_endpoint,
        "5.1-SESSION-TOKEN-SECRET":  lambda: not session_oauth_tokens_present,

        # 5.3
        "5.3-STATE-MISSING":     lambda: not saw_auth_request,
        "5.3-STATE-LOW-ENTROPY": lambda: not saw_auth_request,
        "5.3-STATE-REUSE":       lambda: not saw_auth_request,
        "5.3-CB-STATE-MISSING":  lambda: not saw_callback_with_code,
        "5.3-CB-STATE-MISMATCH": lambda: not saw_callback_with_code,

        # 5.5
        "5.5-RISKY-SCOPE":       lambda: not saw_scope_on_auth,
    }

    json_groups: Dict[str, Any] = {}
    for gid, checks in EXPECTED_CHECKS.items():
        check_results = []
        f_list = groups.get(gid, {}).get("findings", [])

        fmap: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for f in f_list:
            fmap[f.get("id","")].append(f)

        for check_id, short, desc in checks:
            matched = fmap.get(check_id, [])
            if matched:
                result = "FAIL"
            else:
                na_func = NA_RULES.get(check_id)
                result = "NA" if (na_func and na_func()) else "PASS"

            entry: Dict[str, Any] = {
                "id": check_id,
                "title": short,
                "description": desc,
                "result": result,
            }
            if result == "FAIL":
                entry["findings"] = matched
            check_results.append(entry)

        results = [c["result"] for c in check_results]
        if any(r == "FAIL" for r in results):
            grp_overall = "FAIL"
        elif all(r == "NA" for r in results):
            grp_overall = "NA"
        else:
            grp_overall = "PASS"

        json_groups[gid] = {
            "overall": grp_overall,
            "checks": check_results,
        }

    group_overalls = [g["overall"] for g in json_groups.values()]
    if any(r == "FAIL" for r in group_overalls):
        overall = "FAIL"
    elif all(r == "NA" for r in group_overalls):
        overall = "NA"
    else:
        overall = "PASS"

    report = {
        "groups": json_groups,
        "overall": overall
    }

    # Console print
    print("==================== OAuth Security Analysis Report ====================")
    for gid, checks in EXPECTED_CHECKS.items():
        print(f"[{gid}]")
        f_list = groups.get(gid, {}).get("findings", [])
        fmap: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for f in f_list:
            fmap[f.get("id","")].append(f)

        for check_id, short, desc in checks:
            matched = fmap.get(check_id, [])
            if matched:
                print(f"❌ {short} FAIL")
                for i, finding in enumerate(matched, 1):
                    print(f"\n[{i}] {finding['title']}")
                    print(f"│ ID         : {finding.get('id')}")
                    print(f"│ Severity   : {finding.get('severity')}")
                    print(f"│ Description: {finding.get('description')}")
                    print(f"│ Evidence:\n{finding.get('evidence')}")
                    print(f"│ Recommendation: {finding.get('recommendation')}")
            else:
                na_func = NA_RULES.get(check_id)
                result = "NA" if (na_func and na_func()) else "PASS"
                if result == "NA":
                    print(f"➖ {short} NA")
                else:
                    print(f"✅ {short} PASS")

        print(f"▶ Group overall: {report['groups'][gid]['overall']}\n")

    print(f"==================== Overall result: {report.get('overall', 'UNKNOWN')} ====================")
    with open("oauth_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print("[+] JSON report saved: oauth_report.json")
    return report


# ==================== Example harness ====================
if __name__ == "__main__":
    example_packets = [
        {
            "type": "request",
            "request": {
                "url": "https://example.com/callback?access_token=AAA#id_token=XYZ&refresh_token=RRR",
                "headers": {
                    "User-Agent": "TestAgent",
                    "Referer": "https://r.example/?id_token=DEF"
                },
                "body_b64": base64.b64encode("grant_type=authorization_code&code=xyz".encode()).decode()
            }
        }
    ]
    example_session_tokens = {"oauth_tokens": [], "jwt_claims": []}

    analyze_and_report(example_packets, example_session_tokens)

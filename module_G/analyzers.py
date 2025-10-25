# -*- coding: utf-8 -*-
"""
analyzers.py
Combined analyzers (ClientSecret / State / Consent / OtherSensitive) + human-readable report.
- Robust base64 decoding
- Header normalization
- URL query/fragment parsing
- PASS/FAIL/NA status per check, per group, and overall
- Human-readable console output + oauth_report.json

Usage:
  from analyzers import analyze_and_report
  analyze_and_report(packets, session_tokens)
"""

from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, parse_qsl
from collections import defaultdict, Counter
import base64, json, re

# ==================== Robust Parsing Helpers ====================

def safe_b64decode(b64: str) -> bytes:
    """패딩 및 URL-safe를 고려한 안전한 base64 디코더. 실패 시 b'' 반환."""
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
    """헤더 키를 소문자로 정규화해 조회 누락 방지."""
    return {(k or "").lower(): v for k, v in (hdrs or {}).items()}

def parse_query_fragment(url: str) -> Dict[str, Any]:
    """
    URL에서 query와 fragment를 querystring으로 파싱.
    반환: {"url","path","scheme","query":{...},"fragment":{...}}
    - 동일 키 다중 출현 시 마지막 값 사용
    - 값 없음도 keep (keep_blank_values=True)
    """
    try:
        p = urlparse(url)
        q = dict(parse_qsl(p.query, keep_blank_values=True))
        frag = dict(parse_qsl(p.fragment, keep_blank_values=True))
        return {"url": url, "path": p.path, "scheme": p.scheme, "query": q, "fragment": frag}
    except Exception:
        return {"url": url, "path": "", "scheme": "", "query": {}, "fragment": {}}

def mask_secret(val: str, keep: int = 4) -> str:
    """증거 출력용 간단 마스킹 (앞/뒤 일부 유지)."""
    if val is None:
        return ""
    s = str(val)
    if len(s) <= keep * 2:
        return s[:keep] + "..." + s[-keep:]
    return s[:keep] + "..." + s[-keep:]

def extract_request_body_text(pkt: Dict[str, Any]) -> str:
    """
    packets.jsonl의 request.body_b64를 디코딩해 텍스트로 반환.
    - 없거나 실패 시 "" 반환
    - UTF-8 우선 + latin-1 폴백
    """
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
    """
    packets.jsonl의 response.body_b64를 디코딩해 텍스트로 반환.
    - 없거나 실패 시 "" 반환
    - UTF-8 우선 + latin-1 폴백
    """
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

# ==================== Entropy Helper (원래 로직 유지) ====================

def looks_random_state(state: str):
    """
    state 문자열의 무작위성을 간단히 추정:
    - base64url 문자군 여부
    - 샤논 엔트로피로 총 비트수 추정
    - UUID v4면 122비트로 통과 처리
    OK 기준:
      - UUID v4  또는
      - (base64url 문자군) and (길이 ≥ 22) and (추정 엔트로피 비트 ≥ 128)
    """
    import math, re
    from collections import Counter as _C

    if not state:
        return {"ok": False, "reason": "empty", "length": 0}

    # UUID v4 패턴 (122 bits of randomness)
    if re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        state, re.I
    ):
        return {
            "ok": True, "uuid_v4": True, "bits": 122,
            "entropy_per_char": None, "length": len(state),
            "charset_ok": True, "reason": "uuid_v4"
        }

    # base64url 허용 문자군 확인
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    charset_ok = all((c in charset) for c in state)

    n = len(state)
    cnt = _C(state)

    # 샤논 엔트로피 (per-char, bits)
    H = 0.0
    for k in cnt.values():
        p = k / n
        H -= p * math.log2(p)

    # 총 엔트로피 비트수 (최대 6n)
    bits = H * n
    ok = (charset_ok and n >= 22 and bits >= 128)

    return {
        "ok": ok,
        "length": n,
        "entropy_per_char": H,
        "bits": bits,
        "charset_ok": charset_ok,
        "uuid_v4": False,
        "reason": (
            "ok" if ok else
            ("bad-charset" if not charset_ok else
             ("too-short" if n < 22 else "low-entropy"))
        )
    }

# ==================== Finding factory ====================

def mkfind(fid: str, title: str, sev: str, desc: str, evidence: str, rec: str) -> Dict[str, Any]:
    return {"id": fid, "title": title, "severity": sev, "description": desc, "evidence": evidence, "recommendation": rec}

# ==================== Analyzer Classes ====================

class FrontChannelTokenLeakAnalyzer:
    """
    프론트채널(브라우저를 통해 보이는 경로: URL query/fragment, Referer 등)로
    OAuth/OIDC 토큰(access_token, id_token, refresh_token)이 노출되는지 진단합니다.
    - 요청 1개당, 벡터별(주소창/Referer) finding 1개 생성
    - 동일 요청 내 여러 토큰이 있으면 증거에 모두 나열
    - query와 fragment 모두 검사
    """

    SENSITIVE_TOKENS = {"access_token", "id_token", "refresh_token"}

    def _collect_leaks(self, pf: Dict[str, Any]) -> list[tuple[str, str, str]]:
        """
        parse_query_fragment(url) 결과에서 query/fragment 양쪽을 스캔해
        민감 토큰 노출 항목을 [(source, key, value), ...] 형태로 수집.
        source ∈ {"query", "fragment"}
        """
        items = []
        # query
        q_keys = self.SENSITIVE_TOKENS & set((pf.get("query") or {}).keys())
        for k in sorted(q_keys):
            items.append(("query", k, pf["query"][k]))
        # fragment
        f_keys = self.SENSITIVE_TOKENS & set((pf.get("fragment") or {}).keys())
        for k in sorted(f_keys):
            items.append(("fragment", k, pf["fragment"][k]))
        return items

    def analyze(self, packets: List[Dict[str, Any]], session_tokens: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        # 1) URL(주소창) 노출: 요청 URL의 query/fragment 모두 검사
        for pkt in packets:
            if pkt.get("type") != "request":
                continue
            req = pkt.get("request", {}) or {}
            url = req.get("url", "") or ""
            pf = parse_query_fragment(url)

            leaks = self._collect_leaks(pf)
            if leaks:
                # 증거를 한 번에 모아서 출력 (동일 요청 내 여러 토큰/소스 포함)
                lines = [f"Request URL: {url}"]
                for src, k, v in leaks:
                    lines.append(f"{src.capitalize()} param {k}={mask_secret(v)}")
                evidence = "\n".join(lines)

                # 설명도 다중 토큰을 반영
                leaked_keys = ", ".join(sorted({k for _, k, _ in leaks}))
                desc = (
                    f"{leaked_keys} 이(가) 브라우저 주소창, 히스토리, 로그 등에 남아 제3자에게 노출될 수 있습니다. "
                    "토큰은 프론트채널(URL)에 절대 포함하지 마세요."
                )
                rec = (
                    "권장: Authorization Code + PKCE 사용, response_mode=form_post(가능 시), "
                    "토큰은 백엔드로 안전하게 전달(쿠키 HttpOnly/SameSite 또는 BFF 패턴)하고 "
                    "프론트에는 보관하지 않기."
                )

                findings.append(mkfind(
                    "5.0-QUERY-TOKEN",     # 기존 체크 ID 유지
                    "Query Token Leak",
                    "HIGH",
                    desc,
                    evidence,
                    rec
                ))

        # 2) Referer 헤더를 통한 노출: Referer URL의 query/fragment 모두 검사
        for pkt in packets:
            if pkt.get("type") != "request":
                continue
            req = pkt.get("request", {}) or {}
            headers = normalize_headers(req.get("headers", {}))
            ref = headers.get("referer")
            if not ref:
                continue

            pf = parse_query_fragment(ref)
            leaks = self._collect_leaks(pf)
            if leaks:
                lines = [
                    f"Request URL: {req.get('url')}",
                    f"Referer: {ref}",
                ]
                for src, k, v in leaks:
                    lines.append(f"Leaked via {src}: {k}={mask_secret(v)}")
                evidence = "\n".join(lines)

                leaked_keys = ", ".join(sorted({k for _, k, _ in leaks}))
                desc = (
                    f"페이지 간 이동 시 Referer에 {leaked_keys} 이(가) 포함되어 타 도메인(광고/분석/이미지 CDN 등)으로 "
                    "유출될 수 있습니다."
                )
                rec = (
                    "권장: URL에 토큰을 넣지 않기 + 'Referrer-Policy: no-referrer' 또는 "
                    "'strict-origin-when-cross-origin' 설정."
                )

                findings.append(mkfind(
                    "5.0-REFERER-TOKEN",   # 기존 체크 ID 유지
                    "Referer Token Leak",
                    "HIGH",
                    desc,
                    evidence,
                    rec
                ))

        return findings


class ClientSecretAnalyzer:
    """
    URL 쿼리 / Referer 헤더에서 client_secret 노출 탐지 + 토큰 엔드포인트 본문/Basic 인증 확인.
    """
    TARGET_KEY = "client_secret"

    def analyze(self, packets: List[Dict[str, Any]], session_tokens: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        # 1) URL query에 client_secret 포함 여부
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
                    "client_secret이 URL 쿼리에 포함됨",
                    "CRITICAL",
                    "client_secret은 서버-사이드 비밀이며 URL(프론트채널)에 남겨서는 안 됩니다. 브라우저 히스토리/리퍼러로 유출될 수 있습니다.",
                    evidence,
                    "client_secret은 절대 URL에 포함하지 마십시오. 서버-사이드 POST 또는 안전한 백엔드 인증 방식으로 처리하세요."
                ))

        # 2) Referer 헤더로 client_secret 유출 여부
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
                    "Referer로 client_secret 유출",
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
                    "Token 요청에서 client_secret 전송 감지",
                    sev,
                    "client_secret가 토큰 교환 요청의 본문에 포함되어 전송되었습니다.",
                    evidence,
                    "토큰은 HTTP 헤더에 포함되어야 합니다."
                ))

            # Basic Auth
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
                    "Token 요청에서 Authorization: Basic 사용 감지",
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
                    "session_token.json에 client_secret 기록 감지",
                    "HIGH",
                    "요약 파일(session_token.json)에 client_secret 항목이 기록되어 있습니다.",
                    f"Location: {it.get('where')} url={it.get('url')} value={mask_secret(it.get('value'))}",
                    "진단용 로그에도 민감값을 남기지 마십시오. 마스킹/암호화/접근통제 필요"
                ))
        return findings


class StateAnalyzer:
    """state 존재/무작위성/재사용 및 콜백 state 검증."""
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


class ConsentAnalyzer:
    """동의(Consent) 요청에서 과도/민감 scope 탐지 (IDP-agnostic)."""

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

                cid = q.get("client_id")
                if cid:
                    client_scope_counter[cid] += 1
                    if self.behavioral_checks:
                        ts = pkt.get("timestamp", 0)
                        client_times[cid].append(ts)

        return findings

# ==================== Report Generator (PASS/FAIL/NA) ====================

EXPECTED_CHECKS = {
    "5.0": [
        ("5.0-QUERY-TOKEN",   "Query Token Leak",   "토큰이 URL 쿼리에 포함됨"),
        ("5.0-REFERER-TOKEN", "Referer Token Leak", "Referer로 토큰 유출"),
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
    analyzers = [ClientSecretAnalyzer(), StateAnalyzer(), ConsentAnalyzer(),  FrontChannelTokenLeakAnalyzer(),]
    all_findings: List[Dict[str, Any]] = []

    # ---- 사전 플래그(NA 판단용, 확장) ----
    token_paths = ["/protocol/openid-connect/token", "/oauth/token", "/token"]
    def looks_token_url(u):
        try:
            return any(p in (urlparse(u).path or "") for p in token_paths)
        except Exception:
            return False

    saw_any_request = False
    saw_any_query = False                 # 어떤 요청이라도 querystring 존재
    saw_any_referer = False               # 어떤 요청이라도 Referer 헤더 존재
    saw_token_endpoint = False            # 토큰 엔드포인트 호출 관측
    saw_auth_request = False              # authorize 요청 관측
    saw_callback_with_code = False        # 콜백에 code 관측
    saw_scope_on_auth = False             # authorize 요청 중 scope 파라미터 관측
    session_oauth_tokens_present = bool(session_tokens.get("oauth_tokens"))

    for pkt in packets:
        if pkt.get("type") != "request":
            continue
        saw_any_request = True

        req = pkt.get("request", {}) or {}
        url = req.get("url", "") or ""

        # 쿼리 유무
        try:
            parsed = urlparse(url)
            if parsed.query:
                saw_any_query = True
        except Exception:
            pass

        # Referer 유무
        hdrs = normalize_headers(req.get("headers", {}))
        if hdrs.get("referer"):
            saw_any_referer = True

        # 토큰 엔드포인트
        if looks_token_url(url):
            saw_token_endpoint = True

        # authorize / callback 플래그
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

    # ---- Analyzer 실행 ----
    for a in analyzers:
        try:
            all_findings.extend(a.analyze(packets, session_tokens))
        except Exception as e:
            all_findings.append(mkfind("999.ERR", "Analyzer error", "INFO",
                                       "Analyzer raised exception", str(e), "Fix analyzer code."))

    # 그룹 추출
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
    groups: Dict[str, Dict[str, Any]] = {gid: {"findings": [], "overall": "PASS"} for gid in EXPECTED_CHECKS}

    # Finding들을 그룹화
    for f in all_findings:
        fid = f.get("id", "")
        gid = group_from_id(fid)
        if gid not in groups:
            groups[gid] = {"findings": [], "overall": "PASS"}
        groups[gid]["findings"].append(f)

    # ---- 체크별 결과(PASS/FAIL/NA) 산출 (확장 NA RULES) ----
    NA_RULES = {
        # 5.0
        "5.0-QUERY-TOKEN":   lambda: (not saw_any_request) or (not saw_any_query),
        "5.0-REFERER-TOKEN": lambda: (not saw_any_request) or (not saw_any_referer),

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

    # 그룹 결과 구성 + JSON-friendly 구조 생성
    json_groups: Dict[str, Any] = {}
    for gid, checks in EXPECTED_CHECKS.items():
        check_results = []
        f_map = {f["id"]: f for f in groups.get(gid, {}).get("findings", [])}

        for check_id, short, desc in checks:
            finding = f_map.get(check_id)
            if finding:
                result = "FAIL"
            else:
                na_func = NA_RULES.get(check_id)
                result = "NA" if (na_func and na_func()) else "PASS"

            entry: Dict[str, Any] = {
                "id": check_id,
                "title": short,
                "description": desc,
                "result": result,  # ← JSON 필드 이름은 result
            }
            if result == "FAIL":
                entry["severity"] = finding.get("severity")
                entry["evidence"] = finding.get("evidence")
                entry["recommendation"] = finding.get("recommendation")
                entry["full_title"] = finding.get("title")
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

    # 전체 overall
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

    # JSON 저장
    with open("oauth_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    # ==================== 사람 읽기용 출력 ====================
    print("==================== OAuth Security Analysis Report ====================")
    for gid, checks in EXPECTED_CHECKS.items():
        print(f"[{gid}]")
        f_map = {f["id"]: f for f in groups.get(gid, {}).get("findings", [])}

        for check_id, short, desc in checks:
            finding = f_map.get(check_id)
            if finding:
                result = "FAIL"
            else:
                na_func = NA_RULES.get(check_id)
                result = "NA" if (na_func and na_func()) else "PASS"

            if result == "FAIL":
                print(f"❌ {short} FAIL")
                print(f"\n└─ {finding['title']}\n│ Severity : {finding['severity']}\n│ Description: {finding['description']}\n│ Evidence:\n{finding['evidence']}\n│ Recommendation: {finding['recommendation']}\n")
            elif result == "NA":
                print(f"➖ {short} NA")
            else:
                print(f"✅ {short} PASS")

        print(f"▶ Group overall: {report['groups'][gid]['overall']}\n")

    print(f"==================== Overall result: {report.get('overall', 'UNKNOWN')} ====================")
    print("[+] JSON report saved: oauth_report.json")
    return report


# ==================== Example harness ====================
if __name__ == "__main__":
    example_packets = [
        {
            "type": "request",
            "request": {
                "url": "https://example.com/callback?client_secret=abcd1234&state=foo",
                "headers": {"User-Agent": "TestAgent", "Referer": "https://r.example/?id_token=XYZ"},
                "body_b64": base64.b64encode("grant_type=authorization_code&code=xyz".encode()).decode()
            }
        }
    ]
    example_session_tokens = {"oauth_tokens": [], "jwt_claims": []}

    analyze_and_report(example_packets, example_session_tokens)

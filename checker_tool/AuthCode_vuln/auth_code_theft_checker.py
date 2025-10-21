"""
auth_code_theft_checker.py

Single-file "vuln check module" to detect **Authorization Code Theft** risks in OAuth 2.0 / OIDC flows.
- Scope: ONLY the authorization code–theft vector set.
- Input: DataController passes parsed HTTP packet details as a Python dict (see DATA CONTRACT below).
- Output: List of structured findings + pretty text report.

Standards basis (핵심):
  - RFC 6749 (OAuth 2.0 Core) §§3.1.2, 4.1.2, 4.1.3, 10.6, 10.15
  - RFC 7636 (PKCE)
  - RFC 8252 (Native Apps)
  - RFC 9101 (JAR), RFC 9126 (PAR)
  - RFC 9207 (`iss` response parameter)
  - RFC 9700 / BCP 240 (OAuth 2.0 Security BCP)
  - OIDC Core (redirect_uri Simple String Comparison = exact match MUST)
  - OAuth 2.0 Form Post Response Mode (OIDF)
  - PortSwigger OAuth labs (공격 흐름 참고)

==========================
DATA CONTROLLER — 주의!
==========================
이 모듈은 '패킷을 직접 캡처'하지 않습니다. Data Controller가 캡처/파싱한 값을
아래 trace 딕셔너리 포맷으로 넘겨야 합니다(최소 필수 필드는 아래 주석 참고).

"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import math
import urllib.parse as up

SEV_HIGH = "HIGH"
SEV_MEDIUM = "MEDIUM"
SEV_LOW = "LOW"
SEV_INFO = "INFO"

@dataclass
class Finding:
    id: str
    title: str
    severity: str
    description: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
        }

def _host(url: str) -> Optional[str]:
    try:
        return up.urlparse(url).netloc
    except Exception:
        return None

def _scheme(url: str) -> Optional[str]:
    try:
        return up.urlparse(url).scheme
    except Exception:
        return None

def _entropy_bits_per_char(s: str) -> float:
    """Shannon entropy(bits/char) — 추측 난이도 점검(참고용)."""
    if not s:
        return 0.0
    from collections import Counter
    cnt = Counter(s)
    n = len(s)
    return -sum((c/n) * math.log2(c/n) for c in cnt.values())

class AuthCodeTheftChecker:
    """
    사용법: AuthCodeTheftChecker().check(trace_dict) -> List[Finding]

    === DATA CONTRACT(요약) ===
    trace = {
      "as_issuer_expected": "https://as.example",                 # OIDC Discovery issuer 등(권장)
      "registered_redirect_uris": ["https://client.tld/cb"],      # (필수) 사전등록 redirect_uri 목록

      "authorization_request": {                                  # (필수) /authorize 요청에서 추출
         "client_id": "my-client",
         "redirect_uri": "https://client.tld/cb",
         "response_type": "code",
         "response_mode": "query|fragment|form_post|<없음>",
         "state": "XYZ...",                                       # (권장)
         "code_challenge": "AbCd...",                             # (PKCE시 권장)
         "code_challenge_method": "S256|plain|<없음>",
         "is_oidc": True,                                         # (권장) scope에 openid 포함 여부
         "nonce": "abc123...",                                    # (권장) OIDC면
         "request_uri": "https://req-obj.tld/...",                # (선택) by-reference 사용시
         "par_used": False                                        # (선택) PAR 사용 여부
      },

      "authorization_response": {                                 # (필수) AS→클라 콜백 단계
         "delivery": "query|fragment|form_post",                  # 코드 전달 방식
         "redirect_to": "https://client.tld/cb?code=...&state=...",
         "code_present": True,
         "state": "XYZ...",
         "iss": "https://as.example",                             # (선택) RFC 9207 'iss'
         "redirect_chain": [                                      # (선택) 콜백 이후 3xx 체인 추적
             "https://client.tld/cb?code=...",
             "https://client.tld/redirect?next=https://attacker.tld"
         ]
      },

      "callback_page_requests": [                                 # (선택) 콜백 페이지 서브리소스 요청
         {"url": "https://cdn.example/app.js",
          "headers": {"Referer": "https://client.tld/cb?code=..."}}
      ],

      "token_request": {                                          # (권장) /token 요청에서 추출
         "client_id": "my-client",
         "grant_type": "authorization_code",
         "code": "abc...",
         "redirect_uri": "https://client.tld/cb",                 # authz에 보냈다면 여기서도 MUST
         "code_verifier": "....",                                 # PKCE시 필수
         "client_auth": "client_secret_basic|mtls|none"
      },

      "token_response": {                                         # (선택)
         "token_type": "Bearer",
         "dpop": False,
         "mtls": False
      },

      "environment": {                                            # (선택)
         "is_native_app": False,
         "loopback_used": False,
         "claimed_https_scheme": False
      }
    }
    """

    def __init__(self):
        self.findings: List[Finding] = []

    def _add(self, *args, **kwargs):
        self.findings.append(Finding(*args, **kwargs))

    def check(self, trace: Dict[str, Any]) -> List[Finding]:
        self.findings = []

        reg_uris = set(trace.get("registered_redirect_uris") or [])
        authz_req = trace.get("authorization_request") or {}
        authz_res = trace.get("authorization_response") or {}
        cb_reqs  = trace.get("callback_page_requests") or []
        token_req = trace.get("token_request") or {}
        env = trace.get("environment") or {}

        ru = authz_req.get("redirect_uri")

        # [1] redirect_uri 등록/정확일치 (RFC 6749, OIDC Core Simple String Comparison)
        if not reg_uris:
            self._add(
                id="AC-RED-000",
                title="registered_redirect_uris 미제공",
                severity=SEV_INFO,
                description="정확 일치 검증을 위해 사전등록 redirect_uri 허용목록이 필요합니다.",
                remediation="클라이언트 레지스트리의 허용 목록을 'registered_redirect_uris'로 전달하세요.",
                references=["RFC 6749 §3.1.2", "OIDC Core (Simple String Comparison)"]
            )
        else:
            if not ru:
                self._add(
                    id="AC-RED-001",
                    title="인가요청에 redirect_uri 없음",
                    severity=SEV_LOW,
                    description="여러 콜백이 등록된 클라이언트라면 미지정은 리스크가 커질 수 있습니다.",
                    remediation="인가요청에 redirect_uri를 명시하고, 사전등록된 값과 정확히 일치하도록 하세요.",
                    references=["RFC 6749 §3.1.2.2, §4.1.2", "RFC 9700(BCP)"]
                )
            elif ru not in reg_uris:
                self._add(
                    id="AC-RED-002",
                    title="사전등록 목록에 없는 redirect_uri",
                    severity=SEV_HIGH,
                    description=f"인가요청 redirect_uri가 등록 허용목록과 일치하지 않습니다.",
                    evidence=f"allowlist={list(reg_uris)}; seen={ru}",
                    remediation="와일드카드/서브도메인 허용 없이, 사전등록 값에 '정확히' 일치하는 경우만 허용하세요.",
                    references=["RFC 6749 §3.1.2", "OIDC Core", "RFC 9700(BCP)"]
                )

        # [2] 콜백 이후 오픈 리다이렉트 체인 (RFC 6749 §10.15)
        chain = authz_res.get("redirect_chain") or []
        if chain and ru:
            original = _host(ru)
            for hop in chain[1:]:
                if original and _host(hop) and _host(hop) != original:
                    self._add(
                        id="AC-RED-003",
                        title="콜백 경로에서 오픈 리다이렉트 체인 감지",
                        severity=SEV_HIGH,
                        description="등록 콜백 이후 다른 호스트로 리다이렉트됩니다(코드 유출 위험).",
                        evidence=f"chain={chain}",
                        remediation="콜백 경로에서 외부 도메인으로 리다이렉션하지 마세요(정적/동일 출처 유지).",
                        references=["RFC 6749 §10.15", "RFC 9700(BCP)", "PortSwigger OAuth labs"]
                    )
                    break

        # [3] 코드 전달 방식: URL(query/fragment) vs form_post (OIDF Form Post, BCP)
        delivery = (authz_res.get("delivery") or authz_req.get("response_mode") or "").lower()
        if delivery in ("", "query", "fragment"):
            self._add(
                id="AC-DEL-001",
                title="인가코드가 URL로 전달됨(query/fragment)",
                severity=SEV_MEDIUM,
                description="URL에 노출된 코드는 로그/Referer/브라우저 히스토리로 누수될 수 있습니다.",
                remediation="코드 흐름에는 response_mode=form_post 사용을 권장합니다.",
                references=["OIDF Form Post Response Mode", "RFC 9700(BCP)"]
            )

        # [4] 콜백 페이지의 Referer 누수 점검 (BCP, OIDF Form Post)
        for r in cb_reqs:
            referer = (r.get("headers") or {}).get("Referer") or (r.get("headers") or {}).get("referer")
            if referer and "code=" in referer and ru:
                if _host(r.get("url")) and _host(r.get("url")) != _host(ru):
                    self._add(
                        id="AC-DEL-002",
                        title="서드파티로 Referer에 코드 유출",
                        severity=SEV_HIGH,
                        description="콜백 페이지가 외부 리소스를 로드하며 Referer에 인가코드가 포함되었습니다.",
                        evidence=f"request={r.get('url')}, referer={referer}",
                        remediation="Form Post 사용, 콜백에서 서드파티 로드 제거, Referrer-Policy 적용.",
                        references=["RFC 9700(BCP)", "OIDF Form Post"]
                    )
                else:
                    self._add(
                        id="AC-DEL-003",
                        title="Referer에 인가코드 포함",
                        severity=SEV_MEDIUM,
                        description="동일 출처라도 운영 로그/분석 경로로 샐 수 있습니다.",
                        evidence=f"referer={referer}",
                        remediation="Form Post 사용으로 URL 노출 자체를 제거하세요.",
                        references=["RFC 9700(BCP)"]
                    )

        # [5] state 존재/엔트로피 (RFC 6749 §10.12, RFC 9700)
        state = authz_req.get("state")
        if not state:
            self._add(
                id="AC-STA-001",
                title="state 미사용",
                severity=SEV_HIGH,
                description="state가 없으면 로그인 CSRF/코드 주입에 취약합니다.",
                remediation="트랜잭션마다 고엔트로피 state를 생성/검증하고 처리 후 파기하세요.",
                references=["RFC 6749 §10.12", "RFC 9700(BCP)"]
            )
        else:
            ent = _entropy_bits_per_char(state)
            if len(state) < 16 or ent < 3.0:
                self._add(
                    id="AC-STA-002",
                    title="state가 짧거나 예측 가능",
                    severity=SEV_MEDIUM,
                    description=f"state 추측 가능성 존재 (len={len(state)}, entropy≈{ent:.2f} bits/char).",
                    remediation="암호학적 난수로 충분히 긴 state 사용(~128비트 수준의 예측 불가성).",
                    references=["RFC 9700(BCP)"]
                )

        # [6] Mix-Up 방지(iss, RFC 9207)
        expected_iss = trace.get("as_issuer_expected")
        seen_iss = authz_res.get("iss")
        if expected_iss:
            if not seen_iss:
                self._add(
                    id="AC-ISS-001",
                    title="인가응답에 iss 없음(믹스업 방어 비활성)",
                    severity=SEV_LOW,
                    description="다중 AS 환경이면 'iss' 검증으로 발신자 식별이 필요합니다.",
                    remediation="인가응답에 RFC 9207의 'iss'를 포함/검증하세요.",
                    references=["RFC 9207"]
                )
            elif seen_iss != expected_iss:
                self._add(
                    id="AC-ISS-002",
                    title="인가응답의 iss 불일치",
                    severity=SEV_HIGH,
                    description=f"인가응답 발신자(iss)가 기대값과 다릅니다.",
                    evidence=f"expected={expected_iss}, seen={seen_iss}",
                    remediation="응답 거부 및 구성된 AS issuer와 일치하는지 검증하세요.",
                    references=["RFC 9207"]
                )

        # [7] PKCE 점검 (RFC 7636, BCP)
        cc = (authz_req.get("code_challenge") or "")
        ccm = (authz_req.get("code_challenge_method") or "").upper()
        cv = token_req.get("code_verifier")
        if cc:
            if ccm in ("", "PLAIN"):
                self._add(
                    id="AC-PKCE-001",
                    title="PKCE 'plain' 사용(다운그레이드 취약)",
                    severity=SEV_HIGH,
                    description="PKCE는 S256 권장입니다. plain은 사용 금지.",
                    remediation="S256만 허용하도록 정책화하세요.",
                    references=["RFC 7636 §4.2"]
                )
            if not cv:
                self._add(
                    id="AC-PKCE-002",
                    title="/token에 code_verifier 미제출",
                    severity=SEV_HIGH,
                    description="인가요청에서 PKCE를 썼다면 토큰 교환 시 code_verifier가 필수입니다.",
                    remediation="code_verifier 미제출 시 토큰 교환을 거부하도록 하세요.",
                    references=["RFC 7636"]
                )
        else:
            self._add(
                id="AC-PKCE-003",
                title="코드 플로우에서 PKCE 미사용",
                severity=SEV_MEDIUM,
                description="PKCE 미사용은 코드 가로채기/주입 리스크를 키웁니다.",
                remediation="모든 코드 플로우에 PKCE(S256)를 적용하세요.",
                references=["RFC 9700(BCP)", "RFC 7636"]
            )

        # [8] /token 바인딩 검증(redirect_uri 동일 제출, RFC 6749 §4.1.3)
        if ru:
            tru = token_req.get("redirect_uri")
            if not tru:
                self._add(
                    id="AC-TOK-001",
                    title="/token에 redirect_uri 누락(바인딩 상실)",
                    severity=SEV_HIGH,
                    description="인가요청에 redirect_uri를 보냈다면 /token에도 동일한 값을 보내야 합니다.",
                    remediation="/token 요청에 동일 redirect_uri를 포함하고 AS에서 일치 검증을 강제하세요.",
                    references=["RFC 6749 §4.1.3"]
                )
            elif tru != ru:
                self._add(
                    id="AC-TOK-002",
                    title="인가요청과 /token의 redirect_uri 불일치",
                    severity=SEV_HIGH,
                    description="인가요청에서 사용한 redirect_uri와 /token의 값이 다릅니다.",
                    evidence=f"authz={ru}, token={tru}",
                    remediation="두 요청 모두 동일한 redirect_uri를 사용하세요.",
                    references=["RFC 6749 §4.1.3"]
                )

        # [9] Request by reference 사용 시(PAR/JAR 권장)
        req_uri = authz_req.get("request_uri")
        par_used = bool(authz_req.get("par_used"))
        if req_uri and not par_used:
            self._add(
                id="AC-REQ-001",
                title="request_uri by reference 이면서 PAR 미사용",
                severity=SEV_MEDIUM,
                description="by-reference는 변조/노출면이 큽니다. PAR로 백채널 푸시 권장.",
                evidence=f"request_uri={req_uri}",
                remediation="RFC 9126(PAR) 채택, 최소한 JAR 서명/암호화 + request_uri 화이트리스트/단명성.",
                references=["RFC 9101", "RFC 9126"]
            )

        # [10] 네이티브 앱 특이사항(RFC 8252)
        if env.get("is_native_app"):
            sch = _scheme(ru) if ru else None
            if sch and sch not in ("http", "https"):  # 커스텀 스킴
                if not cc:
                    self._add(
                        id="AC-NAT-001",
                        title="네이티브 커스텀 스킴에서 PKCE 미사용",
                        severity=SEV_HIGH,
                        description="커스텀 스킴은 가로채기 위험이 커서 PKCE가 필수적입니다.",
                        remediation="PKCE(S256) 적용. 가능하면 루프백(127.0.0.1/::1) 또는 claimed HTTPS 사용.",
                        references=["RFC 8252", "RFC 7636"]
                    )

        # [11] 토큰 송신자 구속(피해 축소) — mTLS/DPoP (정보성)
        tok = trace.get("token_response") or {}
        if tok and not tok.get("mtls") and not tok.get("dpop"):
            self._add(
                id="AC-MIT-001",
                title="액세스 토큰 송신자 구속 미적용(정보)",
                severity=SEV_INFO,
                description="코드가 유출돼 토큰이 발급되더라도, mTLS/DPoP로 재사용을 줄일 수 있습니다.",
                remediation="가능한 경우 mTLS(RFC 8705) 또는 DPoP(RFC 9449) 채택.",
                references=["RFC 8705", "RFC 9449"]
            )

        return self.findings

    def render_text_report(self, findings: Optional[List[Finding]] = None) -> str:
        findings = findings if findings is not None else self.findings
        if not findings:
            return "[OK] No authorization-code-theft risks detected based on supplied evidence."

        order = {SEV_HIGH:0, SEV_MEDIUM:1, SEV_LOW:2, SEV_INFO:3}
        lines: List[str] = []
        for f in sorted(findings, key=lambda x: order.get(x.severity, 99)):
            lines.append(f"[{f.severity}] {f.id} — {f.title}")
            if f.description: lines.append(f"  desc: {f.description}")
            if f.evidence:    lines.append(f"  evidence: {f.evidence}")
            if f.remediation: lines.append(f"  fix: {f.remediation}")
            if f.references:  lines.append(f"  refs: {', '.join(f.references)}")
            lines.append("")
        return "\n".join(lines)


# --------------- EXAMPLE (Data Controller가 여기만 바꾸면 실행됨) ---------------
if __name__ == "__main__":
    # >>> Data Controller: 아래 'trace'에 캡처/파싱한 값 넣으세요 (예시) <<<
    trace = {
        "as_issuer_expected": "https://as.example",
        "registered_redirect_uris": ["https://client.tld/cb"],

        "authorization_request": {
            "client_id": "my-client",
            "redirect_uri": "https://client.tld/cb",
            "response_type": "code",
            "response_mode": "query",
            "state": "state-123",
            "code_challenge": "abc",
            "code_challenge_method": "plain",  # 의도적으로 취약
            "is_oidc": True,
            "nonce": "nonce-xyz",
            "par_used": False
        },

        "authorization_response": {
            "delivery": "query",
            "redirect_to": "https://client.tld/cb?code=XYZ&state=state-123",
            "code_present": True,
            "state": "state-123",
            "iss": "https://as.example",
            "redirect_chain": [
                "https://client.tld/cb?code=XYZ&state=state-123",
                "https://client.tld/redirect?next=https://attacker.tld"
            ]
        },

        "callback_page_requests": [
            {
                "url": "https://cdn.example/app.js",
                "headers": {"Referer": "https://client.tld/cb?code=XYZ&state=state-123"}
            }
        ],

        "token_request": {
            "client_id": "my-client",
            "grant_type": "authorization_code",
            "code": "XYZ",
            "redirect_uri": "https://client.tld/cb",
            "code_verifier": None,  # 의도적으로 취약
            "client_auth": "client_secret_basic"
        },

        "token_response": {
            "token_type": "Bearer",
            "dpop": False,
            "mtls": False
        },

        "environment": {
            "is_native_app": False,
            "loopback_used": False
        }
    }

    checker = AuthCodeTheftChecker()
    findings = checker.check(trace)
    print(checker.render_text_report(findings))

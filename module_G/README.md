# OAuth Vuln Analyzer (packets.jsonl 기반)

## 개요
mitmproxy 등으로 캡처한 `proxy_artifacts/packets.jsonl` 및 `session_token.json`을 입력으로 받아
다음 취약점을 자동 진단합니다:
- 5.1 Client Secret 유출/노출
- 5.3 state 파라미터 미사용/미검증
- 5.5 Consent/Scope 과다 권한 요청

## 설치
1. Python 3.8+ 환경 준비
2. 의존성(없음: 표준 라이브러리 사용). JWT 디코딩/추가가 필요하면 `pip install pyjwt` 등 추가.

## 사용법
1. mitmproxy로 캡처: `proxy_artifacts/packets.jsonl` 및 `proxy_artifacts/session_token.json` 생성
2. 이 레포에서:
```bash
python analyze_and_report.py


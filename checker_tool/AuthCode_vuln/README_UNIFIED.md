# KSJ15_vuln — Unified Runner & Authorization Code Theft Checker

## Files
- `run_checker.py` — 통합 런너/어댑터
- `auth_code_theft_checker.py` — 인가 코드 탈취 진단 모듈 (A/B/C 섹션 표준 출력)

## 사용 예시 (PowerShell)
```powershell
cd "C:\Users\USER\Desktop\OAuthTool\checker_tool"

# 세션 캡처(JSON)로 실행
python .\run_checker.py .\session_token.json --module .\AuthCode_vuln\auth_code_theft_checker.py --outdir .\out

# 이미 정규화된 flow_bundle로 실행
python .\run_checker.py .\flow_from_session.json --module .\AuthCode_vuln\auth_code_theft_checker.py --outdir .\out
```

### 산출물(통일 규격)
- `flow_from_session.json` (세션 캡처 입력 시 생성)
- `authcode_report.txt`
- `authcode_report.json`
- `authcode_report.md`

이 폴더는 'Proxy Capture' 모드의 산출물입니다.

[파일 설명]
- packets.jsonl: 캡처된 요청/응답을 한 줄당 한 건씩 순서대로 기록(type=request/response).
- session_token.json: 쿠키/스토리지/Authorization/JWT 및 OAuth 파라미터(code/access_token/id_token/refresh_token 등) 요약.
    • oauth_tokens: 개별 토큰 레코드(종류는 kind 필드로 표시).
    • oauth_by_type: 종류별 묶음(access_token, id_token, refresh_token, auth_code, authorization_bearer 등).
- run_meta.json: 실행 시간/모드/카운트/대상 정보 등의 메타데이터.
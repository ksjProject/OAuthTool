이 폴더는 'Proxy Capture' 모드의 산출물입니다.
이 모드는 이 PC를 프록시로 실행하고, 해당 프록시를 경유하는 요청/응답 트래픽을 캡처하여 OAuth 관련 이슈를 점검합니다.

[파일 설명]
- packets.jsonl: 캡처된 요청/응답을 한 줄당 한 건씩 순서대로 기록(type=request/response).
- session_token.json: 쿠키/스토리지/Authorization/JWT 및 OAuth 파라미터(code/access_token/id_token 등) 요약.
- run_meta.json: 실행 시간/모드/카운트/대상 정보 등의 메타데이터.
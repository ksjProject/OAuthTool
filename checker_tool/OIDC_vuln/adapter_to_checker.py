#!/usr/bin/env python3
# adapter_to_checker.py
# - session_token.json(네 캡처 형식)을 oidc_nonce_checker 모듈이 요구하는 flow_bundle로 변환
# - 변환된 flow_bundle로 nonce 진단 실행, 리포트/JSON 저장

import json, argparse, urllib.parse, base64, os
from datetime import datetime
import importlib.util

def parse_q_and_fragment(url: str):
    if not url:
        return {}
    p = urllib.parse.urlparse(url)
    merged = {}
    for qs in (p.query, p.fragment):
        if not qs: continue
        for k,v in urllib.parse.parse_qs(qs, keep_blank_values=True).items():
            if v: merged[k]=v[0]
    return merged

def load_checker(checker_path: str):
    import importlib.util, sys
    spec = importlib.util.spec_from_file_location("oidc_nonce_checker", checker_path)
    mod = importlib.util.module_from_spec(spec)
    # ✅ 중요: dataclasses 등이 sys.modules를 통해 모듈 네임스페이스를 찾습니다.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod

def guess_auth_entries(tokens):
    # 흔한 인가 엔드포인트 패턴들
    hints = ["/authorize", "/protocol/openid-connect/auth", "/oauth2/v2/auth"]
    return [t for t in tokens if any(h in t.get("url","") for h in hints)]

def guess_callback_entries(tokens):
    # 콜백 URL 흔한 패턴
    hints = ["/callback", "/cb", "/signin-oidc", "/login/callback"]
    return [t for t in tokens if any(h in t.get("url","") for h in hints)]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("session_json", help="session_token.json 경로")
    ap.add_argument("--checker", default="./oidc_nonce_checker.py", help="진단 모듈 경로")
    ap.add_argument("--outdir", default=".", help="산출물 폴더")
    args = ap.parse_args()

    # 1) 모듈 로드
    checker = load_checker(args.checker)

    # 2) 캡처 로드
    with open(args.session_json, "r", encoding="utf-8") as f:
        sess = json.load(f)

    oauth_tokens = sess.get("oauth_tokens", [])

    # 3) 인가요청/콜백/토큰 추출(휴리스틱)
    auth_entries = guess_auth_entries(oauth_tokens)
    auth_url = auth_entries[-1]["url"] if auth_entries else None
    auth_params = parse_q_and_fragment(auth_url) if auth_url else {}

    cb_entries = guess_callback_entries(oauth_tokens)
    cb_url = cb_entries[-1]["url"] if cb_entries else None
    cb_params = parse_q_and_fragment(cb_url) if cb_url else {}

    id_tokens = [t for t in oauth_tokens if t.get("key")=="id_token"]
    access_tokens = [t for t in oauth_tokens if t.get("key")=="access_token"]
    id_token_val = id_tokens[-1]["value"] if id_tokens else None
    access_token_val = access_tokens[-1]["value"] if access_tokens else None

    # 4) flow_bundle 구성 (모듈 입력 스키마)
    flow_bundle = {
        "discovery": {},
        "authorization_request": {
            "url": auth_url,
            "params": auth_params,
            "ts": int(datetime.utcnow().timestamp())
        },
        "authorization_response": {
            "location": cb_url,
            "params": cb_params
        },
        "callback_request": {},
        "token_response": {
            "json": {
                **({"id_token": id_token_val} if id_token_val else {}),
                **({"access_token": access_token_val} if access_token_val else {})
            }
        },
        "refresh_token_response": {"json": {}},
        "previous_nonces": []
    }

    # 5) 진단 실행
    res = checker.run_checks(flow_bundle)
    human = checker.pretty_report(res)

    # 6) 산출물 저장
    os.makedirs(args.outdir, exist_ok=True)
    flow_out = os.path.join(args.outdir, "flow_from_session.json")
    res_txt  = os.path.join(args.outdir, "nonce_check_result.txt")
    res_json = os.path.join(args.outdir, "nonce_check_result.json")

    with open(flow_out, "w", encoding="utf-8") as f:
        json.dump(flow_bundle, f, indent=2, ensure_ascii=False)
    with open(res_txt, "w", encoding="utf-8") as f:
        f.write(human)
    with open(res_json, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)

    print("[+] saved:", flow_out)
    print("[+] saved:", res_txt)
    print("[+] saved:", res_json)
    print("\n===== REPORT =====\n")
    print(human)

if __name__ == "__main__":
    main()

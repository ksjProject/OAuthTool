#!/usr/bin/env python3
# adapter_to_checker.py (clean rebuild)
# - session_token.json을 flow_bundle로 변환
# - oidc_nonce_checker.py 실행 및 결과 출력/저장(JSON 1개)

import json, argparse, urllib.parse, os
from datetime import datetime
import importlib.util as iu

# ===== Fixed paths (요청사항 반영) =====
DEFAULT_OUTPUT_DIR   = r"C:\Users\com\Desktop\OAuthTool\module_reports"
DEFAULT_DISCOVERY_DIR= r"C:\Users\com\Desktop\OAuthTool\discovery_artifacts"

def parse_q_and_fragment(url: str):
    if not url:
        return {}
    p = urllib.parse.urlparse(url)
    merged = {}
    for qs in (p.query, p.fragment):
        if not qs: 
            continue
        for k, v in urllib.parse.parse_qs(qs, keep_blank_values=True).items():
            if v: 
                merged[k] = v[0]
    return merged

def load_checker(checker_path: str):
    spec = iu.spec_from_file_location("oidc_nonce_checker", checker_path)
    mod = iu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def guess_auth_entries(tokens):
    hints = ["/authorize", "/protocol/openid-connect/auth", "/oauth2/v2/auth"]
    return [t for t in tokens if any(h in t.get("url","") for h in hints)]

def guess_callback_entries(tokens):
    hints = ["/callback", "/cb", "/signin-oidc", "/login/callback"]
    return [t for t in tokens if any(h in t.get("url","") for h in hints)]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("session_json", help="session_token.json 경로")
    ap.add_argument("--checker", default="./oidc_nonce_checker.py", help="진단 모듈 경로")
    _ = ap.parse_args()
    args = _

    # 1) 체크 모듈 로드
    checker = load_checker(args.checker)

    # 2) 세션 캡처 로드
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

    id_tokens = [t for t in oauth_tokens if t.get("key") == "id_token"]
    access_tokens = [t for t in oauth_tokens if t.get("key") == "access_token"]
    id_token_val = id_tokens[-1]["value"] if id_tokens else None
    access_token_val = access_tokens[-1]["value"] if access_tokens else None

    # 3.5) 디스커버리/JWKS 로드 (고정 경로)
    discovery, jwks = {}, {}
    try:
        with open(os.path.join(DEFAULT_DISCOVERY_DIR, "openid_configuration.json"), "r", encoding="utf-8") as f:
            discovery = json.load(f)
    except Exception:
        discovery = {}
    try:
        with open(os.path.join(DEFAULT_DISCOVERY_DIR, "jwks.json"), "r", encoding="utf-8") as f:
            jwks = json.load(f)
    except Exception:
        jwks = {}

    # 4) flow_bundle 구성
    flow_bundle = {
        "discovery": discovery,
        "jwks": jwks,
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
    res = checker.run_checks(flow_bundle) if hasattr(checker, "run_checks") else checker.run(flow_bundle)
    human = checker.pretty_report(res)

    # 6) 저장(JSON 한 개) + 콘솔 보고서
    os.makedirs(DEFAULT_OUTPUT_DIR, exist_ok=True)
    res_json = os.path.join(DEFAULT_OUTPUT_DIR, "nonce_check_result.json")
    with open(res_json, "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print(f"[+] saved: {res_json}")
    print("\n===== REPORT =====\n")
    print(human)

if __name__ == "__main__":
    main()

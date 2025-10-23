
#!/usr/bin/env python3
# adapter_to_checker.py (nonce-aware + discovery/JWKS pass-through if present)

import json, argparse, urllib.parse, base64, os, importlib.util
from datetime import datetime, timezone

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

def decode_b64url(part: str):
    if not part:
        return b""
    pad = '=' * ((4 - len(part) % 4) % 4)
    import base64
    return base64.urlsafe_b64decode((part + pad).encode())

def decode_jwt_header_payload(jwt: str):
    try:
        h, p, *_ = jwt.split(".")
        header = json.loads(decode_b64url(h).decode("utf-8", "ignore")) if h else {}
        payload = json.loads(decode_b64url(p).decode("utf-8", "ignore")) if p else {}
        return header, payload
    except Exception:
        return {}, {}

def load_checker(checker_path: str):
    spec = importlib.util.spec_from_file_location("oidc_nonce_checker", checker_path)
    mod = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod

def guess_auth_entries(tokens):
    hints = ["/authorize", "/protocol/openid-connect/auth", "/oauth2/v2/auth"]
    return [t for t in tokens if any(h in t.get("url","") for h in hints)]

def guess_callback_entries(tokens):
    hints = ["/callback", "/cb", "/signin-oidc", "/login/callback"]
    return [t for t in tokens if any(h in t.get("url","") for h in hints)]

def try_load(path):
    try:
        if path and os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        return None
    return None

def find_sidecars(session_json_path: str):
    d = os.path.dirname(os.path.abspath(session_json_path))
    cands = [
        os.path.join(d, "summary.json"),
        os.path.join(d, "openid_configuration.json"),
        os.path.join(d, "jwks.json"),
        "summary.json",
        "openid_configuration.json",
        "jwks.json",
    ]
    side = {"summary": None, "discovery": None, "jwks": None}
    for c in cands:
        if not os.path.exists(c): 
            continue
        try:
            data = json.load(open(c, "r", encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict):
            if side["summary"] is None and "discovery_core" in data:
                side["summary"] = data
            if side["discovery"] is None and "authorization_endpoint" in data:
                side["discovery"] = data
            if side["jwks"] is None and "keys" in data:
                side["jwks"] = data
    if side["discovery"] is None and side["summary"] and "discovery_core" in side["summary"]:
        side["discovery"] = side["summary"]["discovery_core"]
    return side

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("session_json")
    ap.add_argument("--checker", default="oidc_nonce_checker.py")
    ap.add_argument("--outdir", default="out")
    args = ap.parse_args()

    checker = load_checker(args.checker)

    with open(args.session_json, "r", encoding="utf-8") as f:
        sess = json.load(f)

    tokens = sess.get("oauth_tokens", [])
    # 1) Authorization request
    auth_entries = guess_auth_entries(tokens)
    auth_url = auth_entries[-1]["url"] if auth_entries else None
    # URL에서 우선 추출
    req_params = parse_q_and_fragment(auth_url) if auth_url else {}
    # Fallback: oauth_by_type.other에서 발견되는 키 병합
    for item in (sess.get("oauth_by_type", {}).get("other") or []):
        if item.get("url") and "/openid-connect/auth" in item["url"]:
            # url의 쿼리를 다시 merge
            req_params.update(parse_q_and_fragment(item["url"]))
    # Body/form이 있으면 병합
    for k in ("request_body", "body", "form"):
        if isinstance(sess.get(k), dict):
            for kk, vv in sess[k].items():
                if vv: req_params.setdefault(kk, vv)

    # 2) Callback (optional; 일부 케이스만)
    cb_entries = guess_callback_entries(tokens)
    cb_url = cb_entries[-1]["url"] if cb_entries else None
    cb_params = parse_q_and_fragment(cb_url) if cb_url else {}

    # 3) Tokens
    id_token_val = None
    for t in tokens:
        if t.get("key") == "id_token":
            id_token_val = t.get("value"); break
    if not id_token_val:
        # oauth_by_type Aggregates
        id_list = (sess.get("oauth_by_type", {}).get("id_token") or [])
        if id_list: id_token_val = id_list[-1].get("value")

    id_header, id_payload = ({}, {})
    if id_token_val:
        id_header, id_payload = decode_jwt_header_payload(id_token_val)

    # 4) Sidecars
    side = find_sidecars(args.session_json)
    discovery = side.get("discovery") or {}
    jwks = side.get("jwks") or {}

    # openid 스코프 플래그
    openid_scope = "openid" in (req_params.get("scope") or "").split()

    flow_bundle = {
        "discovery": discovery,
        "jwks": jwks,
        "authorization_request": {
            "url": auth_url,
            "params": req_params
        },
        "authorization_response": {
            "url": cb_url,
            "params": cb_params
        },
        "token": {
            "id_token": id_token_val,
            "id_token_header": id_header,
            "id_token_payload": id_payload
        },
        "previous_nonces": sess.get("previous_nonces") or [],
        "openid_scope": openid_scope,
        "flow": None
    }

    # 5) Run checker
    policy = sess.get("policy") or {"strict_code_nonce": True}
    res = checker.run(flow_bundle, policy=policy)

    # 6) Print & save
    human = checker.pretty_report(res)
    print(human)

    if args.outdir:
        os.makedirs(args.outdir, exist_ok=True)
        with open(os.path.join(args.outdir, "flow_from_session.json"), "w", encoding="utf-8") as f:
            json.dump(flow_bundle, f, indent=2, ensure_ascii=False)
        with open(os.path.join(args.outdir, "nonce_check_result.json"), "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2, ensure_ascii=False)
        with open(os.path.join(args.outdir, "nonce_check_result.txt"), "w", encoding="utf-8") as f:
            f.write(human)
        print("[+] saved:", os.path.join(args.outdir, "flow_from_session.json"))
        print("[+] saved:", os.path.join(args.outdir, "nonce_check_result.txt"))
        print("[+] saved:", os.path.join(args.outdir, "nonce_check_result.json"))

if __name__ == "__main__":
    main()

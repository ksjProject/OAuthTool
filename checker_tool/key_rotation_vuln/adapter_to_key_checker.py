#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# adapter_to_key_checker.py
# - session_token.json(네 캡처 형식)을 키 회전·JWKS 모듈 입력으로 변환
# - 변환 후 vuln_key_rotation_checker.py 실행

import json, argparse, os

def load_module(path, name="vuln_key_rotation_checker"):
    import importlib.util, sys
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod

def guess_discovery(sess: dict):
    disc = (sess.get("discovery") or {}) if isinstance(sess, dict) else {}
    return {"issuer": disc.get("issuer"), "jwks_uri": disc.get("jwks_uri")}

def guess_jwks(sess: dict, fallback_path: str=None):
    jwks = sess.get("jwks")
    if isinstance(jwks, dict) and jwks.get("keys"):
        return jwks
    if fallback_path and os.path.exists(fallback_path):
        with open(fallback_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"keys": []}

def guess_tokens(sess: dict):
    toks = {"id_token": None, "access_token": None, "client_assertion": None}
    arr = sess.get("oauth_tokens") or []
    for t in arr:
        k = t.get("key"); v = t.get("value")
        if k in ("id_token","access_token"):
            toks[k] = v
    if sess.get("client_assertion"):
        toks["client_assertion"] = sess.get("client_assertion")
    return toks

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("session_json", help="session_token.json 경로")
    ap.add_argument("--checker", default="./vuln_key_rotation_checker.py", help="진단 모듈 경로")
    ap.add_argument("--jwks", default=None, help="JWKS 스냅샷 파일(선택, session_json에 없을 때)")
    ap.add_argument("--outdir", default="./out", help="산출물 폴더")
    args = ap.parse_args()

    with open(args.session_json, "r", encoding="utf-8") as f:
        sess = json.load(f)

    checker = load_module(args.checker)

    payload = {
        "discovery": guess_discovery(sess),
        "as_metadata": sess.get("as_metadata") or {},
        "jwks": guess_jwks(sess, args.jwks),
        "client_registration": sess.get("client_registration") or {},
        "tokens": guess_tokens(sess)
    }

    os.makedirs(args.outdir, exist_ok=True)
    snapshot_path = os.path.join(args.outdir, "key_input_from_session.json")
    with open(snapshot_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    res = checker.run_checks(payload)
    human = checker.pretty_report(res)

    res_txt  = os.path.join(args.outdir, "key_rotation_check_result.txt")
    res_json = os.path.join(args.outdir, "key_rotation_check_result.json")
    with open(res_txt, "w", encoding="utf-8") as f: f.write(human)
    with open(res_json, "w", encoding="utf-8") as f: json.dump(res, f, indent=2, ensure_ascii=False)

    print("[+] saved:", snapshot_path)
    print("[+] saved:", res_txt)
    print("[+] saved:", res_json)
    print("\n===== REPORT =====\n")
    print(human)

if __name__ == "__main__":
    main()

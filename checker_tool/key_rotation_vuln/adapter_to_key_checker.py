
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# adapter_to_key_checker.py
# - session_token.json(네 캡처 형식)을 키 회전·JWKS 모듈 입력으로 변환
# - 같은 폴더의 openid_configuration.json / jwks.json 을 자동 참조
# - 변환 후 vuln_key_rotation_checker.py 실행 + 콘솔/파일 출력
import json, argparse, os, sys
from pathlib import Path

def load_module(path, name="vuln_key_rotation_checker"):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod

def safe_json_load(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def guess_discovery(sess: dict, base_dir: Path, explicit_path: str=None):
    # 1) --discovery 파일 우선
    if explicit_path:
        j = safe_json_load(explicit_path)
        if isinstance(j, dict):
            return {"issuer": j.get("issuer"), "jwks_uri": j.get("jwks_uri")}
    # 2) 세션에 포함되어 있으면 사용
    disc = (sess.get("discovery") or {}) if isinstance(sess, dict) else {}
    if disc.get("issuer") or disc.get("jwks_uri"):
        return {"issuer": disc.get("issuer"), "jwks_uri": disc.get("jwks_uri")}
    # 3) 같은 폴더의 openid_configuration.json 자동 로드
    j = safe_json_load(str(base_dir / "openid_configuration.json"))
    if isinstance(j, dict):
        return {"issuer": j.get("issuer"), "jwks_uri": j.get("jwks_uri")}
    # 4) summary.json에서 힌트 추출(있다면)
    s = safe_json_load(str(base_dir / "summary.json"))
    if isinstance(s, dict):
        return {"issuer": s.get("issuer_inferred"), "jwks_uri": s.get("jwks_url")}
    # 실패 시 빈 값
    return {"issuer": None, "jwks_uri": None}

def guess_jwks(sess: dict, base_dir: Path, explicit_path: str=None):
    # 1) --jwks 파일 우선
    if explicit_path:
        j = safe_json_load(explicit_path)
        if isinstance(j, dict) and isinstance(j.get("keys"), list):
            return j
    # 2) 세션에 포함되어 있으면 사용
    jwks = sess.get("jwks")
    if isinstance(jwks, dict) and isinstance(jwks.get("keys"), list):
        return jwks
    # 3) 같은 폴더의 jwks.json 자동 로드
    j = safe_json_load(str(base_dir / "jwks.json"))
    if isinstance(j, dict) and isinstance(j.get("keys"), list):
        return j
    # 실패 시 빈 값
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
    ap.add_argument("--discovery", default=None, help="(선택) openid_configuration.json 경로")
    ap.add_argument("--jwks", default=None, help="(선택) JWKS 스냅샷(jwks.json) 경로")
    ap.add_argument("--outdir", default="./out", help="산출물 폴더")
    args = ap.parse_args()

    session_path = Path(args.session_json).resolve()
    base_dir = session_path.parent

    with open(session_path, "r", encoding="utf-8") as f:
        sess = json.load(f)

    checker = load_module(args.checker)

    discovery = guess_discovery(sess, base_dir, args.discovery)
    jwks = guess_jwks(sess, base_dir, args.jwks)
    tokens = guess_tokens(sess)

    payload = {
        "discovery": discovery,
        "as_metadata": sess.get("as_metadata") or {},
        "jwks": jwks,
        "client_registration": sess.get("client_registration") or {},
        "tokens": tokens
    }

    os.makedirs(args.outdir, exist_ok=True)
    snapshot_path = Path(args.outdir) / "key_input_from_session.json"
    with open(snapshot_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    res = checker.run_checks(payload)
    human = checker.pretty_report(res)

    res_txt  = Path(args.outdir) / "key_rotation_check_result.txt"
    res_json = Path(args.outdir) / "key_rotation_check_result.json"
    with open(res_txt, "w", encoding="utf-8") as f: f.write(human)
    with open(res_json, "w", encoding="utf-8") as f: json.dump(res, f, indent=2, ensure_ascii=False)

    print("[+] saved:", str(snapshot_path))
    print("[+] saved:", str(res_txt))
    print("[+] saved:", str(res_json))
    print("\n===== REPORT =====\n")
    print(human)

if __name__ == "__main__":
    main()

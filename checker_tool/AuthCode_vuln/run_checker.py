
#!/usr/bin/env python3
# run_checker.py — KSJ15_vuln unified runner/adapter
# Default OUTDIR: <module_dir>\out  (so results sit next to the vuln module)
#
# Extras:
#  - --outdir "@module"  -> resolves to <module_dir>\out
#  - --outdir ".\out"    -> respects current working dir
#  - Auto-creates outdir before writing any files

import argparse, importlib.util, json, os, sys, urllib.parse
from datetime import datetime, timezone

def _load_module(module_path: str):
    spec = importlib.util.spec_from_file_location("vuln_module", module_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod

def _parse_q_and_fragment(url: str):
    if not url:
        return {}
    p = urllib.parse.urlparse(url)
    merged = {}
    for qs in (p.query, p.fragment):
        if not qs: continue
        for k, v in urllib.parse.parse_qs(qs, keep_blank_values=True).items():
            if v: merged[k] = v[0]
    return merged

def _guess_auth_entries(tokens):
    hints = ["/authorize", "/protocol/openid-connect/auth", "/oauth2/v2/auth"]
    return [t for t in tokens if any(h in (t.get("url","")) for h in hints)]

def _guess_callback_entries(tokens):
    hints = ["/callback", "/cb", "/signin-oidc", "/login/callback"]
    return [t for t in tokens if any(h in (t.get("url","")) for h in hints)]

def _normalize_from_session(session_json: dict) -> dict:
    oauth_tokens = session_json.get("oauth_tokens", [])

    auth_entries = _guess_auth_entries(oauth_tokens)
    auth_url = auth_entries[-1]["url"] if auth_entries else None
    auth_params = _parse_q_and_fragment(auth_url) if auth_url else {}

    cb_entries = _guess_callback_entries(oauth_tokens)
    cb_url = cb_entries[-1]["url"] if cb_entries else None
    cb_params = _parse_q_and_fragment(cb_url) if cb_url else {}

    token_req = session_json.get("token_request") or {}
    token_resp = session_json.get("token_response") or {}
    if not token_resp:
        id_tokens = [t for t in oauth_tokens if t.get("key")=="id_token"]
        access_tokens = [t for t in oauth_tokens if t.get("key")=="access_token"]
        id_token_val = id_tokens[-1]["value"] if id_tokens else None
        access_token_val = access_tokens[-1]["value"] if access_tokens else None
        token_resp = {"json": {}}
        if id_token_val: token_resp["json"]["id_token"] = id_token_val
        if access_token_val: token_resp["json"]["access_token"] = access_token_val

    flow_bundle = {
        "discovery": session_json.get("discovery") or {},
        "authorization_request": {
            "url": auth_url,
            "params": auth_params,
            "ts": int(datetime.now(timezone.utc).timestamp())
        },
        "authorization_response": {
            "location": cb_url,
            "params": cb_params
        },
        "callback_request": session_json.get("callback_request") or {},
        "token_request": token_req,
        "token_response": token_resp or {"json": {}},
        "refresh_token_response": session_json.get("refresh_token_response") or {"json": {}},
        "previous_nonces": session_json.get("previous_nonces") or []
    }
    return flow_bundle

def _maybe_to_markdown(mod, result: dict, pretty_text: str) -> str:
    to_md = getattr(mod, "to_markdown", None)
    if callable(to_md):
        try:
            return to_md(result)
        except Exception:
            pass
    escaped = pretty_text.replace("```", "\\`\\`\\`")
    return "```text\n" + escaped + "\n```"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input_json", help="session_token.json 또는 flow_bundle.json")
    ap.add_argument("--module", required=True, help="취약점 모듈 경로 (예: auth_code_theft_checker.py)")
    ap.add_argument("--outdir", default=None, help="산출물 폴더 (기본: 모듈 폴더\\out)")
    args = ap.parse_args()

    mod = _load_module(args.module)
    module_key = getattr(mod, "MODULE_KEY", os.path.splitext(os.path.basename(args.module))[0])

    # Resolve outdir
    module_dir = os.path.dirname(os.path.abspath(args.module))
    if args.outdir in (None, "", "@module"):
        outdir = os.path.join(module_dir, "out")
    else:
        outdir = args.outdir
        if not os.path.isabs(outdir):
            outdir = os.path.normpath(os.path.join(os.getcwd(), outdir))
    os.makedirs(outdir, exist_ok=True)

    with open(args.input_json, "r", encoding="utf-8") as f:
        data = json.load(f)

    is_session = ("authorization_request" not in data) and ("oauth_tokens" in data or "token_request" in data or "discovery" in data)
    if is_session:
        flow_bundle = _normalize_from_session(data)
        norm_path = os.path.join(outdir, "flow_from_session.json")
        with open(norm_path, "w", encoding="utf-8") as f:
            json.dump(flow_bundle, f, indent=2, ensure_ascii=False)
        print("[+] saved:", norm_path)
    else:
        flow_bundle = data

    result = mod.run_checks(flow_bundle)
    pretty = mod.pretty_report(result)
    md = _maybe_to_markdown(mod, result, pretty)

    txt_path = os.path.join(outdir, f"{module_key}_report.txt")
    json_path = os.path.join(outdir, f"{module_key}_report.json")
    md_path = os.path.join(outdir, f"{module_key}_report.md")

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(pretty)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md)

    print("[+] saved:", txt_path)
    print("[+] saved:", json_path)
    print("[+] saved:", md_path)
    print("\n====== REPORT ======\n")
    print(pretty)

if __name__ == "__main__":
    main()

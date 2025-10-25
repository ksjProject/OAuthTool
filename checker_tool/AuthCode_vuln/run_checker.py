#!/usr/bin/env python3
# run_checker.py — KSJ15_vuln unified runner/adapter (patched for custom discovery paths)
#
# - 기존 CLI 유지:  run_checker.py <input_json> --module <module.py> [--outdir OUT]
# - 추가 옵션:
#     --discovery-dir   (기본: C:\Users\com\Desktop\OAuthTool\discovery_artifacts)
#     --discovery-file  (기본: <discovery-dir>\openid_configuration.json)
#     --jwks-file       (기본: <discovery-dir>\jwks.json)
#     --single-json     (선택) 결과를 JSON 1개만 저장
#
# - 동작:
#   * 입력 JSON에 discovery가 없으면, 위 경로들에서 찾아서 주입.
#   * 기존과 동일하게 flow_from_session.json 생성(단, --single-json이면 생략하지 않음; 보고서만 단일화).
#   * 저장 위치는 --outdir. (미지정 시 모듈 폴더\out)

import argparse, importlib.util, json, os, sys, urllib.parse
from datetime import datetime, timezone

DEFAULT_DISCOVERY_DIR   = r"C:\Users\com\Desktop\OAuthTool\discovery_artifacts"
DEFAULT_DISCOVERY_FILE  = os.path.join(DEFAULT_DISCOVERY_DIR, "openid_configuration.json")
DEFAULT_JWKS_FILE       = os.path.join(DEFAULT_DISCOVERY_DIR, "jwks.json")

def _load_module(module_path: str):
    spec = importlib.util.spec_from_file_location("vuln_module", module_path)
    if not spec or not spec.loader:
        raise RuntimeError(f"Invalid module path: {module_path}")
    mod = importlib.util.module_from_spec(spec)
    # dataclasses 등에서 __module__ 조회 시 필요
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

def _try_load_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def _attach_discovery(flow_bundle: dict, sidecar_base: str, discovery_file: str, jwks_file: str):
    """입력에 discovery가 없으면, 우선순위대로 주입:
       1) --discovery-file 명시 경로
       2) 입력 JSON과 같은 폴더의 openid_configuration.json / summary.json
       3) --discovery-dir 기본 경로의 파일
    """
    if flow_bundle.get("discovery"):
        return flow_bundle

    # 1) 명시 파일
    disc = _try_load_json(discovery_file) if discovery_file else None

    # 2) 사이드카
    if not disc:
        for p in (os.path.join(sidecar_base, "openid_configuration.json"),
                  os.path.join(sidecar_base, "summary.json")):
            disc = _try_load_json(p)
            if disc:
                break

    # 3) 디폴트 디렉토리
    if not disc and DEFAULT_DISCOVERY_FILE:
        disc = _try_load_json(DEFAULT_DISCOVERY_FILE)

    if disc:
        flow_bundle["discovery"] = disc
        # JWKS는 참조용으로 discovery에 같이 보관
        jwks = _try_load_json(jwks_file) if jwks_file else None
        if not jwks and DEFAULT_JWKS_FILE:
            jwks = _try_load_json(DEFAULT_JWKS_FILE)
        if jwks:
            flow_bundle["discovery"]["_jwks_cached"] = jwks
    return flow_bundle

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
    ap.add_argument("input_json", help="session.token.json / session_token.json / flow_bundle.json")
    ap.add_argument("--module", required=True, help="취약점 모듈 경로 (예: auth_code_theft_checker.py)")
    ap.add_argument("--outdir", default=None, help="산출물 폴더 (기본: 모듈 폴더\\out)")
    # 새 옵션(경로 커스터마이즈)
    ap.add_argument("--discovery-dir", default=DEFAULT_DISCOVERY_DIR, help="디스커버리 파일 폴더")
    ap.add_argument("--discovery-file", default=None, help="명시적 openid_configuration.json 경로")
    ap.add_argument("--jwks-file", default=None, help="명시적 jwks.json 경로")
    # 선택: JSON만 저장하고 싶으면 사용
    ap.add_argument("--single-json", action="store_true", help="보고서를 JSON 1개만 저장")
    args = ap.parse_args()

    mod = _load_module(args.module)
    module_key = getattr(mod, "MODULE_KEY", os.path.splitext(os.path.basename(args.module))[0])

    # outdir 결정
    module_dir = os.path.dirname(os.path.abspath(args.module))
    if args.outdir in (None, "", "@module"):
        outdir = os.path.join(module_dir, "out")
    else:
        outdir = args.outdir
        if not os.path.isabs(outdir):
            outdir = os.path.normpath(os.path.join(os.getcwd(), outdir))
    os.makedirs(outdir, exist_ok=True)

    # 입력 로드
    with open(args.input_json, "r", encoding="utf-8") as f:
        data = json.load(f)
    # 정규화
    is_session = ("authorization_request" not in data) and ("oauth_tokens" in data or "token_request" in data or "discovery" in data)
    if is_session:
        flow_bundle = _normalize_from_session(data)
        norm_path = os.path.join(outdir, "flow_from_session.json")
        with open(norm_path, "w", encoding="utf-8") as f:
            json.dump(flow_bundle, f, indent=2, ensure_ascii=False)
        print("[+] saved:", norm_path)
    else:
        flow_bundle = data

    # discovery 주입 (신규 경로 적용)
    sidecar_base = os.path.dirname(os.path.abspath(args.input_json))
    discovery_file = args.discovery_file or os.path.join(args.discovery_dir, "openid_configuration.json")
    jwks_file = args.jwks_file or os.path.join(args.discovery_dir, "jwks.json")
    flow_bundle = _attach_discovery(flow_bundle, sidecar_base, discovery_file, jwks_file)

    # 모듈 실행
    result = mod.run_checks(flow_bundle)
    pretty = mod.pretty_report(result)
    md = _maybe_to_markdown(mod, result, pretty)

    # 저장
    json_path = os.path.join(outdir, f"{module_key}_report.json")
    txt_path  = os.path.join(outdir, f"{module_key}_report.txt")
    md_path   = os.path.join(outdir, f"{module_key}_report.md")

    if args.single_json:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print("[+] saved:", json_path)
    else:
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

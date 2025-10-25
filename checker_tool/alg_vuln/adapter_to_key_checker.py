#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 입력 경로 고정 + 결과 JSON 한 개만 저장 + 콘솔 리포트 출력

import json, os, importlib.util, datetime, sys
from pathlib import Path
from typing import Optional, Dict, Any

HERE = Path(__file__).resolve().parent            # ...\checker_tool\alg_vuln
ROOT = HERE.parent.parent                         # ...\OAuthTool

# === 기본 입력 경로(요청 반영) ===
DEFAULT_SESSION   = ROOT / "proxy_artifacts"      / "session_token.json"
DEFAULT_DISCOVERY = ROOT / "discovery_artifacts"  / "openid_configuration.json"
DEFAULT_JWKS      = ROOT / "discovery_artifacts"  / "jwks.json"

# === 출력(단일 파일) ===
DEFAULT_OUTDIR  = ROOT / "module_reports"
DEFAULT_OUTFILE = "alg_check_result.json"

def _load_json(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def _try_load(path: Path) -> Optional[Dict[str, Any]]:
    try:
        if path.exists():
            return _load_json(path)
    except Exception:
        pass
    return None

def prepare_flow_bundle_from_files(session_path: Optional[str|os.PathLike]=None,
                                   discovery_path: Optional[str|os.PathLike]=None,
                                   jwks_path: Optional[str|os.PathLike]=None) -> Dict[str, Any]:
    """세션+디스커버리+JWKS 병합해서 FlowBundle(dict) 작성."""
    session_p   = Path(session_path)   if session_path   else DEFAULT_SESSION
    discovery_p = Path(discovery_path) if discovery_path else DEFAULT_DISCOVERY
    jwks_p      = Path(jwks_path)      if jwks_path      else DEFAULT_JWKS

    flow = _load_json(session_p)
    disc = _try_load(discovery_p)
    if disc: flow["discovery"] = disc
    jwks = _try_load(jwks_p)
    if jwks: flow["jwks"] = jwks

    flow.setdefault("_meta", {})["ts"] = int(datetime.datetime.utcnow().timestamp())
    return flow

def _load_checker_module(path_or_none: Optional[str] = None):
    """vuln_alg_check.py 안전 로드 (dataclasses용 sys.modules 선등록)."""
    if not path_or_none:
        path_or_none = str(HERE / "vuln_alg_check.py")
    mod_name = "alg_vuln_checker_runtime"
    spec = importlib.util.spec_from_file_location(mod_name, path_or_none)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import checker module from: {path_or_none}")
    mod = importlib.util.module_from_spec(spec)  # type: ignore
    sys.modules[mod_name] = mod                  # ★ 선등록
    spec.loader.exec_module(mod)                 # type: ignore
    return mod

def run_alg_check(flow_bundle: Dict[str, Any],
                  checker_path: Optional[str] = None,
                  policy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    mod = _load_checker_module(checker_path)
    if hasattr(mod, "check_alg_vuln"):
        return mod.check_alg_vuln(flow_bundle, policy=policy)
    return mod.run_checks(flow_bundle)

def _write_json(path: Path, data: Dict[str, Any]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def main():
    import argparse
    ap = argparse.ArgumentParser(description="ALG vuln adapter (files→bundle→checker)")
    ap.add_argument("--session",   default=str(DEFAULT_SESSION),   help="session_token.json 경로")
    ap.add_argument("--discovery", default=str(DEFAULT_DISCOVERY), help="openid_configuration.json 경로")
    ap.add_argument("--jwks",      default=str(DEFAULT_JWKS),      help="jwks.json 경로")
    ap.add_argument("--checker",   default=str(HERE / "vuln_alg_check.py"), help="vuln_alg_check.py 경로")
    ap.add_argument("--outdir",    default=str(DEFAULT_OUTDIR),    help="출력 폴더(기본: module_reports)")
    # 정책 옵션(선택)
    ap.add_argument("--no-found", action="store_true", help="found_jwts 제외")
    ap.add_argument("--issuer",   default=None,        help="발급자(iss) 필터")
    args = ap.parse_args()

    flow = prepare_flow_bundle_from_files(args.session, args.discovery, args.jwks)
    policy = {"include_found": not args.no_found, "issuer_filter": args.issuer}

    # 검사 실행
    mod = _load_checker_module(args.checker)
    result = run_alg_check(flow, checker_path=args.checker, policy=policy)

    # 콘솔에 예쁜 리포트 출력
    report_txt = mod.pretty_report(result)
    print("\n===== REPORT =====\n")
    print(report_txt)

    # 단일 JSON 저장
    out_path = Path(args.outdir) / DEFAULT_OUTFILE
    _write_json(out_path, result)
    print(f"[OK] saved result → {out_path}")

if __name__ == "__main__":
    main()

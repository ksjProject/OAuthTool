#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
adapter_to_key_checker.py — KSJ15_vuln용 범용 어댑터 (discovery/JWKS 자동 병합)

사용법(alg_vuln 폴더에서):
  python .\adapter_to_key_checker.py ..\session_token.json ^
    --checker .\vuln_alg_check.py ^
    --outdir .\out ^
    --result-prefix alg_check_result

동작:
- <input_json>을 로드하고, 같은 폴더에 있으면 아래 파일을 자동 병합:
    openid_configuration.json -> raw["discovery"]
    jwks.json                 -> raw["jwks"]
    summary.json              -> raw["discovery_summary"]
- 병합된 dict을 체크 모듈(run_checks)에 전달
- 콘솔 리포트 + --outdir에 결과 3종 저장:
    1) flow_from_session.json
    2) <prefix>.txt
    3) <prefix>.json
"""
from __future__ import annotations
import argparse, importlib.util, json, os, sys
from datetime import datetime, timezone

def _load_json_if_exists(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None

def _merge_discovery(raw: dict, base_dir: str):
    oc_path = os.path.join(base_dir, "openid_configuration.json")
    jwks_path = os.path.join(base_dir, "jwks.json")
    summary_path = os.path.join(base_dir, "summary.json")

    oc = _load_json_if_exists(oc_path)
    jwks = _load_json_if_exists(jwks_path)
    summ = _load_json_if_exists(summary_path)

    merged = dict(raw)
    merged.setdefault("_meta", {})["base_dir"] = base_dir

    # discovery 병합(기존 값이 있으면 덮어쓰지 않음)
    if oc:
        if "discovery" not in merged or not isinstance(merged["discovery"], dict):
            merged["discovery"] = {}
        for k, v in oc.items():
            merged["discovery"].setdefault(k, v)

    if jwks:
        merged["jwks"] = jwks
    if summ:
        merged["discovery_summary"] = summ

    return merged, {"openid_configuration": bool(oc), "jwks": bool(jwks), "summary": bool(summ)}

def _load_module_from_path(path: str):
    spec = importlib.util.spec_from_file_location("ksj_checker_module", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load checker module from: {path}")
    mod = importlib.util.module_from_spec(spec)
    # dataclass 등 데코레이터용으로 모듈을 미리 등록
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod

def _pretty_fallback(result: dict) -> str:
    lines = []
    lines.append(f"Flow: {result.get('flow_type')}  Overall: {'PASS' if result.get('ok') else 'FAIL'}\n")
    for section_name in ("A", "B", "C"):
        sec = (result.get("checklist") or {}).get(section_name) or {}
        title = {"A": "A. Section", "B": "B. Section", "C": "C. Section"}[section_name]
        lines.append(f"== {title} ==")
        for k, v in sec.items():
            lines.append(f"- {k}: {v.get('result')}")
            if "observed" in v and v.get("observed") is not None:
                lines.append(f"  • {v.get('observed')}")
            if "note" in v and v.get("note") is not None:
                lines.append(f"  • {v.get('note')}")
        lines.append("")
    if result.get("failures"):
        lines.append("Failures:")
        for f in result["failures"]:
            lines.append(f" - [{f.get('code')}] {f.get('title')} :: {f.get('detail')} :: evidence={f.get('evidence')}")
        lines.append("")
    if result.get("warnings"):
        lines.append("Warnings:")
        for w in result["warnings"]:
            lines.append(f" - [{w.get('code')}] {w.get('title')} :: {w.get('detail')} :: evidence={w.get('evidence')}")
        lines.append("")
    return "\n".join(lines)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("input", help="session_token.json (or compatible)")
    p.add_argument("--checker", required=True, help="path to checker module (.py)")
    p.add_argument("--outdir", default="./out", help="output directory (default: ./out)")
    p.add_argument("--result-prefix", default=None, help="prefix for result files (default: derived from checker name)")
    args = p.parse_args()

    # 입력 + discovery 병합 (입력 JSON 파일이 있는 폴더 기준)
    with open(args.input, "r", encoding="utf-8") as f:
        raw = json.load(f)
    base_dir = os.path.abspath(os.path.dirname(args.input))
    merged, merged_flags = _merge_discovery(raw, base_dir)

    # 타임스탬프
    utc_now = datetime.now(timezone.utc)
    meta = {"UTC": utc_now.isoformat(), "ts": int(utc_now.timestamp()), "merged": merged_flags}

    # 출력 폴더
    os.makedirs(args.outdir, exist_ok=True)

    # 병합 입력 저장
    flow_path = os.path.join(args.outdir, "flow_from_session.json")
    with open(flow_path, "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "flow": merged}, f, ensure_ascii=False, indent=2, sort_keys=True)
    print(f"[+] saved: {os.path.relpath(flow_path)}")
    if any(merged_flags.values()):
        enabled = ", ".join([k for k, v in merged_flags.items() if v])
        print(f"[i] merged discovery files: {enabled}")

    # 체크 모듈 실행
    mod = _load_module_from_path(args.checker)
    if not hasattr(mod, "run_checks"):
        print("[!] Checker module has no run_checks(raw) function", file=sys.stderr)
        sys.exit(2)
    result = mod.run_checks(merged)

    # 리포트 출력/저장
    report_txt = mod.pretty_report(result) if hasattr(mod, "pretty_report") else _pretty_fallback(result)
    prefix = args.result_prefix or f"{os.path.splitext(os.path.basename(args.checker))[0]}_result"

    txt_path = os.path.join(args.outdir, f"{prefix}.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("===== REPORT =====\n\n")
        f.write(report_txt)
        if not report_txt.endswith("\n"):
            f.write("\n")
    print(f"[+] saved: {os.path.relpath(txt_path)}")

    json_path = os.path.join(args.outdir, f"{prefix}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2, sort_keys=True)
    print(f"[+] saved: {os.path.relpath(json_path)}")

    # 콘솔 미러
    print("\n===== REPORT =====\n")
    print(report_txt)

if __name__ == "__main__":
    main()

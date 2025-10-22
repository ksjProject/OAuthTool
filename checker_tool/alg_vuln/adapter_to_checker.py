
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
adapter_to_checker.py — Generic adapter to run any KSJ15_vuln checker module
Usage:
  python adapter_to_checker.py <input_json> --checker <path_to_checker.py> [--outdir .\\out] [--result-prefix <name>]

Behavior:
- Loads <input_json> (session snapshot) and passes it to checker's run_checks(raw_dict)
- Prints a console report exactly like the existing tools
- Saves three artifacts under --outdir:
    1) flow_from_session.json  (echo of input with meta timestamp)
    2) <prefix>.txt            (pretty text report)
    3) <prefix>.json           (raw result JSON)

Notes:
- The checker module must expose: run_checks(raw_dict) -> dict
- pretty_report(result) is optional; if missing, a minimal report is generated.
"""

from __future__ import annotations
import argparse, importlib.util, json, os, sys
from datetime import datetime, timezone

def _load_module_from_path(path: str):
    spec = importlib.util.spec_from_file_location("ksj_checker_module", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load checker module from: {path}")
    mod = importlib.util.module_from_spec(spec)
    # IMPORTANT: Register in sys.modules so decorators (e.g., dataclasses) can resolve module context.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod

def _pretty_fallback(result: dict) -> str:
    lines = []
    lines.append(f"Flow: {result.get('flow_type')}  Overall: {'PASS' if result.get('ok') else 'FAIL'}\n")
    for section_name in ("A","B","C"):
        sec = (result.get("checklist") or {}).get(section_name) or {}
        title = {"A":"A. Section","B":"B. Section","C":"C. Section"}[section_name]
        lines.append(f"== {title} ==")
        for k,v in sec.items():
            lines.append(f"- {k}: {v.get('result')}")
            if 'observed' in v: lines.append(f"  • {v.get('observed')}")
            if 'note' in v: lines.append(f"  • {v.get('note')}")
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

    with open(args.input, "r", encoding="utf-8") as f:
        raw = json.load(f)

    utc_now = datetime.now(timezone.utc)
    meta = {"UTC": utc_now.isoformat(), "ts": int(utc_now.timestamp())}

    os.makedirs(args.outdir, exist_ok=True)

    flow_path = os.path.join(args.outdir, "flow_from_session.json")
    to_save = {"meta": meta, "flow": raw}
    with open(flow_path, "w", encoding="utf-8") as f:
        json.dump(to_save, f, ensure_ascii=False, indent=2, sort_keys=True)
    print(f"[+] saved: {os.path.relpath(flow_path)}")

    mod = _load_module_from_path(args.checker)
    if not hasattr(mod, "run_checks"):
        print("[!] Checker module has no run_checks(raw) function", file=sys.stderr)
        sys.exit(2)

    result = mod.run_checks(raw)

    if hasattr(mod, "pretty_report"):
        report_txt = mod.pretty_report(result)
    else:
        report_txt = _pretty_fallback(result)

    if args.result_prefix:
        prefix = args.result_prefix
    else:
        base = os.path.splitext(os.path.basename(args.checker))[0]
        prefix = f"{base}_result"

    txt_path = os.path.join(args.outdir, f"{prefix}.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("===== REPORT =====\n\n")
        f.write(report_txt)
        if report_txt and not report_txt.endswith("\n"):
            f.write("\n")
    print(f"[+] saved: {os.path.relpath(txt_path)}")

    json_path = os.path.join(args.outdir, f"{prefix}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2, sort_keys=True)
    print(f"[+] saved: {os.path.relpath(json_path)}")

    print("\n===== REPORT =====\n")
    print(report_txt)

if __name__ == "__main__":
    main()

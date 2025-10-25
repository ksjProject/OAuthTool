#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OAuth Vulnerability Checker - 보고서 생성기 (NR 완전 제거, 한글/영문 표기 고정)
- check.txt: 자동 파싱(섹션/그룹/한글명(영문키)); HIGH/MID/LOW 접두는 무시
- module_reports: ./module_reports (하위 재귀 스캔)
- severity.txt: 기본 ./severity/severity.txt (없으면 전부 High)
- 출력: ./reports/OAuth_Report_YYYYMMDD_HHMMSS.html
- 브라우저 자동 오픈
- 대상 URL 옵션: --target 또는 --target-url
- Pass 비율: N/A 제외 (Pass / (Pass+Fail))
"""
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import json, re, argparse, webbrowser, sys

# =========================
# 파일 읽기 유틸
# =========================
def _read_text(path: Path) -> str:
    for enc in ("utf-8-sig", "utf-8", "cp949", "euc-kr"):
        try:
            return path.read_text(encoding=enc)
        except Exception:
            continue
    return path.read_text()

# =========================
# check.txt 파싱 (강화)
# =========================
CHECK_TXT_DEFAULT = "./check.txt"

# 항목 라인: (선택)SEV + 한글명 (영문키)  ← 괄호로 영문키를 식별
_RX_ITEM = re.compile(
    r'^\s*(?:(HIGH|MID|LOW)\s+)?(?P<title>.+?)\s*\((?P<key>[^)]+)\)\s*$',
    re.IGNORECASE
)

def _indent_level(line: str) -> int:
    """탭=1레벨, 4 spaces=1레벨. (들여쓰기 깨져도 아이템은 괄호로 판별)"""
    if not line:
        return 0
    leading = len(line) - len(line.lstrip(' \t'))
    tabs = len(line) - len(line.lstrip('\t'))
    spaces = leading - tabs
    return tabs + (spaces // 4)

def load_checks_from_checktxt(check_file: Path) -> list[dict]:
    """
    check.txt 포맷(유연 파싱):
    Section
        Group
            [HIGH|MID|LOW] 한글 취약점명 (EnglishKey)
    - 괄호가 있는 라인은 '항목'으로 간주 (들여쓰기 무시)
    - 괄호가 없고 0레벨이면 '섹션', 1+레벨이면 '그룹'으로 간주
    - 동일 영문키 중복 등장 시 최초 1개만 유지
    """
    if not check_file.exists():
        print(f"[WARN] check.txt가 보이지 않습니다: {check_file} → 산출물 키로 목록을 구성합니다.", file=sys.stderr)
        return []

    section = group = None
    items: list[dict] = []
    for raw in _read_text(check_file).splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if line.strip().startswith(("#","//")) or line.strip() == "...":
            continue

        # 1) 아이템(영문키가 괄호로 명시) 우선 판별
        m = _RX_ITEM.match(line.strip())
        if m:
            title_ko = m.group("title").strip()
            key = m.group("key").strip()
            # 빈 제목 방어: (혹시라도) 제목이 공백이면 key로 대체하지 말고 스킵
            if not title_ko:
                continue
            items.append({
                "section": section or "",
                "group": group or "",
                "title_ko": title_ko,
                "key": key
            })
            continue

        # 2) 아이템이 아니면 섹션/그룹
        lvl = _indent_level(line)
        text = line.strip()
        if lvl == 0:
            section = text
        else:
            group = text

    # 동일 key 중복 제거(최초 항목만 유지)
    dedup = {}
    for it in items:
        dedup.setdefault(it["key"], it)
    return list(dedup.values())

# =========================
# Severity(.txt) 로딩
# =========================
_SEV_CODE_MAP = {"HIGH":"High", "MID":"Middle", "LOW":"Low"}

def resolve_severity_file(user_supplied: str | Path | None) -> Path | None:
    if user_supplied:
        p = Path(user_supplied)
        if p.exists():
            return p
    p = Path("./severity/severity.txt")
    if p.exists():
        return p
    sev_dir = Path("./severity")
    if sev_dir.exists():
        for pat in ("severity*.txt", "*severity*.txt", "*.txt"):
            for cand in sorted(sev_dir.rglob(pat)):
                return cand
    return None

def load_severity_from_txt(severity_file: Path | None) -> dict:
    default = defaultdict(lambda: "High")  # 파일 없으면 전부 High
    if not severity_file or not severity_file.exists():
        return default
    text = _read_text(severity_file)
    m = {}
    rx = re.compile(r'^\s*(HIGH|MID|LOW)\s+(.+?)\s*\(([^)]+)\)\s*$', re.IGNORECASE)
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        mo = rx.match(line)
        if not mo:
            continue
        sev_raw, title_ko, _ = mo.groups()
        sev = _SEV_CODE_MAP.get(sev_raw.upper(), "High")
        m[title_ko.strip()] = sev
    if not m:
        return default
    out = defaultdict(lambda: "Low")
    out.update(m)
    return out

# =========================
# 키 정규화(불일치 보정)
# =========================
KEY_ALIAS_INCOMING_TO_CANON = {
    "redirect_uri_present": "redirect_uri_presence",
    "state_present": "state_presence",
    "token_resent_redirect_uri": "token_redirect_match",
    "token_redirect_uri_match": "token_redirect_match",
    "iss_in_response": "iss_in_authorization_response",
}
def _canon_key(k: str) -> str:
    if not k:
        return k
    return KEY_ALIAS_INCOMING_TO_CANON.get(k, k)

# =========================
# 모듈 산출물 파싱(재귀)
# =========================
def _norm_result(val: str) -> str:
    s = (val or "").strip().upper()
    if s in ("PASS", "OK", "TRUE"): return "Pass"
    if s in ("FAIL", "VULN", "FALSE"): return "Fail"
    if s in ("NA", "N/A", "NOT APPLICABLE", "UNKNOWN"): return "N/A"
    return "N/A"

def _extract_results(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    results = defaultdict(list)

    def add(key, res, note=None, observed=None, evidence=None):
        if not key: return
        key = _canon_key(key)
        results[key].append({
            "result": _norm_result(res),
            "note": (note or "").strip(),
            "observed": observed,
            "evidence": evidence,
            "source": path.name,
        })

    def walk(node):
        if isinstance(node, dict):
            grp = node.get("groups")
            if isinstance(grp, dict):
                for g in grp.values():
                    checks = g.get("checks")
                    if isinstance(checks, list):
                        for c in checks:
                            title = c.get("title") or c.get("id") or c.get("key")
                            res = c.get("result")
                            extra = []
                            if c.get("description"):    extra.append(str(c["description"]))
                            if c.get("recommendation"): extra.append("Recommendation: " + str(c["recommendation"]))
                            if c.get("full_title"):     extra.append("Full: " + str(c["full_title"]))
                            note = " | ".join(extra) if extra else None
                            add(title, res, note=note, observed=c.get("observed"), evidence=c.get("evidence"))

            cl = node.get("checklist")
            if isinstance(cl, dict):
                for cat in cl.values():
                    if isinstance(cat, dict):
                        for k, v in cat.items():
                            if isinstance(v, dict) and "result" in v:
                                add(k, v.get("result"), note=v.get("note"),
                                    observed=v.get("observed"), evidence=v.get("evidence"))

            for arr_key in ("failures", "warnings", "issues"):
                arr = node.get(arr_key)
                if isinstance(arr, list):
                    for it in arr:
                        key = it.get("code") or it.get("title") or ""
                        res = "Fail" if arr_key == "failures" else "N/A"
                        add(key, res, note=it.get("detail"), observed=it.get("observed"), evidence=it.get("evidence"))

            for k, v in node.items():
                if k not in ("groups", "checklist", "failures", "warnings", "issues"):
                    walk(v)
        elif isinstance(node, list):
            for x in node:
                walk(x)

    walk(data)
    return results

# =========================
# HTML 빌드
# =========================
def _build_html(rows, summary):
    def esc(s):
        import html
        if s is None: return ""
        return html.escape(str(s))

    def pill_result(res):
        cls = "fail" if res=="Fail" else ("pass" if res=="Pass" else "na")
        return f'<span class="pill"><span class="dot {cls}"></span> {res}</span>'

    def sev_badge(sv):
        cls = {"High":"high","Middle":"mid","Low":"low"}.get(sv,"low")
        return f'<span class="sev {cls}">{sv}</span>'

    tr_html = []
    for r in rows:
        # ← 한글명 왼쪽 · 영문키는 오른쪽 태그로
        vuln = f'<div class="row-badge"><span class="nowrap">{esc(r["title_ko"])}</span>'
        if r["key"]:
            vuln += f' <span class="tag">{esc(r["key"])}</span>'
        vuln += '</div>'
        note = esc(r["notes"]) if r["notes"] else '<span class="muted">—</span>'
        tr_html.append(f"""
        <tr data-result="{esc(r['result'])}">
          <td>{vuln}</td>
          <td>{pill_result(r["result"])}</td>
          <td>{sev_badge(r["severity"])}</td>
          <td class="wrap">{note}</td>
        </tr>""")

    card_html = []
    for r in [x for x in rows if x["result"]=="Fail"]:
        ev_parts = []
        for ev in r["evidences"]:
            if ev is None: continue
            if isinstance(ev, (dict, list)):
                ev_parts.append(f'<div class="evidence">{esc(json.dumps(ev, ensure_ascii=False, indent=2))}</div>')
            else:
                ev_parts.append(f'<div class="evidence">{esc(ev)}</div>')
        src_html = ("<div class='muted'>출처: " + ", ".join(esc(s) for s in r["sources"]) + "</div>") if r["sources"] else ""
        card_html.append(f"""
        <div class="finding">
          <h4 class="wrap">{esc(r["title_ko"])}{' ' + f"<span class='tag'>{esc(r['key'])}</span>" if r['key'] else ''}</h4>
          <div class="meta">
            <span class="pill">결과: {pill_result(r["result"])}</span>
            <span class="pill">위험도: {sev_badge(r["severity"])}</span>
            <span class="pill">분류: {esc(r["section"])} / {esc(r["group"])}</span>
          </div>
          {('<p class="wrap">'+esc(r["notes"])+'</p>') if r["notes"] else ""}
          {''.join(ev_parts)}
          {src_html}
        </div>""")

    return f"""<!doctype html>
<html lang="ko"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>OAuth Vulnerability Checker - 최종 보고서</title>
<style>
:root{{ --bg:#0b0c10; --panel:#12131a; --panel-2:#161823; --text:#e7e9ee; --muted:#a7adbd; --border:#2a2f3a; --accent:#6ea8fe; --pass:#22c55e; --fail:#ef4444; --na:#9aa4b2; --high:#ef4444; --mid:#f59e0b; --low:#22c55e; --chip-bg:#1c1f2b; }}
@media (prefers-color-scheme: light){{ :root{{ --bg:#f7f8fa; --panel:#fff; --panel-2:#f3f4f7; --text:#0b0c10; --muted:#556070; --border:#e3e6ee; --chip-bg:#eef2ff; }} }}
*{{ box-sizing:border-box; }}
html,body{{ margin:0; padding:0; background:var(--bg); color:var(--text); font-family: system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,Helvetica Neue,Arial; }}
header{{ position:sticky; top:0; z-index:10; backdrop-filter: blur(6px); background: color-mix(in oklab, var(--bg), transparent 35%); border-bottom:1px solid var(--border);}}
.container{{ max-width:1100px; margin:0 auto; padding:20px; }}
.topbar{{ display:flex; align-items:center; justify-content:space-between; gap:16px; padding:10px 0; }}
.brand{{ display:flex; gap:12px; align-items:center; font-weight:800; letter-spacing:.2px; }}
.logo{{ width:28px; height:28px; border-radius:8px; display:inline-grid; place-items:center; background:linear-gradient(135deg, var(--accent), #a78bfa); color:white; font-size:16px; }}
.actions button{{ background: var(--panel); color:var(--text); border:1px solid var(--border); padding:8px 12px; border-radius:10px; cursor:pointer; font-weight:600; }}

.grid{{ display:grid; gap:16px; grid-template-columns: 1.2fr .8fr; }}
.card{{ background:var(--panel); border:1px solid var(--border); border-radius:16px; padding:16px; }}

.muted{{ color:var(--muted); font-size:.95rem; }}
.kv{{ display:grid; grid-template-columns: 160px 1fr; gap:10px 14px; }}

.pill{{ display:inline-flex; align-items:center; gap:8px; padding:6px 10px; border-radius:999px; background:var(--chip-bg); border:1px solid var(--border); }}
.dot{{ width:10px; height:10px; border-radius:50%; display:inline-block; }}
.dot.pass{{ background:var(--pass); }} .dot.fail{{ background:var(--fail); }} .dot.na{{ background:var(--na); }}

.sev{{ font-weight:700; padding:2px 8px; border-radius:8px; border:1px solid var(--border); }}
.sev.high{{ color:var(--high);}} .sev.mid{{ color:var(--mid);}} .sev.low{{ color:var(--low);}}

/* 표 & 텍스트 넘침 방지 */
.table{{ width:100%; border-collapse: collapse; table-layout: fixed; }}
.table th,.table td{{ border-bottom:1px solid var(--border); padding:10px 8px; text-align:left; vertical-align: top; }}
.table th,.table td{{ word-break: break-word; overflow-wrap:anywhere; }}
.table th{{ font-size:.9rem; color:var(--muted); font-weight:700; }}
.row-badge{{ display:inline-flex; align-items:center; gap:8px; max-width:100%; }}
.row-badge .nowrap{{ overflow-wrap:anywhere; word-break: break-word; }}
.tag{{ font-size:.8rem; color:var(--muted); border:1px solid var(--border); border-radius:8px; padding:2px 6px; white-space:nowrap; }}

.summary{{ display:grid; grid-template-columns: repeat(4,1fr); gap:12px; }}
.kpi{{ background:var(--panel-2); border:1px solid var(--border); border-radius:14px; padding:12px; display:flex; flex-direction:column; gap:4px; }}
.kpi .num{{ font-size:1.6rem; font-weight:800; }}
.bar{{ height:10px; background:var(--panel); border:1px solid var(--border); border-radius:999px; overflow:hidden; }}
.bar > div{{ height:100%; background: linear-gradient(90deg, var(--fail), #f97316, var(--pass)); width:{summary['pct_pass']}%; }}

.finding{{ border:1px solid var(--border); border-radius:14px; padding:14px; background:var(--panel); }}
.finding + .finding{{ margin-top:12px; }}
.meta{{ display:flex; gap:10px; flex-wrap:wrap; }}
.evidence{{ background:var(--panel-2); border:1px solid var(--border); border-radius:12px; padding:10px;
           white-space:pre-wrap; overflow-wrap:anywhere; word-break: break-word;
           font-family: ui-monospace, Menlo, Consolas, "Liberation Mono", monospace; font-size:.85rem; }}
.wrap{{ overflow_wrap:anywhere; word-break: break-word; }}

.foot{{ margin-top:20px; color:var(--muted); font-size:.9rem; }}
@media print{{ header{{ position:static; }} .container{{ padding:0; }} .card,.finding{{ break-inside: avoid; }} }}
</style>
</head>
<body>
<header>
  <div class="container topbar">
    <div class="brand">
      <div class="logo">🔍</div>
      <div>OAuth Vulnerability Checker</div>
    </div>
    <div class="actions"><button onclick="window.print()">인쇄 / PDF 저장</button></div>
  </div>
</header>
<main class="container">
  <div class="grid">
    <section class="card">
      <h3>리포트 메타</h3>
      <div class="kv" style="margin-top:10px;">
        <div class="muted">프로젝트</div><div>{esc(summary['project'])}</div>
        <div class="muted">대상(서비스/RP)</div><div>{esc(summary['target'])}</div>
        <div class="muted">점검 일시</div><div>{esc(summary['now'])}</div>
      </div>
    </section>
    <section class="card">
      <h3>요약</h3>
      <div class="summary" style="margin-top:8px;">
        <div class="kpi"><div class="muted">총 항목(집계)</div><div class="num">{summary['total_rows']}</div></div>
        <div class="kpi"><div class="muted">실패(Fail)</div><div class="num">{summary['fail']}</div></div>
        <div class="kpi"><div class="muted">통과(Pass)</div><div class="num">{summary['pass']}</div></div>
        <div class="kpi"><div class="muted">N/A</div><div class="num">{summary['na']}</div></div>
      </div>
      <div class="bar" style="margin-top:10px;"><div></div></div>
      <div class="muted" style="margin-top:6px;">Pass 비율 (N/A 제외): {summary['pct_pass']}%</div>
    </section>
  </div>
  <section class="card" style="margin-top:16px;">
    <h3>점검 결과 목록</h3>
    <table class="table" style="margin-top:6px;">
      <thead>
        <tr>
          <th style="width:52%;">Vulnerability (취약점)</th>
          <th style="width:14%;">결과</th>
          <th style="width:12%;">위험도</th>
          <th>비고</th>
        </tr>
      </thead>
      <tbody>
        {''.join(tr_html)}
      </tbody>
    </table>
  </section>
  <section class="card" style="margin-top:16px;">
    <h3>세부 내역 (Fail만)</h3>
    {''.join(card_html) if card_html else '<div class="muted">Fail 항목이 없습니다.</div>'}
  </section>
  <div class="foot">
    <div>※ Pass 비율은 N/A를 제외한 항목(통과+실패) 기준으로 계산합니다.</div>
  </div>
</main>
</body></html>"""

# =========================
# 집계 + 파일 출력 + 브라우저
# =========================
def _dedup_keep_order(seq, keyfunc=lambda x: x):
    seen=set(); out=[]
    for x in seq:
        k=keyfunc(x)
        if k in seen: continue
        seen.add(k); out.append(x)
    return out

def _norm_text(s: str) -> str:
    if s is None: return ""
    s = str(s).replace("\r\n","\n").strip()
    s = re.sub(r"\s+"," ", s)
    return s

def _norm_evidence(ev) -> str:
    if ev is None: return ""
    if isinstance(ev,(dict,list)):
        try: s=json.dumps(ev, ensure_ascii=False, sort_keys=True)
        except Exception: s=str(ev)
    else:
        s=str(ev)
    s=s.replace("\r\n","\n").strip()
    s=re.sub(r"\s+"," ", s)
    return s

def _compute_rows_and_summary(check_items: list[dict], modules_dir: Path, severity_map: dict, project: str, target: str):
    inputs = [p for p in Path(modules_dir).rglob("*.json") if p.is_file()]
    gathered = defaultdict(list)
    for p in inputs:
        for k, lst in _extract_results(p).items():
            gathered[k].extend(lst)

    ORDER = {"Fail":3, "Pass":2, "N/A":1}

    rows = []
    pass_count = fail_count = na_count = 0

    # ⭐ NR 제거: 실제로 보고된 키만 포함
    for item in check_items:
        key = item.get("key")
        if not key:  # 방어
            continue
        per_key = gathered.get(_canon_key(key), [])
        if not per_key:
            continue  # NR 완전 제외

        title_ko = item.get("title_ko") or key  # 한글명 확보
        worst = max(per_key, key=lambda x: ORDER.get(x["result"], 0))
        result = worst["result"]

        notes_raw = [x.get("note","") for x in per_key if x.get("note")]
        notes = _dedup_keep_order(notes_raw, keyfunc=_norm_text)

        evid_raw=[]
        for x in per_key:
            if x.get("evidence") is not None: evid_raw.append(x.get("evidence"))
            if x.get("observed") not in (None,"",{},[]): evid_raw.append(x.get("observed"))
        evidences = _dedup_keep_order(evid_raw, keyfunc=_norm_evidence)

        if not notes and evidences:
            notes = ["세부 내용은 Evidence 참조."]

        sources = sorted({x["source"] for x in per_key if x.get("source")})
        severity = severity_map[title_ko]  # severity.txt 없으면 High

        if result == "Pass": pass_count += 1
        elif result == "Fail": fail_count += 1
        else: na_count += 1

        rows.append({
            "key": key,
            "title_ko": title_ko,
            "result": result,
            "severity": severity,
            "notes": "; ".join(notes) if notes else "",
            "evidences": evidences,
            "sources": sources,
            "section": item.get("section",""),
            "group": item.get("group",""),
        })

    considered = pass_count + fail_count
    pct_pass = round((pass_count/considered)*100, 1) if considered else 0.0
    summary = {
        "project": project,
        "target": target,
        "now": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "pass": pass_count,
        "fail": fail_count,
        "na": na_count,
        "pct_pass": pct_pass,
        "total_rows": len(rows),
    }
    return rows, summary

def generate_report(
    project: str = "KSJ OAuth 취약점 점검",
    target: str = "https://example.com",
    modules_dir: str | Path = "./module_reports",
    check_file: str | Path = CHECK_TXT_DEFAULT,
    severity_file: str | Path | None = None,
    out_dir: str | Path = "./reports",
    open_browser: bool = True
):
    modules_dir = Path(modules_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    check_items = load_checks_from_checktxt(Path(check_file))
    # check.txt가 비어있다면 (진짜로 못 읽었거나 포맷 이슈) → 산출물 키 기반으로 보이게 (이때 한글명=키)
    if not check_items:
        # gathered 키를 만들기 위해 한 번 스캔
        gathered_keys = set()
        for p in Path(modules_dir).rglob("*.json"):
            for k in _extract_results(p).keys():
                gathered_keys.add(k)
        check_items = [{"section":"", "group":"", "title_ko": k, "key": k} for k in sorted(gathered_keys)]

    sev_path = resolve_severity_file(severity_file)
    severity_map = load_severity_from_txt(sev_path)

    rows, summary = _compute_rows_and_summary(check_items, modules_dir, severity_map, project, target)
    out_file = out_dir / f"OAuth_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    html = _build_html(rows, summary)
    out_file.write_text(html, encoding="utf-8")

    if open_browser:
        try:
            webbrowser.open_new_tab(out_file.resolve().as_uri())
        except Exception:
            pass

    return out_file, summary

# =========================
# CLI
# =========================
if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="OAuth Vulnerability Checker - 보고서 생성기")
    ap.add_argument("--project", default="KSJ OAuth 취약점 점검", help="프로젝트명")
    ap.add_argument("--target", "--target-url", dest="target", default="https://example.com", help="대상(서비스/RP) URL")
    ap.add_argument("--modules-dir", default="./module_reports", help="진단 모듈 산출물 JSON 폴더(재귀)")
    ap.add_argument("--check-file", default=CHECK_TXT_DEFAULT, help="check.txt 경로 (기본: ./check.txt)")
    ap.add_argument("--severity-file", default=None, help="severity.txt 경로 (기본: ./severity/severity.txt 자동 탐색)")
    ap.add_argument("--out-dir", default="./reports", help="보고서 출력 폴더")
    args = ap.parse_args()

    out, summary = generate_report(
        project=args.project,
        target=args.target,
        modules_dir=args.modules_dir,
        check_file=args.check_file,
        severity_file=args.severity_file,
        out_dir=args.out_dir,
        open_browser=True
    )
    print("✔ 보고서 생성:", out)
    print("   Target:", summary["target"])
    print("   Pass:", summary["pass"], "Fail:", summary["fail"], "N/A:", summary["na"],
          "총 표기 항목:", summary["total_rows"], "Pass%:", summary["pct_pass"])

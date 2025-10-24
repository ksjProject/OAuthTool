#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OAuth Vulnerability Checker - 자동 스캔 보고서 생성기 (severity.txt 기반, 증거/비고 중복 제거)
- severity.txt: 기본 ./severity/severity.txt (없으면 전체 High)
- module_reports: ./module_reports (재귀 스캔)
- 보고서: ./reports/OAuth_Report_YYYYMMDD_HHMMSS.html
- 브라우저는 기본 자동 오픈
- 대상 URL은 옵션으로 입력 (--target 또는 --target-url)
"""
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import json, re, webbrowser, argparse

# ===== check.txt 기반 하드코딩 항목 (누락 없이) =====
CHECK_ITEMS = [
  {"section":"Client Secret","group":"Client Secret","title_ko":"URL에 클라이언트 시크릿 노출 여부 검사","key":"Client Secret Query"},
  {"section":"Client Secret","group":"Client Secret","title_ko":"Referer 헤더 내 클라이언트 시크릿 포함 여부 검사","key":"Client Secret Referer"},
  {"section":"Client Secret","group":"Client Secret","title_ko":"클라이언트 시크릿 전송 시 https 사용 확인","key":"Token Body Secret"},
  {"section":"Client Secret","group":"Client Secret","title_ko":"세션 및 토큰 내 클라이언트 시크릿 존재 검사","key":"Session token secret"},

  {"section":"STATE","group":"STATE","title_ko":"인가 요청 내 STATE 존재 확인","key":"State Missing"},
  {"section":"STATE","group":"STATE","title_ko":"STATE 엔트로피 검증","key":"State Low Entropy"},
  {"section":"STATE","group":"STATE","title_ko":"인가 요청시 STATE 재사용 가능 여부 검사","key":"State Reuse"},
  {"section":"STATE","group":"STATE","title_ko":"콜백 STATE 누락 검사","key":"Callback State Missing"},
  {"section":"STATE","group":"STATE","title_ko":"콜백 STATE 불일치 검사","key":"Callback State Mismatch"},

  {"section":"Scope","group":"Scope 처리","title_ko":"인가 요청 중 과도한 혹은 민감한 스코프 감지","key":"Risky Scope"},
  {"section":"Scope","group":"Scope 처리","title_ko":"최소권한 원칙 준수 확인","key":"Least Privilege"},

  {"section":"OIDC nonce","group":"Authorization Redirect","title_ko":"https 사용 확인","key":"redirect_uri_safety"},
  {"section":"OIDC nonce","group":"Authorization Redirect","title_ko":"get 방식 사용 검사","key":"form_post_used"},
  {"section":"OIDC nonce","group":"Authorization Redirect","title_ko":"인가코드 응답에 iss 사용 확인","key":"iss_in_authorization_response"},
  {"section":"OIDC nonce","group":"Authorization Redirect","title_ko":"iss 값, discovery와 매치 확인","key":"state_presence"},

  {"section":"OIDC nonce","group":"PKCE & token binding","title_ko":"PKCE 의 S256 (이상) 사용 확인","key":"pkce_s256_in_request"},
  {"section":"OIDC nonce","group":"PKCE & token binding","title_ko":"PKCE 사용 시, 토큰 코드검증 여부 확인","key":"token_has_code_verifier"},

  {"section":"OIDC nonce","group":"Leakage & hardening","title_ko":"프론트 채널 인가코드 노출 검사","key":"front_channel_leak_risk"},
  {"section":"OIDC nonce","group":"Leakage & hardening","title_ko":"referer 노출 검사","key":"referer_leak_risk"},
  {"section":"OIDC nonce","group":"Leakage & hardening","title_ko":"jar par 사용여부 검사","key":"jar_par_usage"},

  {"section":"OIDC nonce","group":"Authorize 요청","title_ko":"nonce 존재 확인","key":"nonce_used_in_codeflow"},
  {"section":"OIDC nonce","group":"Authorize 요청","title_ko":"nonce 엔트로피/신선도 검증","key":"nonce_entropy_freshness"},

  {"section":"OIDC nonce","group":"ID Token","title_ko":"요청에 nonce 존재 시, ID Token nonce 포함 확인","key":"id_token_must_include_nonce_if_requested"},
  {"section":"OIDC nonce","group":"ID Token","title_ko":"ID Token 의 iss, aud, exp 유효성 검사","key":"iss_aud_exp_valid"},

  {"section":"Authorization Code","group":"Authorization Endpoint","title_ko":"인가요청에 response_type=code 확인","key":"response_type_code"},
  {"section":"Authorization Code","group":"Authorization Endpoint","title_ko":"인가요청에 scope 존재 확인","key":"scope_presence"},
  {"section":"Authorization Code","group":"Authorization Endpoint","title_ko":"인가요청에 client_id 존재 확인","key":"client_id_presence"},
  {"section":"Authorization Code","group":"Authorization Endpoint","title_ko":"인가요청에 redirect_uri 존재 확인","key":"redirect_uri_presence"},
  {"section":"Authorization Code","group":"Authorization Endpoint","title_ko":"인가요청에 state 존재 확인","key":"state_presence"},
  {"section":"Authorization Code","group":"Authorization Endpoint","title_ko":"인가코드 응답의 code 파라미터 존재 확인","key":"code_presence"},
  {"section":"Authorization Code","group":"Authorization Endpoint","title_ko":"인가코드 응답이 HTTPS 로 전달 확인","key":"https_callback"},

  {"section":"Authorization Code","group":"Token Endpoint","title_ko":"인가코드 교환 시 grant_type=authorization_code 확인","key":"grant_type_auth_code"},
  {"section":"Authorization Code","group":"Token Endpoint","title_ko":"인가코드 교환 시 client_id 존재 확인","key":"token_client_id_presence"},
  {"section":"Authorization Code","group":"Token Endpoint","title_ko":"인가코드 교환 시 client_secret 존재 여부 검사","key":"token_client_secret_presence"},
  {"section":"Authorization Code","group":"Token Endpoint","title_ko":"인가코드 교환 시 redirect_uri 일치 확인","key":"token_redirect_match"},
  {"section":"Authorization Code","group":"Token Endpoint","title_ko":"인가코드 교환 시 code 정상성 검사","key":"token_code_valid"},

  {"section":"Token","group":"ID Token","title_ko":"iss 값, discovery와 매치 확인","key":"iss_matches_discovery"},
  {"section":"Token","group":"ID Token","title_ko":"aud 에 클라이언트가 포함되는지 확인","key":"aud_includes_client"},
  {"section":"Token","group":"ID Token","title_ko":"alg 가 discovery 내 지원 알고리즘인지 확인","key":"alg_supported_by_discovery"},
  {"section":"Token","group":"ID Token","title_ko":"kid 가 discovery JWKS 내 존재 확인","key":"kid_found_in_jwks"},

  {"section":"Key Rotation & JWKS","group":"Resource Server","title_ko":"액세스토큰 내 KID, JWKS 키 일치 여부 확인","key":"kid_known_access_token"},
  {"section":"Key Rotation & JWKS","group":"Resource Server","title_ko":"액세스토큰 KID 용도 검사","key":"kid_use_sig_access_token"},
  {"section":"Key Rotation & JWKS","group":"Resource Server","title_ko":"액세스토큰 헤더의 외부키 참조 금지 여부 확인","key":"header_external_ref_access_token"},
  {"section":"Key Rotation & JWKS","group":"Resource Server","title_ko":"액세스토큰 KID 패턴 확인","key":"kid_pattern_access_token"},

  {"section":"Key Rotation & JWKS","group":"RS 설정","title_ko":"RS 가 JWKS 캐시 TTL 관리 여부 확인","key":"rs_jwks_cache_ttl"},
  {"section":"Key Rotation & JWKS","group":"RS 설정","title_ko":"RS 가 키 롤오버 전략 수립 여부 확인","key":"rs_key_rollover_plan"},

  {"section":"Key Rotation & JWKS","group":"보안 테스트","title_ko":"알려지지 않은 KID 주입 공격","key":"inject_unknown_kid"},
  {"section":"Key Rotation & JWKS","group":"보안 테스트","title_ko":"헤더 인젝션 공격","key":"header_injection_fields_seen"},
  {"section":"Key Rotation & JWKS","group":"보안 테스트","title_ko":"HS RS 변경 공격","key":"hs_rs_switch"},
  {"section":"Key Rotation & JWKS","group":"보안 테스트","title_ko":"KID Traversal","key":"kid_traversal"}
]

# -----------------------
# 공통 유틸 (중복 제거용)
# -----------------------
def _dedup_keep_order(seq, keyfunc=lambda x: x):
    seen = set()
    out = []
    for x in seq:
        k = keyfunc(x)
        if k in seen:
            continue
        seen.add(k)
        out.append(x)
    return out

def _norm_text(s: str) -> str:
    if s is None: return ""
    s = str(s).replace("\r\n", "\n").strip()
    s = re.sub(r"\s+", " ", s)
    return s

def _norm_evidence(ev) -> str:
    if ev is None: return ""
    if isinstance(ev, (dict, list)):
        try:
            s = json.dumps(ev, ensure_ascii=False, sort_keys=True)
        except Exception:
            s = str(ev)
    else:
        s = str(ev)
    s = s.replace("\r\n", "\n").strip()
    s = re.sub(r"\s+", " ", s)
    return s

# -----------------------
# Severity (.txt) 로딩
# -----------------------
_SEV_CODE_MAP = {"HIGH":"High", "MID":"Middle", "LOW":"Low"}

def _read_text(path: Path) -> str:
    for enc in ("utf-8-sig", "utf-8", "cp949", "euc-kr"):
        try:
            return path.read_text(encoding=enc)
        except Exception:
            continue
    return path.read_text()

def load_severity_from_txt(severity_file: Path | None) -> dict:
    """
    severity.txt 포맷:
      HIGH    한글 취약점명 (EnglishKey)
      MID     ...
      LOW     ...
    결과 키는 '한글 취약점명' 기준으로 반환
    """
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
        sev_raw, title_ko, eng_key = mo.groups()
        sev = _SEV_CODE_MAP.get(sev_raw.upper(), "High")
        m[title_ko.strip()] = sev
        # 필요 시 영어 키도 동일 세버리티로: m[eng_key.strip()] = sev
    if not m:
        return default
    out = defaultdict(lambda: "Low")
    out.update(m)
    return out

def resolve_severity_file(user_supplied: str | Path | None) -> Path | None:
    """
    우선순위:
    1) 사용자가 넘긴 severity.txt 경로
    2) ./severity/severity.txt
    3) ./severity/ 하위 *.txt 중 'severity' 패턴 우선
    4) 없으면 None (→ 전체 High)
    """
    if user_supplied:
        p = Path(user_supplied)
        if p.exists():
            return p

    p = Path("./severity/severity.txt")
    if p.exists():
        return p

    sev_dir = Path("./severity")
    if sev_dir.exists():
        patterns = ["severity*.txt", "*severity*.txt", "*.txt"]
        for pat in patterns:
            for cand in sorted(sev_dir.rglob(pat)):
                return cand

    return None  # None이면 전체 High

# -----------------------
# 모듈 산출물 파싱 (재귀형)
# -----------------------
def _norm_result(val: str) -> str:
    s = (val or "").strip().upper()
    if s in ("PASS", "OK", "TRUE"): return "Pass"
    if s in ("FAIL", "VULN", "FALSE"): return "Fail"
    return "N/A"

def _extract_results(path: Path):
    """
    어디에 있든 다음 패턴을 모두 수집:
      - groups.*.checks[]   → title/result/description/evidence
      - (중첩 허용) checklist → 각 항목 result/note/observed/evidence
      - (중첩 허용) failures/warnings/issues 배열 → code/title/detail/evidence
    key 매핑:
      - checks[].title (또는 id/key) → 예: "Client Secret Query"
      - checklist.* 의 항목 키 → 예: "redirect_uri_safety"
      - failures... → code 또는 title
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}

    results = defaultdict(list)

    def add(key, res, note=None, observed=None, evidence=None):
        if not key:
            return
        results[key].append({
            "result": _norm_result(res),
            "note": note or "",
            "observed": observed,
            "evidence": evidence,
            "source": path.name,
        })

    def walk(node):
        if isinstance(node, dict):
            # 1) groups.*.checks[] (oauth_report, combined_* 등)
            grp = node.get("groups")
            if isinstance(grp, dict):
                for g in grp.values():
                    checks = g.get("checks")
                    if isinstance(checks, list):
                        for c in checks:
                            title = c.get("title") or c.get("id") or c.get("key")
                            res = c.get("result")
                            add(title, res, note=c.get("description") or c.get("detail"),
                                evidence=c.get("evidence"))

            # 2) checklist (중첩 허용: authcode_report, nonce_check_result, key_rotation_check_result 등)
            cl = node.get("checklist")
            if isinstance(cl, dict):
                for cat in cl.values():  # "A","B","C" 같은 그룹
                    if isinstance(cat, dict):
                        for k, v in cat.items():  # k: "redirect_uri_safety" 등
                            if isinstance(v, dict) and "result" in v:
                                add(
                                    k, v.get("result"),
                                    note=v.get("note"),
                                    observed=v.get("observed"),
                                    evidence=v.get("evidence"),
                                )

            # 3) failures/warnings/issues (중첩 허용)
            for arr_key in ("failures", "warnings", "issues"):
                arr = node.get(arr_key)
                if isinstance(arr, list):
                    for it in arr:
                        key = it.get("code") or it.get("title") or ""
                        res = "Fail" if arr_key == "failures" else "N/A"
                        add(key, res, note=it.get("detail"), evidence=it.get("evidence"))

            # 4) 다른 자식도 재귀 탐색
            for k, v in node.items():
                if k not in ("groups", "checklist", "failures", "warnings", "issues"):
                    walk(v)

        elif isinstance(node, list):
            for x in node:
                walk(x)

    walk(data)
    return results

# -----------------------
# HTML 빌드 (문자 넘침 방지 포함)
# -----------------------
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
        vuln = f'<div class="row-badge"><span class="nowrap">{esc(r["title_ko"])}</span>'
        if r["key"]: vuln += f' <span class="tag">{esc(r["key"])}</span>'
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
.wrap{{ overflow-wrap:anywhere; word-break: break-word; }}

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
        <div class="kpi"><div class="muted">총 항목(집계)</div><div class="num">{summary['considered']}</div></div>
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

# -----------------------
# 집계 + 파일 출력 + 브라우저 (중복 제거 적용)
# -----------------------
def _compute_rows_and_summary(modules_dir: Path, severity_map: dict, project: str, target: str):
    inputs = [p for p in modules_dir.rglob("*.json") if p.is_file()]
    gathered = defaultdict(list)
    for p in inputs:
        for k, lst in _extract_results(p).items():
            gathered[k].extend(lst)

    ORDER = {"Fail":3, "Pass":2, "N/A":1}
    rows = []; pass_count = fail_count = na_count = 0

    for item in CHECK_ITEMS:
        key = item["key"]
        title_ko = item["title_ko"]
        per_key = gathered.get(key, []) if key else []

        if per_key:
            worst = max(per_key, key=lambda x: ORDER.get(x["result"],0))
            result = worst["result"]

            # 비고/증거 중복 제거 (내용 기준)
            notes_raw = [x.get("note","") for x in per_key if x.get("note")]
            notes = _dedup_keep_order(notes_raw, keyfunc=_norm_text)

            evid_raw = [x.get("evidence") for x in per_key if x.get("evidence") is not None]
            evidences = _dedup_keep_order(evid_raw, keyfunc=_norm_evidence)

            # 출처는 전체 합집합
            sources = sorted({x["source"] for x in per_key if x.get("source")})
        else:
            result = "N/A"; notes=[]; evidences=[]; sources=[]

        severity = severity_map[title_ko]  # 기본 High or txt 기준

        if result == "Pass": pass_count += 1
        elif result == "Fail": fail_count += 1
        else: na_count += 1

        rows.append({
            "key": key, "title_ko": title_ko, "result": result, "severity": severity,
            "notes": "; ".join(notes) if notes else "",
            "evidences": evidences, "sources": sources,
            "section": item["section"], "group": item["group"]
        })

    considered = pass_count + fail_count
    pct_pass = round((pass_count / considered) * 100, 1) if considered else 0.0
    summary = {
        "project": project, "target": target, "now": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "pass": pass_count, "fail": fail_count, "na": na_count,
        "considered": considered, "pct_pass": pct_pass
    }
    return rows, summary

def generate_report(
    project: str = "KSJ OAuth 취약점 점검",
    target: str = "https://example.com",
    modules_dir: str | Path = "./module_reports",
    severity_file: str | Path | None = None,
    out_dir: str | Path = "./reports",
    open_browser: bool = True
):
    """
    보고서 생성 + (기본) 브라우저 자동 오픈
    severity_file: 사용자가 넘기는 severity.txt 경로(선택)
                   None이면 ./severity/severity.txt 또는 fallback 검색
    Returns: (output_html_path: Path, summary: dict)
    """
    modules_dir = Path(modules_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    sev_path = resolve_severity_file(severity_file)
    severity_map = load_severity_from_txt(sev_path)

    rows, summary = _compute_rows_and_summary(modules_dir, severity_map, project, target)
    out_file = out_dir / f"OAuth_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    html = _build_html(rows, summary)
    out_file.write_text(html, encoding="utf-8")

    if open_browser:
        try:
            webbrowser.open_new_tab(out_file.resolve().as_uri())
        except Exception:
            pass

    return out_file, summary

# -----------------------
# CLI 진입점: 대상 URL 옵션 추가
# -----------------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="OAuth Vulnerability Checker - 보고서 생성기")
    ap.add_argument("--project", default="KSJ OAuth 취약점 점검", help="프로젝트명")
    ap.add_argument("--target", "--target-url", dest="target", default="https://example.com", help="대상(서비스/RP) URL")
    ap.add_argument("--modules-dir", default="./module_reports", help="진단 모듈 산출물 JSON 폴더(재귀)")
    ap.add_argument("--severity-file", default=None, help="severity.txt 경로 (기본: ./severity/severity.txt 자동 탐색)")
    ap.add_argument("--out-dir", default="./reports", help="보고서 출력 폴더")
    args = ap.parse_args()

    out, summary = generate_report(
        project=args.project,
        target=args.target,
        modules_dir=args.modules_dir,
        severity_file=args.severity_file,
        out_dir=args.out_dir,
        open_browser=True  # 기본 자동 오픈
    )
    print("✔ 보고서 생성:", out)
    print("   Target:", summary["target"])
    print("   Pass:", summary["pass"], "Fail:", summary["fail"], "N/A:", summary["na"], "Pass%:", summary["pct_pass"])

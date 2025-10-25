#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ovc.py — OAuth Vulnerability Checker
Flow (mode 0):
  1) Proxy Capture
  2) Discovery Fetch
  3) Run 4 local checker modules (relative to ovc.py)
  4) Call module_G/runner.py: run_analysis(packets, session, out)
  5) Run move.py → report_builder.py --target <login URL>
"""
from __future__ import annotations

import os
import sys
import json
import time
import shutil
import signal
import tempfile
import subprocess
import platform
from pathlib import Path
from typing import Optional, List, Tuple
from urllib.parse import urlsplit

# --- Paths ---
BASE_DIR = Path(__file__).resolve().parent
PROXY_ARTIFACT_DIR = (BASE_DIR / "proxy_artifacts").resolve()
BROWSER_ARTIFACT_DIR = (BASE_DIR / "browser_artifacts").resolve()
DISCOVERY_ARTIFACT_DIR = (BASE_DIR / "discovery_artifacts").resolve()

# --- Helpers ---
def ask_yes_no(prompt: str, default: bool=False) -> bool:
    suf = "[Y/n]" if default else "[y/N]"
    while True:
        v = input(f"{prompt} {suf} ").strip().lower()
        if not v:
            return default
        if v in ("y","yes"): return True
        if v in ("n","no"): return False
        print("y 또는 n으로 입력해 주세요.")

def _ensure_dirs(*p: Path) -> None:
    for x in p: x.mkdir(parents=True, exist_ok=True)

def _timestamp() -> str:
    import datetime as dt
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")

def _which(name: str) -> Optional[str]:
    from shutil import which
    return which(name)

def _latest_discovery_dir() -> Optional[Path]:
    if not DISCOVERY_ARTIFACT_DIR.exists():
        return None
    dirs = [d for d in DISCOVERY_ARTIFACT_DIR.iterdir() if d.is_dir()]
    return max(dirs, key=lambda d: d.stat().st_mtime) if dirs else None

def _latest_discovery_summary() -> Tuple[Optional[dict], Optional[Path]]:
    d = _latest_discovery_dir()
    if not d:
        return None, None
    sj = d / "summary.json"
    if sj.exists():
        try:
            return json.loads(sj.read_text(encoding="utf-8")), sj
        except Exception:
            return None, None
    return None, None

def _infer_target_from_discovery(summary: Optional[dict]) -> str:
    try:
        if not summary: return "OVC-Target"
        iss = summary.get("issuer_inferred") or ""
        return urlsplit(iss).netloc or "OVC-Target"
    except Exception:
        return "OVC-Target"

# --- Capture (mitmdump) ---
def run_proxy_capture(listen_host: str, listen_port: int, ssl_insecure: bool, login_url: Optional[str]) -> None:
    _ensure_dirs(PROXY_ARTIFACT_DIR)
    flows_tmp = Path(tempfile.gettempdir()) / f"flows_{next(tempfile._get_candidate_names())}.mitm"  # noqa
    mitmdump = _which("mitmdump") or _which("mitmdump.exe")
    if not mitmdump:
        # last-resort; let it fail if not found
        mitmdump = "mitmdump"

    cmd = [
        mitmdump,
        "--listen-host", listen_host,
        "--listen-port", str(listen_port),
        "-w", str(flows_tmp),
        "--set", "stream_large_bodies=5m",
        "--set", "anticomp=true",
    ]
    if ssl_insecure:
        cmd.append("--ssl-insecure")

    print(f"[proxy] mitmdump 실행: {' '.join(cmd)}")
    print(f"        외부 장치/컨테이너가 {listen_host}:{listen_port} 프록시를 사용하면 트래픽이 캡처됩니다.")
    print("        (브라우저 테스트: http://mitm.it)")

    if ask_yes_no("mitmproxy 루트 CA를 OS에 신뢰로 추가할까요?", default=True):
        print("※ OS/브라우저에 따라 수동 설치가 필요할 수 있습니다. (mitm.it 안내 참고)")

    if login_url:
        try:
            import webbrowser
            webbrowser.open(login_url)
        except Exception:
            pass

    creationflags = 0
    popen_kwargs = {}
    if os.name == "nt":
        # run child in a new process group to avoid sending break to parent console
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        popen_kwargs["creationflags"] = creationflags

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **popen_kwargs)
    except Exception as e:
        print(f"[오류] mitmdump 실행 실패: {e}")
        return

    try:
        input("[Proxy Capture] 프록시 캡처 진행 중입니다. 종료하려면 Enter...")
    finally:
        # terminate only the child process
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            proc.wait(timeout=8)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    try:
        flows_out = PROXY_ARTIFACT_DIR / f"flows_{_timestamp()}.mitm"
        if flows_tmp.exists():
            shutil.move(str(flows_tmp), str(flows_out))
    except Exception:
        pass

    # Placeholders for downstream
    (PROXY_ARTIFACT_DIR / "packets.jsonl").touch(exist_ok=True)
    if not (PROXY_ARTIFACT_DIR / "session_token.json").exists():
        (PROXY_ARTIFACT_DIR / "session_token.json").write_text(json.dumps({"issuer_inferred": ""}, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[완료] 산출물: {PROXY_ARTIFACT_DIR}")
    print("[다음 단계] Discovery Fetch로 진행합니다...")

# --- Discovery (minimal) ---
def _http_json(url: str, timeout: float=10.0) -> Optional[dict]:
    try:
        import requests
    except Exception:
        return None
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        if r.status_code == 200:
            try:
                return r.json()
            except Exception:
                return json.loads(r.text)
    except Exception:
        return None
    return None

def _infer_issuer_from_login_url(login_url: str) -> Optional[str]:
    try:
        u = urlsplit(login_url)
        return f"{u.scheme}://{u.netloc}"
    except Exception:
        return None

def _discovery_candidates(issuer: str) -> List[str]:
    u = urlsplit(issuer)
    hostroot = f"{u.scheme}://{u.netloc}"
    path = (u.path or "").rstrip("/")
    out: List[str] = []
    out.append(f"{issuer.rstrip('/')}/.well-known/openid-configuration")
    if path:
        out.append(f"{hostroot}/.well-known/openid-configuration{path}")
    out.append(f"{issuer.rstrip('/')}/.well-known/oauth-authorization-server")
    if path:
        out.append(f"{hostroot}/.well-known/oauth-authorization-server{path}")
    ext: List[str] = []
    for x in out:
        ext.append(x)
        if x.startswith("https://"):
            ext.append("http://" + x[8:])
    seen=set(); uniq=[]
    for x in ext:
        if x not in seen:
            seen.add(x); uniq.append(x)
    return uniq

def run_discovery_fetch_from_artifacts(login_url_hint: Optional[str]) -> None:
    print("\n[Discovery Fetch] Issuer 추론 및 디스커버리 로드")
    issuer = _infer_issuer_from_login_url(login_url_hint) if login_url_hint else None
    if not issuer:
        manual = input("Issuer(URL) 또는 로그인 URL을 입력해 주세요(엔터=건너뜀): ").strip()
        if manual:
            issuer = manual

    if not issuer:
        print("[경고] Issuer를 결정하지 못했습니다. Discovery를 건너뜁니다.")
        return

    cands = _discovery_candidates(issuer)
    for u in cands[:6]:
        print("  -", u)
    if len(cands) > 6:
        print(f"  ... (총 {len(cands)}개)")

    disco = None; used = None
    for u in cands:
        j = _http_json(u)
        if j:
            disco = j; used = u; break

    if not disco:
        print("[오류] 디스커버리 문서를 가져오지 못했습니다.")
        return

    outdir = DISCOVERY_ARTIFACT_DIR / f"{_timestamp()}_{(urlsplit(issuer).netloc or 'issuer').replace(':','_')}"
    _ensure_dirs(outdir)
    (outdir / "openid_configuration.json").write_text(json.dumps(disco, ensure_ascii=False, indent=2), encoding="utf-8")
    jwks_url = disco.get("jwks_uri")
    if jwks_url:
        jwks = _http_json(jwks_url) or {}
        (outdir / "jwks.json").write_text(json.dumps(jwks, ensure_ascii=False, indent=2), encoding="utf-8")
    summary = {
        "issuer_inferred": issuer,
        "discovery_url_used": used,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    (outdir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[완료] discovery_artifacts 생성: {outdir}")
    print("[다음 단계] 4개 모듈 실행으로 진행합니다...")

# --- User commands (relative) ---
def _run_external_commands_for_checks() -> None:
    """
    4개 명령을 'ovc.py' 기준 상대경로로 실행.
    OIDC는 내부 상수의 절대경로를 런타임 오버라이드하여 로컬 경로 사용.
    """
    root = BASE_DIR
    proxy_dir = root / "proxy_artifacts"
    disco_dir = _latest_discovery_dir()
    openid_json = (disco_dir / "openid_configuration.json") if disco_dir else (root / "discovery_artifacts" / "openid_configuration.json")
    jwks_json   = (disco_dir / "jwks.json") if disco_dir else (root / "discovery_artifacts" / "jwks.json")

    module_reports = root / "module_reports"
    checker_tool = root / "checker_tool"
    session_json = proxy_dir / "session_token.json"

    cmds = []

    # 1) Auth Code
    cmd1 = [
        sys.executable,
        str(checker_tool / "AuthCode_vuln" / "run_checker.py"),
        str(session_json),
        "--module", str(checker_tool / "AuthCode_vuln" / "auth_code_theft_checker.py"),
        "--outdir", str(module_reports),
        "--discovery-file", str(openid_json),
        "--jwks-file", str(jwks_json),
        "--single-json",
    ]
    cmds.append(cmd1)

    # 2) OIDC nonce — override module globals
    override_code = f"""
import importlib.util, sys, pathlib
p = r'{(checker_tool / "OIDC_vuln" / "adapter_to_checker.py").as_posix()}'
spec = importlib.util.spec_from_file_location('oidc_nonce_adapter', p)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
m.DEFAULT_DISCOVERY_DIR = r'{(disco_dir if disco_dir else (BASE_DIR / "discovery_artifacts")).as_posix()}'
m.DEFAULT_OUTPUT_DIR = r'{(module_reports).as_posix()}'
sys.argv = ['adapter_to_checker.py', r'{(session_json).as_posix()}', '--checker', r'{(checker_tool / "OIDC_vuln" / "oidc_nonce_checker.py").as_posix()}']
m.main()
"""
    cmd2 = [sys.executable, "-c", override_code]
    cmds.append(cmd2)

    # 3) 키 회전
    cmd3 = [
        sys.executable,
        str(checker_tool / "key_rotation_vuln" / "adapter_to_key_checker.py"),
    ]
    cmds.append(cmd3)

    # 4) alg 공격
    cmd4 = [
        sys.executable,
        str(checker_tool / "alg_vuln" / "adapter_to_key_checker.py"),
        "--session", str(session_json),
        "--discovery", str(openid_json),
        "--jwks", str(jwks_json),
        "--checker", str(checker_tool / "alg_vuln" / "vuln_alg_check.py"),
        "--outdir", str(module_reports),
    ]
    cmds.append(cmd4)

    for i, cmd in enumerate(cmds, 1):
        print(f"[Checks] ({i}/{len(cmds)}) 실행: {' '.join(cmd[:3])} ...")
        try:
            subprocess.run(cmd, cwd=str(root), check=False)
        except Exception as e:
            print(f"[Checks] 명령 실행 중 예외: {e}")
    print("[다음 단계] module_G runner 실행으로 진행합니다...")

# --- module_G runner ---
def call_moduleG_runner(packet_path: Path, session_path: Path, out_dir: Path) -> None:
    import importlib, importlib.util
    try:
        mod = importlib.import_module("module_G.runner")
    except ModuleNotFoundError:
        runner_py = BASE_DIR / "module_G" / "runner.py"
        if not runner_py.exists():
            print("[Runner] module_G/runner.py 가 없습니다. 건너뜁니다.")
            return
        spec = importlib.util.spec_from_file_location("module_G_runner_fallback", str(runner_py))
        if not spec or not spec.loader:
            print("[Runner] runner.py spec 생성 실패")
            return
        mod = importlib.util.module_from_spec(spec)
        sys.modules["module_G_runner_fallback"] = mod
        spec.loader.exec_module(mod)
    except Exception as e:
        print(f"[Runner] 임포트 오류: {e}")
        return

    fn = getattr(mod, "run_analysis", None)
    if not callable(fn):
        print("[Runner] run_analysis(packet, session, out) 함수가 없습니다.")
        return

    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[Runner] run_analysis 호출 → packet={packet_path}, session={session_path}, out={out_dir}")
    try:
        fn(packet_path, session_path, out_dir)
        print("[Runner] 완료.")
    except Exception as e:
        print(f"[Runner] 실행 예외: {e}")
    print("[다음 단계] move.py → report_builder.py 순서로 진행합니다...")

# --- Mode 0 ---
def run_mode0_ovc() -> None:
    print("\n[0] OAuth Vulnerability Checker (자동 실행)")
    listen_host = input("프록시 바인딩 호스트 [기본 0.0.0.0]: ").strip() or "0.0.0.0"
    try:
        listen_port = int(input("프록시 포트 [기본 18080]: ").strip() or "18080")
    except ValueError:
        print("잘못된 포트 값입니다. 18080으로 진행합니다.")
        listen_port = 18080
    ssl_insecure = ask_yes_no("서버 인증서 검증을 생략하시겠습니까?", default=False)

    # URL 먼저, 그 다음 열지 여부
    login_url_input = input("진단 대상 로그인 페이지 URL (예: https://example.com/login): ").strip()
    open_login = ask_yes_no("로그인 페이지를 브라우저로 열까요?", default=True)
    login_url = login_url_input if (open_login and login_url_input) else None

    # 1) Capture
    run_proxy_capture(listen_host, listen_port, ssl_insecure, login_url)

    # 2) Discovery
    run_discovery_fetch_from_artifacts(login_url_input)
    summary, _ = _latest_discovery_summary()

    # 3) 외부 명령 4개 (상대경로)
    _run_external_commands_for_checks()

    # 4) module_G runner
    pkt = PROXY_ARTIFACT_DIR / "packets.jsonl"
    ses = PROXY_ARTIFACT_DIR / "session_token.json"
    if not pkt.exists() and (BROWSER_ARTIFACT_DIR / "packets.jsonl").exists():
        pkt = BROWSER_ARTIFACT_DIR / "packets.jsonl"
    if not ses.exists() and (BROWSER_ARTIFACT_DIR / "session_token.json").exists():
        ses = BROWSER_ARTIFACT_DIR / "session_token.json"
    call_moduleG_runner(pkt, ses, BASE_DIR / "module_reports" / "module_G")

    # 5) move.py → report_builder.py --target <URL>
    try:
        rc = subprocess.run([sys.executable, str(BASE_DIR / "move.py")], cwd=str(BASE_DIR))
        print(f"[Move] move.py 종료 코드: {rc.returncode}")
    except Exception as e:
        print(f"[Move] 실행 예외: {e}")

    report_target = login_url_input or _infer_target_from_discovery(summary)
    try:
        rc = subprocess.run([sys.executable, str(BASE_DIR / "report_builder.py"), "--target", report_target], cwd=str(BASE_DIR))
        print(f"[Report] report_builder.py 종료 코드: {rc.returncode}")
    except Exception as e:
        print(f"[Report] 실행 예외: {e}")

    print("\n[완료] 0) OAuth Vulnerability Checker 파이프라인을 마쳤습니다.")

# --- OS 선택 & 메뉴 ---
def choose_os() -> str:
    detected = platform.system().lower()
    guess = {"windows":"windows", "darwin":"macos", "linux":"ubuntu"}.get(detected, "windows")
    print("\n=== OS 선택 ===")
    print("1) Windows")
    print("2) macOS")
    print("3) Ubuntu/Debian")
    print("4) RHEL/CentOS/Fedora")
    print("5) 기타/수동")
    sel = input(f"번호 선택 [기본 { {'windows':1,'macos':2,'ubuntu':3,'rhel':4,'other':5}[guess] } ]: ").strip()
    return {"1":"windows","2":"macos","3":"ubuntu","4":"rhel","5":"other","":guess}.get(sel, guess)

def main() -> None:
    _ensure_dirs(PROXY_ARTIFACT_DIR, BROWSER_ARTIFACT_DIR, DISCOVERY_ARTIFACT_DIR, BASE_DIR / "module_reports")
    choose_os()
    print("\n=== OAuth Vulnerability Checker (OVC) ===")
    print("산출물 폴더: Proxy=./proxy_artifacts, Browser=./browser_artifacts, Discovery=./discovery_artifacts")
    print("모드 선택: 0) OAuth Vulnerability Checker(기본)  1) Proxy Capture  2) Browser Session Capture  3) Proxy Setup Assistant  4) Proxy Setup Revert  5) Discovery Fetch  q) 종료")
    choice = input("선택 입력 [0/1/2/3/4/5/q] (엔터=0): ").strip().lower()
    if choice in ("", "0"):
        run_mode0_ovc(); return
    if choice == "1":
        listen_host = input("프록시 바인딩 호스트 [기본 0.0.0.0]: ").strip() or "0.0.0.0"
        try: listen_port = int(input("프록시 포트 [기본 18080]: ").strip() or "18080")
        except ValueError: listen_port = 18080
        ssl_insecure = ask_yes_no("서버 인증서 검증을 생략하시겠습니까?", default=False)
        url = input("로그인 페이지 URL (엔터=없음): ").strip() or None
        run_proxy_capture(listen_host, listen_port, ssl_insecure, url); return
    if choice == "5":
        url = input("로그인/Issuer URL 힌트(엔터=없음): ").strip() or None
        run_discovery_fetch_from_artifacts(url); return
    print("종료합니다.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[중단됨] 사용자에 의해 종료")
        sys.exit(130)

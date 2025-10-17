#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OAuth Vuln Scanner (CLI)
- 사용자가 브라우저에서 직접 로그인하는 동안 세션 토큰/패킷을 수집하여 산출물로 저장.
- 필수: selenium 4+
- 선택(권장): selenium-wire (패킷 캡처용)
Usage:
    python oauth_vuln_scanner.py
"""

import sys
import os
import re
import json
import base64
import pathlib
import time
import warnings
from datetime import datetime
from typing import Any, Dict, List
from urllib.parse import urlsplit, urlunsplit, parse_qsl

# -------------------------
# 전역 상수/유틸리티
# -------------------------
ARTIFACT_ROOT = pathlib.Path("artifacts")
JWT_REGEX = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')

def now_ts_str() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def ensure_dir(p: pathlib.Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def normalize_url(raw: str) -> str:
    s = (raw or "").strip()
    if not s:
        raise ValueError("빈 URL 입니다.")
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', s):
        s = "http://" + s
    parts = urlsplit(s)
    path = parts.path if parts.path else "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc, path, parts.query, parts.fragment))

def to_bytes(x: Any) -> bytes:
    if x is None:
        return b""
    if isinstance(x, bytes):
        return x
    if isinstance(x, str):
        return x.encode("utf-8", "ignore")
    return str(x).encode("utf-8", "ignore")

def b64(x: bytes, max_len: int = 1024 * 512) -> str:
    data = x[:max_len]
    return base64.b64encode(data).decode("ascii", "ignore")

def scan_jwts(text: str) -> List[str]:
    if not text:
        return []
    return list(set(JWT_REGEX.findall(text)))

def parse_url_params(url: str) -> Dict[str, Any]:
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    frag = dict(parse_qsl(parts.fragment, keep_blank_values=True))
    return {"url": url, "query": q, "fragment": frag}

# -------------------------
# 환경 점검
# -------------------------
def check_env() -> Dict[str, Any]:
    info = {"selenium": False, "selenium_wire": False}
    ok = True
    try:
        import selenium  # noqa: F401
        info["selenium"] = True
    except Exception:
        ok = False
    try:
        import seleniumwire  # noqa: F401
        info["selenium_wire"] = True
    except Exception:
        pass
    return {"ok": ok, "detail": info}

# -------------------------
# 브라우저 시작 (pkg_resources 경고 억제)
# -------------------------
def start_browser(use_wire: bool):
    """
    Returns: (driver, wired: bool)
    """
    if use_wire:
        # selenium-wire가 내부적으로 pkg_resources를 import할 때 출력되는
        # "pkg_resources is deprecated as an API" UserWarning만 억제한다.
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                message=r".*pkg_resources is deprecated as an API.*",
                category=UserWarning,
            )
            warnings.filterwarnings(
                "ignore",
                message=r".*pkg_resources package is slated for removal.*",
                category=UserWarning,
            )
            from seleniumwire import webdriver as sw_webdriver
            from selenium.webdriver.chrome.options import Options
            opts = Options()
            # 대화형 로그인 UX를 위해 headful. 필요 시 다음 줄 주석 해제
            # opts.add_argument("--headless=new")
            opts.add_argument("--disable-gpu")
            opts.add_argument("--no-sandbox")
            opts.add_argument("--disable-dev-shm-usage")
            driver = sw_webdriver.Chrome(options=opts)
            return driver, True
    else:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        opts = Options()
        # opts.add_argument("--headless=new")
        opts.add_argument("--disable-gpu")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        driver = webdriver.Chrome(options=opts)
        return driver, False

# -------------------------
# 수집 함수
# -------------------------
def dump_web_storage(driver) -> Dict[str, Dict[str, str]]:
    get_ls = "return Object.fromEntries(Object.entries(window.localStorage));"
    get_ss = "return Object.fromEntries(Object.entries(window.sessionStorage));"
    ls = {}
    ss = {}
    try:
        ls = driver.execute_script(get_ls) or {}
    except Exception:
        ls = {}
    try:
        ss = driver.execute_script(get_ss) or {}
    except Exception:
        ss = {}
    return {"localStorage": ls, "sessionStorage": ss}

def collect_cookies(driver) -> List[Dict[str, Any]]:
    try:
        return driver.get_cookies() or []
    except Exception:
        return []

def dump_network(driver, out_jsonl_path: pathlib.Path) -> Dict[str, Any]:
    """
    selenium-wire 전용. 요청/응답을 JSONL 로 저장.
    body는 base64로 인코딩(최대 512KB).
    """
    stats = {"requests": 0, "responses": 0, "errors": 0}
    try:
        requests_iter = getattr(driver, "requests", [])
    except Exception:
        requests_iter = []

    try:
        with out_jsonl_path.open("w", encoding="utf-8") as f:
            for req in requests_iter:
                try:
                    rec = {
                        "ts": time.time(),
                        "request": {
                            "method": getattr(req, "method", None),
                            "url": getattr(req, "url", None),
                            "headers": dict(getattr(req, "headers", {}) or {}),
                            "body_b64": b64(to_bytes(getattr(req, "body", b"")))
                        },
                        "response": None
                    }
                    stats["requests"] += 1

                    resp = getattr(req, "response", None)
                    if resp is not None:
                        body_bytes = b""
                        try:
                            body_bytes = to_bytes(resp.body)
                        except Exception:
                            body_bytes = b""
                        rec["response"] = {
                            "status": getattr(resp, "status_code", None),
                            "headers": dict(getattr(resp, "headers", {}) or {}),
                            "body_b64": b64(body_bytes)
                        }
                        stats["responses"] += 1

                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                except Exception:
                    stats["errors"] += 1
                    continue
    except Exception:
        stats["errors"] += 1
    return stats

# -------------------------
# readme.txt 작성 (고정 내용)
# -------------------------
README_TEXT = """\
OAuth Vuln Scanner – Artifacts Guide
===================================

본 폴더는 한 번의 스캔 실행에서 생성된 산출물입니다.

1) session_tokens.json
   - cookies[]: Selenium이 수집한 브라우저 쿠키 전체.
   - localStorage{} / sessionStorage{}: 각 Web Storage의 key-value 스냅샷.
   - url_params_history[]: 시작/종료 시점의 URL, query, fragment 파싱(예: code/state/id_token 등).
   - auth_headers[]: 네트워크에서 추출된 Authorization 헤더(있을 경우).
   - jwt_hits[]: 값들에서 정규식으로 탐지한 JWT 형태 토큰 리스트.
   *주의*: 민감정보(세션/토큰)가 포함될 수 있으니 보안적으로 취급하세요.

2) packets.jsonl  (selenium-wire 사용 시 생성)
   - JSON Lines 형식. 각 줄은 하나의 요청/응답 기록.
   - 필드:
     request{ method, url, headers{}, body_b64 },
     response{ status, headers{}, body_b64 }
   - body_b64는 본문(최대 512KB)의 Base64 인코딩입니다.
   - 열람 팁: jq, Python 등으로 라인 단위 파싱하세요.

3) run_meta.json
   - 이번 실행(런)의 메타데이터(재현·감사용).
   - 예: target, started_at, ended_at, use_selenium_wire, version,
         platform, python, packets_path, packets_stats 등.

보안 주의사항
-------------
- 본 산출물에는 인증 토큰/세션 쿠키 등이 포함될 수 있습니다.
- 팀 외부 공유 금지, 암호화 저장 권장, 필요 시 즉시 폐기하십시오.

문의/버전
---------
- 도구 버전은 run_meta.json 의 "version" 필드를 참고하세요.
"""

def write_readme(out_dir: pathlib.Path) -> None:
    try:
        with (out_dir / "readme.txt").open("w", encoding="utf-8") as f:
            f.write(README_TEXT)
    except Exception as e:
        print(f"[!] readme.txt 저장 실패: {e}", file=sys.stderr)

# -------------------------
# 메인
# -------------------------
def main():
    print("\n[OAuth Vuln Scanner] CLI 시작")

    env = check_env()
    if not env["detail"]["selenium"]:
        print("[!] selenium 미설치: `pip install --upgrade selenium` 후 다시 실행하세요.", file=sys.stderr)
        sys.exit(1)

    use_wire = env["detail"]["selenium_wire"]
    if use_wire:
        print("[*] selenium-wire 감지됨 → 패킷 캡처 활성화")
    else:
        print("[*] selenium-wire 미설치 → 패킷 캡처 비활성 (설치 권장: `pip install --upgrade selenium-wire`)")

    raw = input("진단 대상 로그인 URL 입력: ").strip()
    try:
        target_url = normalize_url(raw)
    except Exception as e:
        print(f"[!] URL 오류: {e}", file=sys.stderr)
        sys.exit(2)

    run_id = now_ts_str()
    out_dir = ARTIFACT_ROOT / run_id
    ensure_dir(out_dir)

    run_meta = {
        "target": target_url,
        "started_at": datetime.now().isoformat(),
        "use_selenium_wire": use_wire,
        "version": "0.1.2",
        "platform": sys.platform,
        "python": sys.version.split()[0]
    }

    # 브라우저 시작
    try:
        driver, wired = start_browser(use_wire)
    except Exception as e:
        print(f"[!] 브라우저 시작 실패: {e}", file=sys.stderr)
        sys.exit(3)

    # 타깃 이동
    try:
        driver.get(target_url)
    except Exception as e:
        print(f"[!] 페이지 로드 실패: {e}", file=sys.stderr)
        try:
            driver.quit()
        except Exception:
            pass
        sys.exit(4)

    url_history: List[Dict[str, Any]] = [parse_url_params(getattr(driver, "current_url", target_url))]

    print("\n[안내] 브라우저에서 직접 로그인 진행하세요.")
    print("       로그인 플로우가 끝난 뒤 터미널로 돌아와 Enter 를 누르면 수집을 마감합니다.")
    input("계속하려면 Enter... ")

    # 최종 상태 스냅샷
    url_history.append(parse_url_params(getattr(driver, "current_url", target_url)))
    storage = dump_web_storage(driver)
    cookies = collect_cookies(driver)

    # JWT/Authorization 헤더 수집
    jwt_hits: List[str] = []
    auth_headers: List[str] = []

    # 스토리지에서 JWT 패턴 스캔
    for v in list(storage.get("localStorage", {}).values()) + list(storage.get("sessionStorage", {}).values()):
        jwt_hits += scan_jwts(str(v))

    # URL 쿼리/프래그먼트에서도 스캔
    for u in url_history:
        for v in list(u.get("query", {}).values()) + list(u.get("fragment", {}).values()):
            jwt_hits += scan_jwts(str(v))

    # 네트워크 덤프
    packet_stats = {"requests": 0, "responses": 0, "errors": 0}
    packets_path = out_dir / "packets.jsonl"
    if wired:
        packet_stats = dump_network(driver, packets_path)
        # Authorization 헤더만 별도 수집 + JWT 스캔
        try:
            for req in getattr(driver, "requests", []):
                try:
                    hdrs = dict(getattr(req, "headers", {}) or {})
                    for k, v in hdrs.items():
                        if str(k).lower() == "authorization":
                            auth_headers.append(str(v))
                            jwt_hits += scan_jwts(str(v))
                except Exception:
                    continue
        except Exception:
            pass

    # 세션 토큰/지표 정리
    tokens_bundle = {
        "cookies": cookies,
        "localStorage": storage.get("localStorage", {}),
        "sessionStorage": storage.get("sessionStorage", {}),
        "url_params_history": url_history,
        "auth_headers": auth_headers,
        "jwt_hits": sorted(set(jwt_hits))
    }

    # 저장
    try:
        with (out_dir / "session_tokens.json").open("w", encoding="utf-8") as f:
            json.dump(tokens_bundle, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[!] session_tokens.json 저장 실패: {e}", file=sys.stderr)

    run_meta.update({
        "packets_saved": wired,
        "packets_path": str(packets_path if wired else ""),
        "packets_stats": packet_stats,
        "ended_at": datetime.now().isoformat()
    })
    try:
        with (out_dir / "run_meta.json").open("w", encoding="utf-8") as f:
            json.dump(run_meta, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[!] run_meta.json 저장 실패: {e}", file=sys.stderr)

    # readme.txt 추가 생성(고정 내용)
    write_readme(out_dir)

    # 마무리
    try:
        driver.quit()
    except Exception:
        pass

    print("\n[완료] 아티팩트 폴더:", out_dir)
    if wired:
        print(f" - packets.jsonl (req:{packet_stats['requests']}, resp:{packet_stats['responses']}, err:{packet_stats['errors']})")
    else:
        print(" - (패킷 캡처 비활성: selenium-wire 미설치)")
    print(" - session_tokens.json")
    print(" - run_meta.json")
    print(" - readme.txt")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[중단됨] 사용자에 의해 종료")
        sys.exit(130)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OAuth Vuln Scanner (CLI)
- 실행: python oauth_vuln_scanner.py

- 산출물(최종):
    • proxy_artifacts/...
    • browser_artifacts/...

- 모드:
    1) Proxy Capture
       - (개편) 같은 PC에서 서비스 클라이언트를 돌리는지 먼저 확인
         · 같은 PC라면 호스트=0.0.0.0, 포트=18080으로 자동 고정, 캡처 시작 직후 **캡처 도중** 3번을 자동 수행
           (프록시 자동 설정이 끝난 뒤 브라우저가 켜지도록 순서 조정)
         · 다른 PC에서 모을 땐 기본 호스트=0.0.0.0, 포트 기본=18080
    2) Browser Session Capture
    3) Proxy Setup Assistant        ← OS별 시스템 프록시/mitm CA + docker-compose 자동 수정 + 컨테이너 주입 + (수정 시) up -d 자동 + mitm 기본 로깅 주입
                                     (개편) 프록시 호스트/포트가 preset으로 들어오면 해당 값으로 자동 진행
                                     (개편) 127.0.0.1/localhost/0.0.0.0 로 받은 경우 컨테이너/compose에 host.docker.internal 자동 보정
                                     (신규) 호스트 PC 환경변수(HTTP[S]_PROXY, REQUESTS_CA_BUNDLE, SSL_CERT_FILE) 자동 주입
    4) Proxy Setup Revert           ← 시스템 프록시/mitm CA/컨테이너 주입/compose 수정 원복 + mitm 기본 로깅 원복
                                     (개편) 컨테이너의 /etc/hosts에 추가되었을 수 있는 host.docker.internal 매핑 제거
                                     (신규) 3번에서 주입한 호스트 PC 환경변수 원복

주의:
- 3번은 “설정만” 수행합니다(원복 묻지 않음). 원복은 4번에서 따로 실행하세요.
"""
import base64
import datetime as dt
import json
import re
import sys
import time
import socket
import platform
import ctypes
import tempfile
import shutil
import subprocess
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, parse_qsl

# ====== 전역 OS 선택 상태 ======
SELECTED_OS = None  # 'windows' | 'macos' | 'ubuntu' | 'rhel' | 'other'

JWT_REGEX = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}")

OAUTH_KEYS = {
    "code",
    "access_token",
    "id_token",
    "refresh_token",
    "token",
    "oauth_token",
    "token_type",
    "scope",
    "state",
    "session_state",
    "client_id",
    "redirect_uri",
    "response_type",
    "grant_type",
    "iss",
    "aud",
    "nonce",
}

# === 산출물 디렉토리(간결명) ===
PROXY_ARTIFACT_DIR = Path("./proxy_artifacts").resolve()
BROWSER_ARTIFACT_DIR = Path("./browser_artifacts").resolve()

# ====== 진행률(스피너/바) 유틸 ======
class _Spinner:
    def __init__(self, text: str = "작업 진행 중"):
        self.text = text
        self._stop = False
        self._t = threading.Thread(target=self._spin, daemon=True)

    def _spin(self):
        frames = "|/-\\"
        i = 0
        while not self._stop:
            sys.stdout.write(f"\r{self.text} {frames[i % len(frames)]}")
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1
        # 지우기
        sys.stdout.write("\r" + " " * (len(self.text) + 4) + "\r")
        sys.stdout.flush()

    def start(self):
        self._t.start()

    def stop(self):
        self._stop = True
        try:
            self._t.join(timeout=1.0)
        except Exception:
            pass


def _progress_run(cmd: List[str], check: bool = False, label: Optional[str] = None) -> int:
    """서브프로세스를 스피너와 함께 실행."""
    sp = _Spinner(label or f"실행: {' '.join(cmd)}")
    sp.start()
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    finally:
        sp.stop()
    if check and proc.returncode != 0:
        if proc.stdout:
            print(proc.stdout.strip())
        if proc.stderr:
            print(proc.stderr.strip())
    return proc.returncode


# ====== 공통 유틸 ======
def b64lim(data: bytes, limit: int = 512 * 1024) -> str:
    if not data:
        return ""
    if len(data) > limit:
        data = data[:limit]
    return base64.b64encode(data).decode("ascii")


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def write_jsonl(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False))
        f.write(os.linesep)


def scan_jwts(text: str) -> List[str]:
    if not text:
        return []
    return list(set(JWT_REGEX.findall(text)))


def parse_url_params(url: str) -> Dict[str, Any]:
    try:
        parts = urlsplit(url)
        q = dict(parse_qsl(parts.query, keep_blank_values=True))
        frag = dict(parse_qsl(parts.fragment, keep_blank_values=True))
        return {"url": url, "query": q, "fragment": frag}
    except Exception:
        return {"url": url, "query": {}, "fragment": {}}


def ensure_url_https_then_http(url: str) -> Tuple[str, List[str]]:
    """스킴이 없으면 https를 우선 붙이고, 필요 시 http로 재시도 후보 반환.
       스킴을 명시하면 후보는 [원본]만."""
    tried: List[str] = []
    if not url:
        return url, tried
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        return url, [url]
    https = "https://" + url
    http = "http://" + url
    return https, [https, http]


def ensure_url_list(url: str) -> List[str]:
    first, candidates = ensure_url_https_then_http(url)
    return candidates or [first]


def ask_yes_no(prompt: str, default: bool = False) -> bool:
    suf = "[Y/n]" if default else "[y/N]"
    ans = input(f"{prompt} {suf} ").strip().lower()
    if not ans:
        return default
    return ans.startswith("y")


def _run(cmd: List[str], check: bool = False, show_progress: bool = False, progress_text: Optional[str] = None) -> int:
    """기존 _run을 유지하면서 필요 시 진행 스피너 표시."""
    if show_progress:
        return _progress_run(cmd, check=check, label=progress_text)
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if check and proc.returncode != 0:
            if proc.stdout:
                print(proc.stdout.strip())
            if proc.stderr:
                print(proc.stderr.strip())
        return proc.returncode
    except Exception as e:
        print(f"[실행 오류] {' '.join(cmd)} -> {e}")
        return 1

# === 추가: 토큰 분류/디코딩 유틸 ===
def _looks_like_jwt(v: str) -> bool:
    if not isinstance(v, str):
        return False
    return bool(JWT_REGEX.search(v))

def _classify_oauth_pair(key_lc: str, value: Any, where: str) -> str:
    if key_lc == "access_token":
        return "access_token"
    if key_lc == "id_token":
        return "id_token"
    if key_lc == "refresh_token":
        return "refresh_token"
    if key_lc == "code":
        return "auth_code"
    if key_lc in ("token", "oauth_token"):
        if isinstance(value, str) and _looks_like_jwt(value):
            return "unknown_jwt"
        return "unknown_token"
    if key_lc == "authorization":
        return "authorization_bearer"
    return "other"

def _maybe_decode_body(headers: Dict[str, Any], body: bytes) -> str:
    """content-encoding을 고려해 body를 가급적 텍스트로 디코딩"""
    if not body:
        return ""
    h = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    enc = h.get("content-encoding", "")
    try:
        raw = body
        if "br" in enc:
            try:
                import brotli  # type: ignore
                raw = brotli.decompress(raw)
            except Exception:
                pass
        if "gzip" in enc:
            import gzip, io
            raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
        elif "deflate" in enc:
            import zlib
            try:
                raw = zlib.decompress(raw, -zlib.MAX_WBITS)
            except Exception:
                raw = zlib.decompress(raw)
        ctype = h.get("content-type", "")
        charset = None
        m = re.search(r"charset=([\w\-\d]+)", ctype, re.I)
        if m:
            charset = m.group(1).strip()
        for cs in (charset, "utf-8", "latin-1"):
            if not cs:
                continue
            try:
                return raw.decode(cs, "ignore")
            except Exception:
                continue
    except Exception:
        pass
    try:
        return body.decode("utf-8", "ignore")
    except Exception:
        return body.decode("latin-1", "ignore")

def _collect_from_authz_header(headers: Dict[str, Any], url: Optional[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not headers:
        return out
    vals: List[str] = []
    try:
        vals = [v for k, v in headers.items(multi=True) if str(k).lower() == "authorization"]  # mitmproxy MultiDict
    except Exception:
        vals = [v for k, v in dict(headers).items() if str(k).lower() == "authorization"]
    for v in vals:
        if not isinstance(v, str):
            continue
        m = re.match(r"\s*Bearer\s+(.+)\s*$", v, re.I)
        if m:
            tok = m.group(1)
            out.append({
                "key": "authorization",
                "value": tok,
                "where": "request.headers.authorization",
                "url": url,
                "kind": "authorization_bearer",
            })
    return out

def _collect_from_cookies_for_oauth(name: str, value: str, where: str, url: Optional[str]) -> Optional[Dict[str, Any]]:
    key_lc = name.lower()
    if key_lc in ("access_token", "id_token", "refresh_token", "token", "oauth_token"):
        return {
            "key": name,
            "value": value,
            "where": where,
            "url": url,
            "kind": _classify_oauth_pair(key_lc, value, where),
        }
    return None


# ====== 산출물 작성기 ======
class ArtifactWriter:
    def __init__(self, outdir: Path, mode_label: str):
        self.outdir = outdir
        self.mode_label = mode_label  # "Proxy Capture" | "Browser Session Capture"
        self.outdir.mkdir(parents=True, exist_ok=True)
        self.packets = outdir / "packets.jsonl"
        self.tokens = outdir / "session_token.json"
        self.meta = outdir / "run_meta.json"
        self._stats = {"requests": 0, "responses": 0, "errors": 0}
        self._token_store: Dict[str, Any] = {
            "cookies": [],
            "local_storage": {},
            "session_storage": {},
            "auth_headers": [],
            "found_jwts": [],
            "oauth_tokens": [],     # 개별 레코드: {key, value, where, url, kind}
            "oauth_by_type": {},    # 집계: kind -> [ {value, where, url, key}... ]
            "jwt_claims": [],
        }
        self._started = now_iso()

    def add_packet(self, pkt: Dict[str, Any]) -> None:
        # 요청/응답을 별도 레코드로 순서 기록 (type=request|response|error)
        write_jsonl(self.packets, pkt)
        kind = pkt.get("type")
        if kind == "request":
            self._stats["requests"] += 1
        elif kind == "response":
            self._stats["responses"] += 1
        if pkt.get("error"):
            self._stats["errors"] += 1

    def add_tokens(self, **kw) -> None:
        for k in ("cookies", "auth_headers", "found_jwts", "jwt_claims"):
            if kw.get(k):
                if isinstance(self._token_store.get(k), list):
                    self._token_store[k].extend(kw[k])
        if kw.get("local_storage"):
            self._token_store["local_storage"].update(kw["local_storage"])
        if kw.get("session_storage"):
            self._token_store["session_storage"].update(kw["session_storage"])

        # oauth_tokens: kind 분류 및 by_type 집계
        if kw.get("oauth_tokens"):
            items = kw["oauth_tokens"]
            for it in items:
                key_lc = str(it.get("key", "")).lower()
                if "kind" not in it or not it["kind"]:
                    it["kind"] = _classify_oauth_pair(key_lc, it.get("value"), it.get("where", ""))
                self._token_store["oauth_tokens"].append(it)
                kd = it.get("kind") or "unknown_token"
                self._token_store["oauth_by_type"].setdefault(kd, []).append({
                    "key": it.get("key"),
                    "value": it.get("value"),
                    "where": it.get("where"),
                    "url": it.get("url"),
                })

    @staticmethod
    def _dedupe_list(lst: List[Any]) -> List[Any]:
        seen: set = set()
        out: List[Any] = []
        for item in lst:
            try:
                key = json.dumps(item, sort_keys=True, ensure_ascii=False)
            except TypeError:
                key = repr(item)
            if key not in seen:
                seen.add(key)
                out.append(item)
        return out

    @staticmethod
    def _merge_oauth_tokens_by_key_value(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        key+value 기준 통합.
        - where는 콤마 병합
        - url은 최초 비어있지 않은 값 유지
        - kind는 다르면 리스트로 유지
        """
        grouped: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for it in items:
            k = str(it.get("key"))
            v = str(it.get("value"))
            w = str(it.get("where", "") or "")
            u = it.get("url")
            kind = it.get("kind") or "unknown_token"
            gv = grouped.get((k, v))
            if not gv:
                grouped[(k, v)] = {"key": k, "value": v, "where_list": [], "url": u, "kinds": []}
            if w and w not in grouped[(k, v)]["where_list"]:
                grouped[(k, v)]["where_list"].append(w)
            if not grouped[(k, v)]["url"] and u:
                grouped[(k, v)]["url"] = u
            if kind and kind not in grouped[(k, v)]["kinds"]:
                grouped[(k, v)]["kinds"].append(kind)
        out: List[Dict[str, Any]] = []
        for (_k, _v), rec in grouped.items():
            out.append({
                "key": _k,
                "value": _v,
                "where": ", ".join(rec["where_list"]),
                "url": rec.get("url"),
                "kind": rec["kinds"][0] if len(rec["kinds"]) == 1 else rec["kinds"],
            })
        return out

    def _readme_text(self) -> str:
        header = [
            f"이 폴더는 '{self.mode_label}' 모드의 산출물입니다.",
            "",
            "[파일 설명]",
            "- packets.jsonl: 캡처된 요청/응답을 한 줄당 한 건씩 순서대로 기록(type=request/response).",
            "- session_token.json: 쿠키/스토리지/Authorization/JWT 및 OAuth 파라미터(code/access_token/id_token/refresh_token 등) 요약.",
            "    • oauth_tokens: 개별 토큰 레코드(종류는 kind 필드로 표시).",
            "    • oauth_by_type: 종류별 묶음(access_token, id_token, refresh_token, auth_code, authorization_bearer 등).",
            "- run_meta.json: 실행 시간/모드/카운트/대상 정보 등의 메타데이터.",
        ]
        return os.linesep.join(header)

    def finalize(self, wired: bool, mode: str, extra: Optional[Dict[str, Any]] = None) -> None:
        # 리스트형 필드 기본 dedupe
        self._token_store["cookies"] = self._dedupe_list(self._token_store.get("cookies", []))
        self._token_store["auth_headers"] = self._dedupe_list(self._token_store.get("auth_headers", []))
        self._token_store["found_jwts"] = self._dedupe_list(self._token_store.get("found_jwts", []))
        self._token_store["jwt_claims"] = self._dedupe_list(self._token_store.get("jwt_claims", []))

        merged = self._merge_oauth_tokens_by_key_value(self._token_store.get("oauth_tokens", []))
        self._token_store["oauth_tokens"] = merged

        # 집계 재구성(oauth_by_type)
        by_type: Dict[str, List[Dict[str, Any]]] = {}
        for it in merged:
            kinds = it.get("kind")
            kinds_list = kinds if isinstance(kinds, list) else [kinds]
            for kd in kinds_list:
                kd = kd or "unknown_token"
                by_type.setdefault(kd, []).append({
                    "key": it.get("key"),
                    "value": it.get("value"),
                    "where": it.get("where"),
                    "url": it.get("url"),
                })
        self._token_store["oauth_by_type"] = by_type

        meta = {
            "started_at": self._started,
            "finished_at": now_iso(),
            "packets_saved": self._stats,
            "capture_mode": mode,  # "internal"=Proxy Capture, "external"=Browser Session Capture (호환)
            "selenium_wire_active": wired,
        }
        if extra:
            meta.update(extra)
        with self.tokens.open("w", encoding="utf-8") as f:
            json.dump(self._token_store, f, ensure_ascii=False, indent=2)
        with self.meta.open("w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
        with (self.outdir / "readme.txt").open("w", encoding="utf-8") as f:
            f.write(self._readme_text())


# ====== 토큰 수집 유틸 ======
def _collect_from_kv(kv: Dict[str, Any], where: str, url: Optional[str] = None) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for k, v in (kv or {}).items():
        lk = str(k).lower()
        if lk in OAUTH_KEYS:
            out.append({
                "key": k,
                "value": v,
                "where": where,
                "url": url,
                "kind": _classify_oauth_pair(lk, v, where),
            })
    return out


def _decode_jwt_claims(token: str) -> Optional[Dict[str, Any]]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        import json as _json, base64 as _b64
        def _b64pad(s: str) -> bytes:
            pad = '=' * (-len(s) % 4)
            return (s + pad).encode('ascii')
        payload = _b64.urlsafe_b64decode(_b64pad(parts[1]))
        data = _json.loads(payload.decode('utf-8', 'ignore'))
        keep = {k: data.get(k) for k in ("iss", "aud", "sub", "exp", "iat", "nonce") if k in data}
        keep["_token_prefix"] = token[:24] + "..."
        return keep
    except Exception:
        return None


def _extract_and_store_oauth_from_req_resp(aw: ArtifactWriter, req_obj, resp_obj, req_body: bytes, resp_body: bytes) -> None:
    try:
        # URL 파라미터
        up = parse_url_params(getattr(req_obj, 'url', '') or '')
        aw.add_tokens(oauth_tokens=_collect_from_kv(up.get('query', {}), 'request.query', up.get('url')))
        aw.add_tokens(oauth_tokens=_collect_from_kv(up.get('fragment', {}), 'request.fragment', up.get('url')))

        # Authorization: Bearer 스캔
        try:
            aw.add_tokens(oauth_tokens=_collect_from_authz_header(getattr(req_obj, 'headers', {}) or {}, up.get('url')))
        except Exception:
            pass

        # 요청 바디 파싱
        ct_req = ''
        try:
            ct_req = (getattr(req_obj, 'headers', {}) or {}).get('content-type') or ''
        except Exception:
            try:
                ct_req = req_obj.headers.get('Content-Type') or ''
            except Exception:
                ct_req = ''
        body_text = (req_body or b'').decode('latin-1', 'ignore')
        kv: Dict[str, Any] = {}
        if 'application/x-www-form-urlencoded' in ct_req or ('=' in body_text and '&' in body_text):
            kv = dict(parse_qsl(body_text, keep_blank_values=True))
        elif 'application/json' in ct_req:
            try:
                data = json.loads(body_text)
                if isinstance(data, dict):
                    kv = data
            except Exception:
                pass
        if kv:
            aw.add_tokens(oauth_tokens=_collect_from_kv(kv, 'request.body', up.get('url')))

        # 응답 Location 파라미터
        if resp_obj is not None:
            try:
                loc = None
                if hasattr(resp_obj, 'headers'):
                    try:
                        loc = resp_obj.headers.get('Location') or resp_obj.headers.get('location')
                    except Exception:
                        loc = None
                if loc:
                    locp = parse_url_params(loc)
                    aw.add_tokens(oauth_tokens=_collect_from_kv(locp.get('query', {}), 'response.location.query', loc))
                    aw.add_tokens(oauth_tokens=_collect_from_kv(locp.get('fragment', {}), 'response.location.fragment', loc))
            except Exception:
                pass

        # 응답 바디(중요: JSON/폼 + JWT 스캔)
        resp_headers = {}
        try:
            resp_headers = dict(getattr(resp_obj, 'headers', {}) or {})
        except Exception:
            resp_headers = {}
        rtext = _maybe_decode_body(resp_headers, resp_body)

        added = False
        try:
            if rtext.strip().startswith("{"):
                data = json.loads(rtext)
                if isinstance(data, dict):
                    aw.add_tokens(oauth_tokens=_collect_from_kv(data, 'response.body.json', up.get('url')))
                    added = True
        except Exception:
            pass
        if not added and ('=' in rtext and '&' in rtext):
            try:
                kv2 = dict(parse_qsl(rtext, keep_blank_values=True))
                if kv2:
                    aw.add_tokens(oauth_tokens=_collect_from_kv(kv2, 'response.body.form', up.get('url')))
            except Exception:
                pass

        # JWT 스캔 (요청+응답 텍스트)
        joined = ' '.join([body_text or '', rtext or ''])
        tokens = scan_jwts(joined)
        if tokens:
            claims = []
            for t in tokens:
                c = _decode_jwt_claims(t)
                if c:
                    claims.append(c)
            if claims:
                aw.add_tokens(jwt_claims=claims)
            aw.add_tokens(found_jwts=tokens)
    except Exception:
        pass


# ====== mitmproxy & CA ======
MITM_DIR = Path.home() / ".mitmproxy"
CA_PEM = MITM_DIR / "mitmproxy-ca-cert.pem"
CA_CER = MITM_DIR / "mitmproxy-ca-cert.cer"

# (신규) 호스트 PC 영구 환경변수 주입/원복용 파일/마커
HOST_ENV_FILE = Path.home() / ".oauth_vuln_proxy_env.sh"
RC_FILES = [Path.home()/".bashrc", Path.home()/".zshrc", Path.home()/".profile"]
START_MARK = "# >>> oauth-vuln-scanner proxy env >>>"
END_MARK   = "# <<< oauth-vuln-scanner proxy env <<<"

def ensure_pip_package(pkg: str, import_name: Optional[str] = None) -> None:
    name = import_name or pkg.replace("-", "_")
    try:
        __import__(name)
        return
    except Exception:
        pass
    if ask_yes_no(f"'{pkg}'가 설치되어 있지 않습니다. 설치할까요?", default=True):
        rc = _run([sys.executable, "-m", "pip", "install", pkg], check=True, show_progress=True, progress_text=f"pip 설치: {pkg}")
        if rc != 0:
            print(f"[오류] '{pkg}' 설치 실패.")
            sys.exit(2)
    else:
        print("설치를 취소하여 종료합니다.")
        sys.exit(2)


def ensure_mitmdump_available() -> str:
    mitmdump = shutil.which("mitmdump") or shutil.which("mitmdump.exe")
    if mitmdump:
        return mitmdump
    if ask_yes_no("'mitmproxy'가 없습니다. 설치할까요?", default=True):
        rc = _run([sys.executable, "-m", "pip", "install", "mitmproxy"], check=True, show_progress=True, progress_text="pip 설치: mitmproxy")
        if rc == 0:
            mitmdump = shutil.which("mitmdump") or shutil.which("mitmdump.exe")
            if mitmdump:
                return mitmdump
    print("[오류] mitmproxy 설치/확인이 불가하여 종료합니다.")
    sys.exit(2)


def ensure_mitm_ca_files(mitmdump_path: str) -> None:
    """~/.mitmproxy에 CA 파일이 없으면 자동 생성(짧게 mitmdump 가동)."""
    if CA_PEM.exists() or CA_CER.exists():
        return
    print("[안내] mitmproxy CA 파일을 생성합니다...")
    log = Path(tempfile.mkstemp(prefix="mitmdump_boot_", suffix=".log")[1])
    proc = subprocess.Popen([mitmdump_path, "--listen-port", "0", "-q"], stdout=open(log, "w"), stderr=subprocess.STDOUT)
    time.sleep(2.0)
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    if not (CA_PEM.exists() or CA_CER.exists()):
        print("[오류] CA 파일 생성에 실패했습니다.")
        sys.exit(2)


def trust_mitm_ca() -> None:
    """OS에 맞춰 mitm CA를 신뢰 루트에 추가(사용자 동의 필요)."""
    global SELECTED_OS
    pem = str(CA_PEM)
    cer = str(CA_CER if CA_CER.exists() else CA_PEM)

    if not ask_yes_no("mitmproxy 루트 CA를 OS에 신뢰로 추가할까요?", default=True):
        print("사용자가 CA 신뢰 추가를 거부하여 종료합니다.")
        sys.exit(3)

    if SELECTED_OS == "windows":
        rc = _run(["certutil", "-addstore", "-f", "ROOT", cer], check=True, show_progress=True, progress_text="Windows 신뢰 저장소에 CA 추가")
        if rc != 0:
            print("[경고] Windows에 CA 추가 실패. 관리자 PowerShell로 다시 시도해 주세요.")
            sys.exit(3)
    elif SELECTED_OS == "macos":
        rc = _run(["sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k",
                   "/Library/Keychains/System.keychain", pem], check=True, show_progress=True, progress_text="macOS 키체인에 CA 추가")
        if rc != 0:
            print("[경고] macOS에 CA 추가 실패.")
            sys.exit(3)
    elif SELECTED_OS == "ubuntu":
        rc = _run(["sudo", "cp", pem, "/usr/local/share/ca-certificates/mitmproxy-ca.crt"], check=True, show_progress=True, progress_text="CA 복사")
        rc |= _run(["sudo", "update-ca-certificates"], check=True, show_progress=True, progress_text="CA 갱신")
        if rc != 0:
            print("[경고] Debian/Ubuntu에 CA 추가 실패.")
            sys.exit(3)
    elif SELECTED_OS == "rhel":
        rc = _run(["sudo", "cp", pem, "/etc/pki/ca-trust/source/anchors/mitmproxy-ca.crt"], check=True, show_progress=True, progress_text="CA 복사")
        rc |= _run(["sudo", "update-ca-trust"], check=True, show_progress=True, progress_text="CA 갱신")
        if rc != 0:
            print("[경고] RHEL/CentOS/Fedora에 CA 추가 실패.")
            sys.exit(3)
    else:
        print("[안내] 지원되지 않는 OS로 자동 추가를 건너뜁니다.")
        sys.exit(3)


def untrust_mitm_ca(force: bool = True) -> None:
    """OS에 맞춰 mitm CA 신뢰 제거."""
    global SELECTED_OS
    if SELECTED_OS == "windows":
        _run(["powershell", "-Command",
              "Get-ChildItem Cert:\\LocalMachine\\Root | Where-Object { $_.Subject -like '*mitmproxy*' } | Remove-Item -Force"], show_progress=True, progress_text="Windows CA 제거")
    elif SELECTED_OS == "macos":
        _run(["sudo", "security", "delete-certificate", "-c", "mitmproxy", "/Library/Keychains/System.keychain"], show_progress=True, progress_text="macOS CA 제거")
    elif SELECTED_OS == "ubuntu":
        _run(["sudo", "rm", "-f", "/usr/local/share/ca-certificates/mitmproxy-ca.crt"], show_progress=True, progress_text="CA 파일 삭제")
        _run(["sudo", "update-ca-certificates", "--fresh"], show_progress=True, progress_text="CA 갱신")
    elif SELECTED_OS == "rhel":
        _run(["sudo", "rm", "-f", "/etc/pki/ca-trust/source/anchors/mitmproxy-ca.crt"], show_progress=True, progress_text="CA 파일 삭제")
        _run(["sudo", "update-ca-trust"], show_progress=True, progress_text="CA 갱신")


def fetch_mitm_ca_via_proxy(proxy_host: str, proxy_port: int) -> bool:
    """Proxy Setup Assistant: 지정 프록시 경유로 pem 다운로드."""
    sp = _Spinner(f"mitm CA 다운로드 중 (프록시 {proxy_host}:{proxy_port})")
    sp.start()
    try:
        import urllib.request
        MITM_DIR.mkdir(parents=True, exist_ok=True)
        proxy_url = f"http://{proxy_host}:{proxy_port}"
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        )
        with opener.open("http://mitm.it/cert/pem", timeout=15) as resp:
            data = resp.read()
        with open(CA_PEM, "wb") as f:
            f.write(data)
        return True
    except Exception as e:
        print(f"\n[경고] mitm CA 다운로드 실패: {e}")
        return False
    finally:
        sp.stop()

# === 추가: mitm 기본 설정 파일 주입/원복 ===
def ensure_mitm_config_defaults() -> None:
    """
    ~/.mitmproxy/config.yaml에 기본값을 주입:
      - stream_large_bodies: 5m
      - anticomp: true
    기존 파일이 있으면 백업 후 누락 항목만 추가.
    """
    try:
        MITM_DIR.mkdir(parents=True, exist_ok=True)
        cfg = MITM_DIR / "config.yaml"
        want = {
            "stream_large_bodies": "5m",
            "anticomp": True,
        }
        current: Dict[str, Any] = {}
        changed = False
        if cfg.exists():
            # 백업
            bak = cfg.with_suffix(".yaml.bak")
            try:
                shutil.copy2(cfg, bak)
                print(f"[mitmproxy] config.yaml 백업 생성: {bak}")
            except Exception:
                pass
            try:
                import yaml  # type: ignore
                current = yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}
            except Exception:
                txt = cfg.read_text(encoding="utf-8", errors="ignore")
                if "stream_large_bodies" not in txt:
                    txt += "\nstream_large_bodies: 5m\n"
                    changed = True
                if re.search(r"(?m)^\s*anticomp\s*:", txt) is None:
                    txt += "anticomp: true\n"
                    changed = True
                if changed:
                    cfg.write_text(txt, encoding="utf-8")
                    print("[mitmproxy] 기본 캡처 옵션 추가(stream_large_bodies, anticomp).")
                return
        # yaml 사용 가능하면 병합 저장
        try:
            import yaml  # type: ignore
            for k, v in want.items():
                if current.get(k) in (None, "", 0, False):
                    current[k] = v
                    changed = True
            if changed or not cfg.exists():
                cfg.write_text(yaml.safe_dump(current or want, sort_keys=False), encoding="utf-8")
                print("[mitmproxy] 기본 캡처 옵션 적용(stream_large_bodies=5m, anticomp=true).")
        except Exception:
            # YAML 미설치 시 append
            with cfg.open("a", encoding="utf-8") as f:
                for k, v in want.items():
                    f.write(f"{k}: {str(v).lower() if isinstance(v,bool) else v}\n")
            print("[mitmproxy] 기본 캡처 옵션 적용(append).")
    except Exception:
        pass

def revert_mitm_config_defaults() -> None:
    """
    3번에서 주입한 ~/.mitmproxy/config.yaml 변경 원복:
    - .bak가 있으면 복원
    - 없으면 stream_large_bodies/anticomp 키 제거 시도
    """
    try:
        cfg = MITM_DIR / "config.yaml"
        bak = cfg.with_suffix(".yaml.bak")
        if bak.exists():
            try:
                if cfg.exists():
                    cfg.unlink()
                shutil.move(str(bak), str(cfg))
                print("[mitmproxy] config.yaml을 백업본으로 복원했습니다.")
                return
            except Exception as e:
                print(f"[mitmproxy] 백업 복원 실패: {e}")
        if cfg.exists():
            try:
                import yaml  # type: ignore
                data = yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}
                if isinstance(data, dict):
                    changed = False
                    for k in ("stream_large_bodies", "anticomp"):
                        if k in data:
                            data.pop(k, None); changed = True
                    if changed:
                        cfg.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
                        print("[mitmproxy] config.yaml에서 기본 캡처 옵션을 제거했습니다.")
            except Exception:
                # 라인 기반 제거
                txt = cfg.read_text(encoding="utf-8", errors="ignore")
                new = re.sub(r"(?m)^\s*stream_large_bodies\s*:\s*.*\n?", "", txt)
                new = re.sub(r"(?m)^\s*anticomp\s*:\s*.*\n?", "", new)
                if new != txt:
                    cfg.write_text(new, encoding="utf-8")
                    print("[mitmproxy] config.yaml 텍스트 기반으로 옵션을 제거했습니다.")
    except Exception:
        pass
# ====== 시스템 프록시 관리 ======
def _win_proxy_notify() -> None:
    try:
        INTERNET_OPTION_SETTINGS_CHANGED = 39
        INTERNET_OPTION_REFRESH = 37
        ctypes.windll.wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        ctypes.windll.wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
    except Exception:
        pass

def windows_proxy_disable():
    import winreg
    path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as k:
        try:
            winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            try:
                winreg.DeleteValue(k, "ProxyServer")
            except FileNotFoundError:
                pass
        except Exception:
            pass
    _win_proxy_notify()

def _win_proxy_snapshot() -> Dict[str, Any]:
    import winreg
    path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    snap: Dict[str, Any] = {}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ) as k:
            for name in ("ProxyEnable", "ProxyServer", "ProxyOverride"):
                try:
                    v, _ = winreg.QueryValueEx(k, name)
                except FileNotFoundError:
                    v = None
                snap[name] = v
    except Exception:
        pass
    return snap

def _win_proxy_apply(host: str, port: int) -> None:
    import winreg
    path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        server = f"http={host}:{port};https={host}:{port}"
        winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, server)
    _win_proxy_notify()

def _win_proxy_restore(snap: Dict[str, Any]) -> None:
    import winreg
    path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as k:
        pe = snap.get("ProxyEnable")
        if pe is None:
            try:
                winreg.DeleteValue(k, "ProxyEnable")
            except FileNotFoundError:
                pass
        else:
            winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, int(pe))
        ps = snap.get("ProxyServer")
        if ps is None:
            try:
                winreg.DeleteValue(k, "ProxyServer")
            except FileNotFoundError:
                pass
        else:
            winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, ps)
        po = snap.get("ProxyOverride")
        if po is None:
            try:
                winreg.DeleteValue(k, "ProxyOverride")
            except FileNotFoundError:
                pass
        else:
            winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ, po)
    _win_proxy_notify()

class SystemProxyManager:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.os = (SELECTED_OS or "").lower()
        self.backup: Optional[Dict[str, Any]] = None
        self.did_configure_nonwin = False
        self.macos_iface = "Wi-Fi"

    def enable(self) -> None:
        if self.os == "windows":
            self.backup = _win_proxy_snapshot()
            _win_proxy_apply(self.host, self.port)
            print("[proxy] Windows 시스템 프록시를 자동 설정했습니다.")
        elif self.os == "macos":
            iface = self.macos_iface
            cmds = [
                ["sudo", "networksetup", "-setwebproxy", iface, self.host, str(self.port)],
                ["sudo", "networksetup", "-setsecurewebproxy", iface, self.host, str(self.port)],
                ["sudo", "networksetup", "-setwebproxystate", iface, "on"],
                ["sudo", "networksetup", "-setsecurewebproxystate", iface, "on"],
            ]
            ok = True
            for c in cmds: ok &= (_run(c, show_progress=True, progress_text="macOS 시스템 프록시 적용") == 0)
            if ok:
                self.did_configure_nonwin = True
                print("[proxy] macOS 시스템 프록시 설정 완료.")
        elif self.os in ("ubuntu", "rhel"):
            cmds = [
                ["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"],
                ["gsettings", "set", "org.gnome.system.proxy.http", "host", self.host],
                ["gsettings", "set", "org.gnome.system.proxy.http", "port", str(self.port)],
                ["gsettings", "set", "org.gnome.system.proxy.https", "host", self.host],
                ["gsettings", "set", "org.gnome.system.proxy.https", "port", str(self.port)],
            ]
            ok = True
            for c in cmds: ok &= (_run(c, show_progress=True, progress_text="GNOME 시스템 프록시 적용") == 0)
            if ok:
                self.did_configure_nonwin = True
                print("[proxy] GNOME 시스템 프록시 설정 완료.")

    def disable_all(self) -> None:
        if self.os == "windows":
            windows_proxy_disable()
            print("[proxy] Windows 시스템 프록시 비활성화.")
        elif self.os == "macos":
            _run(["sudo", "networksetup", "-setwebproxystate", self.macos_iface, "off"], show_progress=True, progress_text="macOS 웹 프록시 끔")
            _run(["sudo", "networksetup", "-setsecurewebproxystate", self.macos_iface, "off"], show_progress=True, progress_text="macOS HTTPS 프록시 끔")
            print("[proxy] macOS 시스템 프록시 비활성화.")
        elif self.os in ("ubuntu", "rhel"):
            _run(["gsettings", "set", "org.gnome.system.proxy", "mode", "none"], show_progress=True, progress_text="GNOME 프록시 끔")
            print("[proxy] GNOME 시스템 프록시 비활성화.")

    def disable(self) -> None:
        if self.os == "windows" and self.backup is not None:
            _win_proxy_restore(self.backup)
            print("[proxy] 이전 프록시 설정을 복원했습니다.")
        elif self.os == "macos" and self.did_configure_nonwin:
            _run(["sudo", "networksetup", "-setwebproxystate", self.macos_iface, "off"], show_progress=True, progress_text="macOS 웹 프록시 끔")
            _run(["sudo", "networksetup", "-setsecurewebproxystate", self.macos_iface, "off"], show_progress=True, progress_text="macOS HTTPS 프록시 끔")
            print("[proxy] macOS 시스템 프록시를 비활성화했습니다.")
        elif self.os in ("ubuntu", "rhel") and self.did_configure_nonwin:
            _run(["gsettings", "set", "org.gnome.system.proxy", "mode", "none"], show_progress=True, progress_text="GNOME 프록시 끔")
            print("[proxy] GNOME 시스템 프록시를 비활성화했습니다.")

def _wait_proxy_ready(host: str, port: int, proc, log_path: Path, timeout: float = 6.0) -> None:
    start = time.time()
    while time.time() - start < timeout:
        if proc.poll() is not None:
            try:
                print("[오류] mitmdump가 즉시 종료되었습니다.")
                if log_path.exists():
                    print((log_path.read_text(encoding="utf-8", errors="ignore"))[-2000:])
            finally:
                raise SystemExit(2)
        try:
            with socket.create_connection((host, port), timeout=0.3):
                return
        except OSError:
            time.sleep(0.1)
    print("[오류] 프록시 포트에 연결할 수 없습니다. 방화벽/포트충돌을 확인하세요.")
    raise SystemExit(2)

# ====== (신규) 호스트 PC 환경변수 주입/원복 ======
HOST_ENV_BACKUP = Path.home() / ".oauth_vuln_proxy_env_backup.json"

def _write_unix_rc_block(proxy_host: str, proxy_port: int, ca_path: str) -> None:
    block = [
        START_MARK,
        f'export HTTP_PROXY="http://{proxy_host}:{proxy_port}"',
        f'export HTTPS_PROXY="http://{proxy_host}:{proxy_port}"',
        f'export REQUESTS_CA_BUNDLE="{ca_path}"',
        'export SSL_CERT_FILE="$REQUESTS_CA_BUNDLE"',
        END_MARK,
        "",
    ]
    HOST_ENV_FILE.write_text("\n".join(block), encoding="utf-8")
    for rc in RC_FILES:
        try:
            if not rc.exists():
                rc.touch()
            txt = rc.read_text(encoding="utf-8", errors="ignore")
            if START_MARK in txt and END_MARK in txt:
                new = re.sub(rf"{re.escape(START_MARK)}.*?{re.escape(END_MARK)}\n?", "\n".join(block), txt, flags=re.S)
            else:
                new = txt.rstrip() + "\n\n# OAuth Vuln Scanner proxy env\nsource \"$HOME/.oauth_vuln_proxy_env.sh\"\n"
            rc.write_text(new, encoding="utf-8")
        except Exception:
            pass

def _apply_host_env(proxy_host: str, proxy_port: int) -> None:
    ca_path = str(CA_PEM)
    os_name = (SELECTED_OS or "").lower()
    backup = {k: os.environ.get(k) for k in ("HTTP_PROXY", "HTTPS_PROXY", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE")}
    try:
        HOST_ENV_BACKUP.write_text(json.dumps(backup, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass

    if os_name == "windows":
        _run(["setx", "HTTP_PROXY",  f"http://{proxy_host}:{proxy_port}"], show_progress=True, progress_text="Windows: HTTP_PROXY 설정")
        _run(["setx", "HTTPS_PROXY", f"http://{proxy_host}:{proxy_port}"], show_progress=True, progress_text="Windows: HTTPS_PROXY 설정")
        _run(["setx", "REQUESTS_CA_BUNDLE", str(CA_PEM)], show_progress=True, progress_text="Windows: REQUESTS_CA_BUNDLE 설정")
        _run(["setx", "SSL_CERT_FILE", str(CA_PEM)], show_progress=True, progress_text="Windows: SSL_CERT_FILE 설정")
        os.environ.update({
            "HTTP_PROXY": f"http://{proxy_host}:{proxy_port}",
            "HTTPS_PROXY": f"http://{proxy_host}:{proxy_port}",
            "REQUESTS_CA_BUNDLE": str(CA_PEM),
            "SSL_CERT_FILE": str(CA_PEM),
        })
        print("[host-env] Windows 환경변수 주입 완료 (새 콘솔에서 자동 적용).")
    else:
        sp = _Spinner("호스트 환경변수 파일/쉘 설정 적용")
        sp.start()
        try:
            _write_unix_rc_block(proxy_host, proxy_port, ca_path)
        finally:
            sp.stop()
        os.environ.update({
            "HTTP_PROXY": f"http://{proxy_host}:{proxy_port}",
            "HTTPS_PROXY": f"http://{proxy_host}:{proxy_port}",
            "REQUESTS_CA_BUNDLE": ca_path,
            "SSL_CERT_FILE": ca_path,
        })
        print(f"[host-env] UNIX 계열 환경변수 주입 완료 (~/{HOST_ENV_FILE.name} + rc파일에 source 추가).")

def _revert_host_env() -> None:
    os_name = (SELECTED_OS or "").lower()
    old = {}
    try:
        if HOST_ENV_BACKUP.exists():
            old = json.loads(HOST_ENV_BACKUP.read_text(encoding="utf-8"))
    except Exception:
        old = {}
    vars_ = ("HTTP_PROXY", "HTTPS_PROXY", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE")

    if os_name == "windows":
        for k in vars_:
            prev = old.get(k)
            if prev in ("", None):
                _run(["reg", "delete", r"HKCU\Environment", "/v", k, "/f"], show_progress=True, progress_text=f"Windows: {k} 삭제")
            else:
                _run(["setx", k, str(prev)], show_progress=True, progress_text=f"Windows: {k} 복원")
        print("[host-env] Windows 환경변수 원복 완료.")
    else:
        for rc in RC_FILES:
            if not rc.exists():
                continue
            try:
                txt = rc.read_text(encoding="utf-8", errors="ignore")
                new = re.sub(rf"{re.escape(START_MARK)}.*?{re.escape(END_MARK)}\n?", "", txt, flags=re.S)
                rc.write_text(new, encoding="utf-8")
            except Exception:
                pass
        try:
            if HOST_ENV_FILE.exists():
                HOST_ENV_FILE.unlink()
        except Exception:
            pass
        print("[host-env] UNIX 계열 환경변수 원복 완료.")

    try:
        if HOST_ENV_BACKUP.exists():
            HOST_ENV_BACKUP.unlink()
    except Exception:
        pass

# ====== 캡처 실행 (Proxy/Browser) ======
def run_proxy_capture(
    listen_host: str,
    listen_port: int,
    ssl_insecure: bool,
    login_url: Optional[str],
    suppress_untrust_prompt: bool = False,
    auto_setup_during_capture: bool = False,
) -> None:
    """Proxy Capture (요청에 따라 캡처 도중 3번 자동 수행)"""
    mitmdump = ensure_mitmdump_available()
    if login_url:
        ensure_pip_package("selenium", "selenium")

    # CA 확보 + 신뢰
    if not (CA_PEM.exists() or CA_CER.exists()):
        ensure_mitm_ca_files(mitmdump)
    trust_mitm_ca()  # 사용자 동의 후

    aw = ArtifactWriter(PROXY_ARTIFACT_DIR, "Proxy Capture")
    tmp_flows = Path(tempfile.mkstemp(prefix="flows_", suffix=".mitm")[1])
    tmp_log = Path(tempfile.mkstemp(prefix="mitmdump_", suffix=".log")[1])

    # 시스템 프록시 적용:
    # - 같은 PC 시에는 3번(Assistant)에서 적용하므로 여기서는 '지연'
    # - 외부 PC/수동 시에는 즉시 적용
    spm: Optional[SystemProxyManager] = None
    if not auto_setup_during_capture:
        spm = SystemProxyManager(listen_host, listen_port)
        spm.enable()

    cmd = [
        mitmdump,
        "--listen-host", listen_host,
        "--listen-port", str(listen_port),
        "-w", str(tmp_flows),
        "--set", "stream_large_bodies=5m",
        "--set", "anticomp=true",
    ]
    if ssl_insecure:
        cmd.append("--ssl-insecure")

    print(f"[proxy] mitmdump 실행: {' '.join(cmd)}")
    print(f"        이 PC/장치/컨테이너가 {listen_host}:{listen_port} 프록시를 사용하면 트래픽이 캡처됩니다.")
    print("        (브라우저 테스트: http://mitm.it)")

    with open(tmp_log, "w", encoding="utf-8") as lf:
        proc = subprocess.Popen(cmd, stdout=lf, stderr=lf)
    # 바인딩이 0.0.0.0이더라도 로컬 확인은 127.0.0.1로 시도
    _wait_proxy_ready("127.0.0.1" if listen_host in ("0.0.0.0", "::") else listen_host, listen_port, proc, tmp_log)

    driver = None
    try:
        # ====== 요청 기능: 캡처 "도중"에 3번 수행, 이후 브라우저 띄우기 ======
        if auto_setup_during_capture:
            print("\n[자동] Proxy Setup Assistant(3번)을 먼저 수행합니다 (캡처는 이미 동작 중).")
            # 바인딩이 0.0.0.0이면 로컬 클라이언트/환경변수/시스템프록시는 127.0.0.1로 안내
            preset_host = "127.0.0.1" if listen_host in ("0.0.0.0", "::", "localhost") else listen_host
            run_proxy_setup_assistant(preset_host=preset_host, preset_port=listen_port, skip_trust=True)
            print("[자동] 3번 완료. 이제 브라우저를 실행합니다.\n")

        if login_url:
            from selenium.webdriver.chrome.options import Options as ChromeOptions  # type: ignore
            from selenium import webdriver  # type: ignore
            from selenium.common.exceptions import WebDriverException  # type: ignore

            chrome_options = ChromeOptions()
            chrome_options.add_argument(f"--proxy-server=http://127.0.0.1:{listen_port}" if listen_host in ("0.0.0.0", "::") else f"--proxy-server=http://{listen_host}:{listen_port}")
            if ssl_insecure:
                chrome_options.add_argument("--ignore-certificate-errors")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")

            driver = webdriver.Chrome(options=chrome_options)
            start_url, candidates = ensure_url_https_then_http(login_url)
            for idx, u in enumerate(candidates or [start_url]):
                try:
                    driver.get(u)
                    break
                except WebDriverException:
                    if idx == len(candidates) - 1:
                        raise
            print("[Proxy Capture] 브라우저에서 로그인/동작을 수행하세요.")
            input("[Proxy Capture] 완료되면 Enter를 눌러 캡처를 종료합니다...")
        else:
            input("[Proxy Capture] 프록시 캡처 진행 중입니다. 종료하려면 Enter...")
    except KeyboardInterrupt:
        pass
    finally:
        try:
            if driver:
                driver.quit()
        except Exception:
            pass
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    # 플로우 처리
    try:
        from mitmproxy.io import FlowReader
        from http.cookies import SimpleCookie
        if not tmp_flows.exists() or tmp_flows.stat().st_size == 0:
            print("[경고] 수집된 플로우가 없습니다. 프록시/브라우저/CA 설정을 확인하세요.")
        else:
            with tmp_flows.open("rb") as f:
                reader = FlowReader(f)
                for flow in reader.stream():
                    try:
                        if not hasattr(flow, "request"):
                            continue
                        req = flow.request
                        resp = getattr(flow, "response", None)

                        req_body = getattr(req, "raw_content", None) or getattr(req, "content", b"") or b""
                        req_entry = {
                            "ts": now_iso(),
                            "via": "mitmdump",
                            "type": "request",
                            "request": {
                                "method": req.method,
                                "url": req.url,
                                "http_version": getattr(req, "http_version", ""),
                                "headers": dict(req.headers),
                                "body_b64": b64lim(req_body),
                                "url_parts": parse_url_params(req.url),
                            },
                            "response": None,
                            "error": None,
                        }
                        try:
                            auth_tokens = _collect_from_authz_header(req.headers, req.url)
                            if auth_tokens:
                                aw.add_tokens(oauth_tokens=auth_tokens)
                        except Exception:
                            pass
                        try:
                            cookies_hdrs = (
                                req.headers.get_all("cookie") if hasattr(req.headers, "get_all")
                                else ([req.headers.get("cookie")] if req.headers.get("cookie") else [])
                            )
                            for raw in cookies_hdrs:
                                from http.cookies import SimpleCookie as _SC
                                c = _SC(); c.load(raw)
                                for morsel in c.values():
                                    aw.add_tokens(cookies=[{"name": morsel.key, "value": morsel.value, "source": "request"}])
                                    ot = _collect_from_cookies_for_oauth(morsel.key, morsel.value, "cookie.request", req.url)
                                    if ot:
                                        aw.add_tokens(oauth_tokens=[ot])
                        except Exception:
                            pass
                        aw.add_packet(req_entry)

                        resp_body = b""
                        if resp is not None:
                            resp_body = getattr(resp, "content", None) or getattr(resp, "raw_content", b"") or b""
                            resp_entry = {
                                "ts": now_iso(),
                                "via": "mitmdump",
                                "type": "response",
                                "request": None,
                                "response": {
                                    "status_code": getattr(resp, 'status_code', None),
                                    "reason": getattr(resp, 'reason', ''),
                                    "http_version": getattr(resp, 'http_version', ''),
                                    "headers": dict(resp.headers),
                                    "body_b64": b64lim(resp_body),
                                },
                                "error": None,
                            }
                            try:
                                set_cookie_hdrs = (
                                    resp.headers.get_all("set-cookie") if hasattr(resp.headers, "get_all")
                                    else ([resp.headers.get("set-cookie")] if resp.headers.get("set-cookie") else [])
                                )
                                for raw in set_cookie_hdrs:
                                    c = SimpleCookie(); c.load(raw)
                                    for morsel in c.values():
                                        aw.add_tokens(cookies=[{"name": morsel.key, "value": morsel.value, "source": "response"}])
                                        ot = _collect_from_cookies_for_oauth(morsel.key, morsel.value, "cookie.response", getattr(req, "url", None))
                                        if ot:
                                            aw.add_tokens(oauth_tokens=[ot])
                            except Exception:
                                pass
                            aw.add_packet(resp_entry)

                        _extract_and_store_oauth_from_req_resp(aw, req, resp, req_body, resp_body)
                    except Exception as e:
                        aw.add_packet({
                            "ts": now_iso(),
                            "via": "mitmdump",
                            "type": "error",
                            "request": {"method": getattr(getattr(flow, "request", None), "method", None),
                                        "url": getattr(getattr(flow, "request", None), "url", None)},
                            "response": None,
                            "error": {"type": e.__class__.__name__, "msg": str(e)},
                        })
    except Exception as e:
        print(f"[오류] 플로우 파일 처리 중 예외: {e}")
    finally:
        if spm:
            spm.disable()
        for p in (tmp_flows, tmp_log):
            try:
                if p.exists():
                    p.unlink()
            except Exception:
                pass
        aw.finalize(wired=False, mode="internal", extra={
            "listen_host": listen_host,
            "listen_port": listen_port,
            "ssl_insecure": ssl_insecure,
            "login_url": login_url,
        })
        print(f"[완료] 산출물: {aw.outdir}")
        if not suppress_untrust_prompt:
            if ask_yes_no("mitmproxy 루트 CA 신뢰를 원래대로 되돌릴까요?", default=False):
                untrust_mitm_ca()
                print("[안내] CA 신뢰를 원복했습니다.")

def run_browser_session_capture(target: str) -> None:
    """Browser Session Capture"""
    aw = ArtifactWriter(BROWSER_ARTIFACT_DIR, "Browser Session Capture")
    ensure_pip_package("selenium", "selenium")
    try:
        from selenium.webdriver.chrome.options import Options as ChromeOptions  # type: ignore
        from selenium import webdriver  # type: ignore
    except Exception:
        print("[오류] Selenium import 실패.")
        sys.exit(2)

    wired = False
    try:
        __import__("seleniumwire")
        from seleniumwire import webdriver as wired_webdriver  # type: ignore
        wired = True
    except Exception:
        if ask_yes_no("'selenium-wire'를 설치하여 네트워크 캡처를 활성화할까요?", default=False):
            ensure_pip_package("selenium-wire", "seleniumwire")
            from seleniumwire import webdriver as wired_webdriver  # type: ignore
            wired = True

    chrome_options = ChromeOptions()
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")

    driver = wired_webdriver.Chrome(options=chrome_options) if wired else webdriver.Chrome(options=chrome_options)

    try:
        start_url, candidates = ensure_url_https_then_http(target)
        from selenium.common.exceptions import WebDriverException  # type: ignore
        for idx, u in enumerate(candidates or [start_url]):
            try:
                driver.get(u)
                break
            except WebDriverException:
                if idx == len(candidates) - 1:
                    raise
        input("[Browser Session Capture] 브라우저에서 로그인/동작을 마치고 Enter를 누르세요...")

        try:
            cookies = driver.get_cookies()
        except Exception:
            cookies = []
        try:
            ls = driver.execute_script('var o={}; for (var i=0;i<localStorage.length;i++){var k=localStorage.key(i);o[k]=localStorage.getItem(k)}; return o;')
        except Exception:
            ls = {}
        try:
            ss = driver.execute_script('var o={}; for (var i=0;i<sessionStorage.length;i++){var k=sessionStorage.key(i);o[k]=sessionStorage.getItem(k)}; return o;')
        except Exception:
            ss = {}
        aw.add_tokens(cookies=cookies, local_storage=ls, session_storage=ss)

        try:
            cur = driver.current_url
            up = parse_url_params(cur)
            aw.add_tokens(oauth_tokens=_collect_from_kv(up.get('query', {}), 'browser.current_url.query', cur))
            aw.add_tokens(oauth_tokens=_collect_from_kv(up.get('fragment', {}), 'browser.current_url.fragment', cur))
        except Exception:
            pass

        if wired:
            for req in driver.requests:
                try:
                    req_body = req.body or b""

                    req_entry = {
                        "ts": now_iso(),
                        "via": "selenium-wire",
                        "type": "request",
                        "request": {
                            "method": req.method,
                            "url": req.url,
                            "headers": dict(req.headers),
                            "body_b64": b64lim(req_body if isinstance(req_body, (bytes, bytearray)) else str(req_body).encode()),
                            "url_parts": parse_url_params(req.url),
                        },
                        "response": None,
                        "error": None,
                    }
                    aw.add_tokens(oauth_tokens=_collect_from_authz_header(dict(req.headers), req.url))
                    aw.add_packet(req_entry)

                    resp_body = b""
                    resp_obj = None
                    if req.response:
                        resp = req.response
                        try:
                            resp_body = resp.body or b""
                        except Exception:
                            resp_body = b""
                        resp_obj = resp
                        resp_entry = {
                            "ts": now_iso(),
                            "via": "selenium-wire",
                            "type": "response",
                            "request": None,
                            "response": {
                                "status_code": getattr(resp_obj, 'status_code', None),
                                "headers": dict(getattr(resp_obj, 'headers', {})),
                                "body_b64": b64lim(resp_body),
                            },
                            "error": None,
                        }
                        aw.add_packet(resp_entry)

                    _extract_and_store_oauth_from_req_resp(
                        aw, req, resp_obj, req_body if isinstance(req_body, (bytes, bytearray)) else str(req_body).encode(), resp_body
                    )
                except Exception as e:
                    aw.add_packet({
                        "ts": now_iso(),
                        "via": "selenium-wire",
                        "type": "error",
                        "request": {"method": getattr(req, "method", None), "url": getattr(req, "url", None)},
                        "response": None,
                        "error": {"type": e.__class__.__name__, "msg": str(e)},
                    })
        else:
            print("[안내] selenium-wire 미사용: 네트워크 세부 캡처는 생략됩니다.")
    finally:
        try:
            driver.quit()
        except Exception:
            pass
        aw.finalize(wired=wired, mode="external", extra={"target_url": target})
        print(f"[완료] 산출물: {aw.outdir}")

# ====== docker-compose / 컨테이너 유틸 ======
def _compose_find_path() -> Optional[Path]:
    for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        p = Path(name).resolve()
        if p.exists():
            return p
    return None

def _compose_backup(path: Path) -> Path:
    bak = path.with_suffix(path.suffix + ".bak")
    if bak.exists():
        ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        bak = path.with_name(path.name + f".{ts}.bak")
    shutil.copy2(path, bak)
    print(f"[compose] 백업 생성: {bak}")
    return bak

def _compose_dump(path: Path, data: Dict[str, Any]) -> None:
    import yaml  # type: ignore
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False)

def _compose_load(path: Path) -> Dict[str, Any]:
    import yaml  # type: ignore
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def _env_list_to_dict(env) -> Dict[str, str]:
    if isinstance(env, dict):
        return dict(env)
    out: Dict[str, str] = {}
    if isinstance(env, list):
        for item in env:
            if not isinstance(item, str):
                continue
            if "=" in item:
                k, v = item.split("=", 1)
                out[k] = v
            else:
                out[item] = ""
    return out

def _merge_no_proxy(current: str, add: str) -> str:
    cur = [x.strip() for x in (current or "").split(",") if x.strip()]
    extra = [x.strip() for x in (add or "").split(",") if x.strip()]
    merged = []
    for x in cur + extra:
        if x not in merged:
            merged.append(x)
    return ",".join(merged)

def _no_proxy_to_java_hosts(no_proxy: str) -> str:
    parts = [p.strip() for p in no_proxy.split(",") if p.strip()]
    if "127.0.0.1" in parts and "127.*" not in parts:
        parts.append("127.*")
    return "|".join(parts) if parts else "localhost|127.*|::1"

def compose_modify_services(compose_path: Path, proxy_host: str, proxy_port: int) -> List[str]:
    """
    compose 파일을 수정하고, 수정된 서비스명 목록을 반환.
    - HTTP_PROXY/HTTPS_PROXY/NO_PROXY/JAVA_TOOL_OPTIONS/REQUESTS_CA_BUNDLE 주입
    - (개편) 프록시 호스트가 루프백이면 컨테이너용으로 host.docker.internal 사용 + extra_hosts 주입
    """
    data = _compose_load(compose_path)
    services = (data.get("services") or {})
    if not isinstance(services, dict) or not services:
        print("[compose] services 블록을 찾을 수 없습니다. 수정 없이 건너뜁니다.")
        return []

    print("[compose] 발견한 서비스:", ", ".join(services.keys()))
    print("설명: 프록시를 적용할 서비스 이름을 쉼표로 입력하거나 Enter로 전체 적용합니다.")
    pick = input("수정할 서비스 이름들(쉼표, 기본=all): ").strip()
    if not pick or pick.lower() in ("all", "*"):
        target_names = list(services.keys())
    else:
        target_names = [s.strip() for s in pick.split(",") if s.strip() in services]
        if not target_names:
            print("[compose] 유효한 서비스가 없어 전체 적용으로 진행합니다.")
            target_names = list(services.keys())

    # 0.0.0.0도 로컬 바인딩 취급
    is_loopback = proxy_host in ("127.0.0.1", "localhost", "::1", "0.0.0.0")
    container_proxy_host = "host.docker.internal" if is_loopback else proxy_host
    proxy_url = f"http://{container_proxy_host}:{proxy_port}"
    default_no_proxy = "localhost,127.0.0.1,::1,nginx,django,spring"

    print("설명: 프록시를 타지 않을 내부 호스트 목록입니다(콤마로 구분).")
    no_proxy = input(f"NO_PROXY 값 입력 [기본 {default_no_proxy}]: ").strip() or default_no_proxy
    print("설명: Java(Spring) 앱은 JVM 인자도 필요합니다. 해당 서비스명을 쉼표로 입력하거나 빈칸이면 자동 감지(container_name에 'spring' 포함 시 적용).")
    java_pick = input("Java(Spring) 서비스 이름들(쉼표, 없으면 엔터): ").strip()
    java_targets = [s.strip() for s in java_pick.split(",") if s.strip()] if java_pick else []

    modified: List[str] = []
    for name in target_names:
        svc = services.get(name, {}) or {}
        env = _env_list_to_dict(svc.get("environment", {}))

        env["HTTP_PROXY"] = proxy_url
        env["HTTPS_PROXY"] = proxy_url
        env["NO_PROXY"] = _merge_no_proxy(env.get("NO_PROXY", ""), no_proxy)
        env.setdefault("REQUESTS_CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt")

        c_name = str(svc.get("container_name", ""))
        if name in java_targets or ("spring" in c_name.lower()):
            nph = _no_proxy_to_java_hosts(env["NO_PROXY"])
            jtool = env.get("JAVA_TOOL_OPTIONS", "")
            inject = f"-Dhttp.proxyHost={container_proxy_host} -Dhttp.proxyPort={proxy_port} -Dhttps.proxyHost={container_proxy_host} -Dhttps.proxyPort={proxy_port} -Dhttp.nonProxyHosts={nph}"
            if inject not in jtool:
                env["JAVA_TOOL_OPTIONS"] = (jtool + " " + inject).strip()

        svc["environment"] = env

        if is_loopback:
            hosts = list(svc.get("extra_hosts", []) or [])
            if "host.docker.internal:host-gateway" not in hosts:
                hosts.append("host.docker.internal:host-gateway")
            svc["extra_hosts"] = hosts

        services[name] = svc
        modified.append(name)

    data["services"] = services
    _compose_dump(compose_path, data)
    print(f"[compose] docker-compose 수정 완료 → {compose_path}\n")
    if is_loopback:
        print("[안내] 로컬 프록시를 감지하여 컨테이너에는 host.docker.internal로 연결되도록 설정했습니다.")
    print("")
    return modified

def compose_revert_auto(compose_path: Path) -> Optional[Path]:
    candidates = [compose_path.with_suffix(compose_path.suffix + ".bak")]
    for p in compose_path.parent.glob(compose_path.name + ".*.bak"):
        candidates.append(p)
    candidates = [p for p in candidates if p.exists()]
    if not candidates:
        print("[compose] 원복할 .bak를 찾지 못했습니다.")
        return None
    latest = max(candidates, key=lambda p: p.stat().st_mtime)
    try:
        if compose_path.exists():
            compose_path.unlink()
        shutil.move(str(latest), str(compose_path))
        print(f"[compose] 원복 완료: {compose_path}")
        return compose_path
    except Exception as e:
        print(f"[경고] compose 원복 실패: {e}")
        return None

def docker_available() -> bool:
    return shutil.which("docker") is not None

def _docker_ps_service_map() -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    if not docker_available():
        return out
    try:
        res = subprocess.run(["docker", "ps", "-q"], stdout=subprocess.PIPE, text=True)
        ids = [x for x in res.stdout.strip().splitlines() if x.strip()]
        for cid in ids:
            lr = subprocess.run(["docker", "inspect", "-f", "{{ index .Config.Labels \"com.docker.compose.service\"}}", cid],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            svc = lr.stdout.strip()
            if not svc:
                continue
            out.setdefault(svc, []).append(cid)
    except Exception:
        pass
    return out

def docker_configure_container(container: str, proxy_host: str, proxy_port: int, no_proxy: str) -> None:
    # 0.0.0.0도 로컬 취급
    is_loopback = proxy_host in ("127.0.0.1", "localhost", "::1", "0.0.0.0")

    if is_loopback:
        pre = (
            "GW=$(ip route | awk '/default/ {print $3}' || true); "
            "if [ -n \"$GW\" ] && ! grep -q 'host.docker.internal' /etc/hosts 2>/dev/null; then "
            "  echo \"$GW host.docker.internal\" >> /etc/hosts; "
            "fi; "
            "PH=host.docker.internal; "
        )
    else:
        pre = f"PH='{proxy_host}'; "

    cmd1 = [
        "docker", "exec", container, "/bin/sh", "-lc",
        pre +
        f'echo "export HTTP_PROXY=http://$PH:{proxy_port}"  > /etc/profile.d/proxy.sh && '
        f'echo "export HTTPS_PROXY=http://$PH:{proxy_port}" >> /etc/profile.d/proxy.sh && '
        f'echo "export NO_PROXY={no_proxy}" >> /etc/profile.d/proxy.sh && '
        'chmod 644 /etc/profile.d/proxy.sh'
    ]
    _run(cmd1, show_progress=True, progress_text=f"컨테이너 {container}: 프록시 env 주입")

    cmd_fetch = [
        "docker", "exec", container, "/bin/sh", "-lc",
        pre +
        'apk --version >/dev/null 2>&1 && PKG="apk add --no-cache ca-certificates curl" || '
        'PKG="apt-get update && apt-get install -y ca-certificates curl"; '
        '$PKG >/dev/null 2>&1 || true; '
        f'export http_proxy=http://$PH:{proxy_port}; export https_proxy=http://$PH:{proxy_port}; '
        'mkdir -p /usr/local/share/ca-certificates && '
        'curl -fsSL http://mitm.it/cert/pem -o /usr/local/share/ca-certificates/mitmproxy-ca.crt || true; '
        '(command -v update-ca-certificates >/dev/null && update-ca-certificates) || '
        '(command -v update-ca-trust >/dev/null && update-ca-trust) || true'
    ]
    _run(cmd_fetch, show_progress=True, progress_text=f"컨테이너 {container}: CA 설치 및 반영")
    print(f"[docker] 컨테이너 '{container}'에 프록시/CA 설정을 적용했습니다.")

def docker_revert_container(container: str) -> None:
    cmd = [
        "docker", "exec", container, "/bin/sh", "-lc",
        'rm -f /etc/profile.d/proxy.sh || true; '
        'rm -f /usr/local/share/ca-certificates/mitmproxy-ca.crt || true; '
        '(command -v update-ca-certificates >/dev/null && update-ca-certificates --fresh) || '
        '(command -v update-ca-trust >/dev/null && update-ca-trust) || true; '
        "sed -i '/host.docker.internal/d' /etc/hosts 2>/dev/null || true"
    ]
    _run(cmd, show_progress=True, progress_text=f"컨테이너 {container}: 프록시/CA 원복")
    print(f"[docker] 컨테이너 '{container}'의 프록시/CA 주입을 제거했습니다.")

# ====== (개편) Proxy Setup Assistant (3번) ======
def _tcp_test(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

def run_proxy_setup_assistant(preset_host: Optional[str] = None, preset_port: Optional[int] = None, skip_trust: bool = False) -> None:
    """
    서비스 클라이언트(서버)에서 실행해, 지정한 Proxy Capture(IP:PORT)로
    시스템 프록시/CA 신뢰를 자동 적용하고 docker-compose를 감지하면 .bak 백업 후 자동 수정.
    실행 중 컨테이너에도 자동 주입. compose 수정 시에는 up -d 자동 실행.
    mitm 기본 로깅(stream_large_bodies, anticomp) 및 (신규) 호스트 PC 환경변수 주입도 포함.
    - 같은 PC에서 바인딩이 0.0.0.0이면:
      * 로컬 클라이언트/브라우저/환경변수/시스템프록시는 127.0.0.1:{port}
      * 컨테이너/compose는 host.docker.internal:{port}
    """
    print("\n[Proxy Setup Assistant]")
    print("설명: 진단 PC의 Proxy Capture(IP:PORT)로 이 시스템/도커 서비스를 연결시키는 모드입니다.")

    if preset_host is not None and preset_port is not None:
        proxy_host_in = preset_host
        proxy_port = int(preset_port)
        print(f"[자동] 프록시 호스트/포트: {proxy_host_in}:{proxy_port}")
    else:
        proxy_host_in = input("진단 PC의 프록시 호스트/IP (예: 10.0.0.5 또는 127.0.0.1): ").strip()
        if not proxy_host_in:
            print("[오류] 호스트가 필요합니다.")
            return
        try:
            proxy_port = int(input("프록시 포트 (예: 18080): ").strip())
        except ValueError:
            print("[오류] 올바른 포트를 입력하세요.")
            return

    # 0.0.0.0/localhost/127.0.0.1 는 로컬 취급
    is_local = proxy_host_in in ("127.0.0.1", "localhost", "0.0.0.0", "::1")
    host_for_local_clients = "127.0.0.1" if is_local else proxy_host_in
    host_for_containers = "host.docker.internal" if is_local else proxy_host_in

    compose_path = _compose_find_path()
    if compose_path:
        ensure_pip_package("pyyaml", "yaml")

    if _tcp_test(host_for_local_clients, proxy_port):
        print(f"[연결 확인] {host_for_local_clients}:{proxy_port} TCP 연결 성공.")
    else:
        print(f"[경고] {host_for_local_clients}:{proxy_port} 에 연결할 수 없습니다. 방화벽/네트워크를 확인하세요.")

    # 시스템 프록시 설정 (로컬 클라이언트 기준)
    spm = SystemProxyManager(host_for_local_clients, proxy_port)
    spm.enable()

    # mitm CA 다운로드 & 신뢰
    if not skip_trust:
        ca_downloaded = fetch_mitm_ca_via_proxy(host_for_local_clients, proxy_port)
        if ca_downloaded:
            trust_mitm_ca()
        else:
            print("[경고] 프록시 경유 mitm CA 다운로드 실패. system 신뢰 추가를 생략했습니다.")

    # mitm 기본 로깅 적용
    ensure_mitm_config_defaults()
    print("[mitmproxy] 기본 캡처 설정(stream_large_bodies=5m, anticomp=true)을 적용했습니다.")

    # (신규) 호스트 PC 환경변수 자동 주입 (로컬 클라이언트 기준)
    _apply_host_env(host_for_local_clients, proxy_port)

    # docker-compose 수정 + up -d  (컨테이너 기준 호스트 사용)
    modified_services: List[str] = []
    if compose_path:
        print(f"[compose] 감지: {compose_path.name}")
        compose_bak = _compose_backup(compose_path)
        # compose 함수 내부에서 host.docker.internal로 변환되도록 로컬 호스트를 전달
        modified_services = compose_modify_services(compose_path, "127.0.0.1" if is_local else proxy_host_in, proxy_port)
        if modified_services:
            up_cmd = None
            if shutil.which("docker") and _run(["docker", "compose", "version"]) == 0:
                up_cmd = ["docker", "compose", "up", "-d"]
            elif shutil.which("docker-compose"):
                up_cmd = ["docker-compose", "up", "-d"]
            if up_cmd:
                _run(up_cmd, show_progress=True, progress_text="docker compose 배포(up -d)")
            else:
                print("[경고] docker compose/ docker-compose 명령을 찾지 못했습니다. 수동으로 배포하세요.")
        else:
            try:
                if compose_bak.exists():
                    compose_bak.unlink()
            except Exception:
                pass
    else:
        print("[compose] 현재 경로에서 docker-compose 파일을 찾지 못했습니다. (자동 수정 생략)")

    # 실행 중 컨테이너 자동 주입 (컨테이너 기준 호스트 사용)
    if docker_available():
        svc_map = _docker_ps_service_map()
        targets: List[str] = []
        if modified_services:
            for s in modified_services:
                targets.extend(svc_map.get(s, []))
        if not targets:
            print("설명: 실행 중 컨테이너에 프록시/CA를 주입합니다. 자동 탐지에 실패하면 이름/ID를 입력하세요(쉼표 가능).")
            manual = input("컨테이너 이름/ID들 (엔터=건너뜀): ").strip()
            if manual:
                targets = [x.strip() for x in manual.split(",") if x.strip()]
        if targets:
            no_proxy_default = "localhost,127.0.0.1,::1,nginx,django,spring"
            # 컨테이너 함수에 '로컬 호스트'를 넘겨서 host.docker.internal 로 셋업되도록
            for cid in targets:
                docker_configure_container(cid, "127.0.0.1" if is_local else proxy_host_in, proxy_port, no_proxy_default)
        else:
            print("[docker] 주입 대상 컨테이너를 찾지 못해 컨테이너 주입을 생략했습니다.")
    else:
        print("[안내] Docker CLI가 감지되지 않아 Docker 설정 단계는 건너뜁니다.")

    print("[완료] Proxy Setup Assistant 작업을 마쳤습니다.")

# ====== (신규) Proxy Setup Revert (4번) ======
def run_proxy_setup_revert() -> None:
    """
    시스템 프록시 비활성화, mitm CA 제거, docker-compose 원복(+ up -d),
    실행 중 컨테이너의 프록시/CA 주입 제거, mitm 기본 로깅 원복,
    (신규) 호스트 PC 환경변수 원복을 자동 수행.
    """
    print("\n[Proxy Setup Revert]")
    print("설명: 3번에서 적용한 프록시/CA/compose/컨테이너 주입/mitm/호스트 환경변수를 원래대로 되돌립니다.")

    # 1) 시스템 프록시 비활성화
    spm = SystemProxyManager("0.0.0.0", 0)
    spm.disable_all()

    # 2) 호스트 환경변수 원복
    _revert_host_env()

    # 3) mitm CA 제거
    untrust_mitm_ca()

    # 4) mitm 기본 로깅 설정 원복
    revert_mitm_config_defaults()

    # 5) compose 원복(+ up -d)
    compose_path = _compose_find_path()
    if compose_path:
        reverted = compose_revert_auto(compose_path)
        if reverted:
            up_cmd = None
            if shutil.which("docker") and _run(["docker", "compose", "version"]) == 0:
                up_cmd = ["docker", "compose", "up", "-d"]
            elif shutil.which("docker-compose"):
                up_cmd = ["docker-compose", "up", "-d"]
            if up_cmd:
                _run(up_cmd, show_progress=True, progress_text="docker compose 재배포(up -d)")
            else:
                print("[경고] docker compose/ docker-compose 명령을 찾지 못했습니다. 수동으로 배포하세요.")
    else:
        print("[compose] 현재 경로에서 docker-compose 파일을 찾지 못했습니다. (원복 생략)")

    # 6) 실행 중 컨테이너의 주입 제거 (전체 대상)
    if docker_available():
        svc_map = _docker_ps_service_map()
        all_containers = [cid for ids in svc_map.values() for cid in ids]
        if not all_containers:
            res = subprocess.run(["docker", "ps", "-q"], stdout=subprocess.PIPE, text=True)
            all_containers = [x for x in res.stdout.strip().splitlines() if x.strip()]
        if all_containers:
            for cid in all_containers:
                docker_revert_container(cid)
        else:
            print("[docker] 실행 중 컨테이너가 없거나 식별하지 못했습니다.")
    else:
        print("[안내] Docker CLI가 감지되지 않아 컨테이너 원복 단계는 건너뜁니다.")

    print("[완료] Proxy Setup Revert 작업을 마쳤습니다.")

# ====== OS 선택 & 메인 ======
def choose_os() -> str:
    detected = platform.system().lower()
    map_guess = {"windows": "windows", "darwin": "macos", "linux": "ubuntu"}
    guess = map_guess.get(detected, "other")
    print("=== OS 선택 ===")
    print("1) Windows")
    print("2) macOS")
    print("3) Ubuntu/Debian")
    print("4) RHEL/CentOS/Fedora")
    print("5) 기타/수동")
    sel = input(f"번호 선택 [기본 { {'windows':1,'macos':2,'ubuntu':3,'rhel':4,'other':5}[guess] } ]: ").strip()
    mapping = {"1":"windows","2":"macos","3":"ubuntu","4":"rhel","5":"other","":guess}
    return mapping.get(sel, guess)

def main() -> None:
    global SELECTED_OS
    SELECTED_OS = choose_os()
    print("\n=== OAuth Vuln Scanner ===")
    print("산출물 폴더: Proxy=./proxy_artifacts, Browser=./browser_artifacts")
    print("모드 선택: 1) Proxy Capture  2) Browser Session Capture  3) Proxy Setup Assistant  4) Proxy Setup Revert  q) 종료")

    choice = input("선택 입력 [1/2/3/4/q]: ").strip().lower()
    if choice in ("q", "quit"):
        print("종료합니다.")
        return

    if choice == "1":
        print("\n[Proxy Capture] 이 PC에서 mitmproxy를 실행해, 이 프록시를 경유하는 요청/응답 트래픽을 캡처합니다.")

        same_pc = ask_yes_no("이 PC에서 서비스 클라이언트(컨테이너/앱)가 구동 중입니까? (같은 PC)", default=True)

        if same_pc:
            # 요구사항: 같은 PC면 0.0.0.0:18080으로 열고, 캡처 도중 3번 자동수행
            listen_host = "0.0.0.0"
            listen_port = 18080
            print(f"[자동] 같은 PC로 판단 → 프록시를 {listen_host}:{listen_port} 로 바인딩합니다.")
        else:
            listen_host = input("프록시 호스트 [기본 0.0.0.0]: ").strip() or "0.0.0.0"
            try:
                listen_port = int(input("프록시 포트 [기본 18080]: ").strip() or "18080")
            except ValueError:
                print("잘못된 포트 값입니다. 18080으로 진행합니다.")
                listen_port = 18080

        ssl_insecure = ask_yes_no("서버 인증서 검증을 생략하시겠습니까?", default=False)

        print("설명: 로그인 플로우를 캡처하려면 브라우저로 로그인 페이지를 띄울 수 있습니다.")
        open_login = ask_yes_no("로그인 페이지가 필요합니까?", default=True)
        login_url: Optional[str] = None
        if open_login:
            login_url = input("로그인 페이지 URL을 입력하세요 (예: example.com/login): ").strip() or None

        run_proxy_capture(
            listen_host, listen_port, ssl_insecure, login_url,
            suppress_untrust_prompt=same_pc,
            auto_setup_during_capture=same_pc
        )
        return

    if choice == "2":
        print("\n[Browser Session Capture] 도구가 띄운 브라우저 '한 세션'에서 발생하는 요청/응답을 캡처합니다.")
        target = input("오픈할 URL을 입력하세요 (예: example.com/login): ").strip()
        if not target:
            print("[오류] URL이 필요합니다. 다시 실행하세요.")
            return
        run_browser_session_capture(target)
        return

    if choice == "3":
        # 수동 실행 시에도 로컬이면 127.0.0.1 사용을 권장
        run_proxy_setup_assistant()
        return

    if choice == "4":
        run_proxy_setup_revert()
        return

    print("알 수 없는 선택입니다. 다시 실행하세요.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[중단됨] 사용자에 의해 종료")
        sys.exit(130)

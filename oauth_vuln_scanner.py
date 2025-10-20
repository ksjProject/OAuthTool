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
    2) Browser Session Capture
    3) Proxy Setup Assistant   ← (신규) 프록시/CA 설정 자동화 + (추가) docker-compose.yml 자동 수정

- CA 체크/설정:
    Proxy Capture에서 필요 시 자동 생성·신뢰/원복(사용자 동의 후 실행)
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


def _run(cmd: List[str], check: bool = False) -> int:
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
            "oauth_tokens": [],
            "jwt_claims": [],
        }
        self._started = now_iso()

    def add_packet(self, pkt: Dict[str, Any]) -> None:
        # 요청/응답을 별도 레코드로 순서 기록 (type: request|response|error)
        write_jsonl(self.packets, pkt)
        kind = pkt.get("type")
        if kind == "request":
            self._stats["requests"] += 1
        elif kind == "response":
            self._stats["responses"] += 1
        if pkt.get("error"):
            self._stats["errors"] += 1

    def add_tokens(self, **kw) -> None:
        for k in ("cookies", "auth_headers", "found_jwts", "oauth_tokens", "jwt_claims"):
            if kw.get(k):
                if isinstance(self._token_store.get(k), list):
                    self._token_store[k].extend(kw[k])
        if kw.get("local_storage"):
            self._token_store["local_storage"].update(kw["local_storage"])
        if kw.get("session_storage"):
            self._token_store["session_storage"].update(kw["session_storage"])

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
        """key+value가 동일하면 하나로 통합하고, where는 콤마+공백(“, ”)으로 합친다."""
        grouped: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for it in items:
            k = str(it.get("key"))
            v = str(it.get("value"))
            w = str(it.get("where", "") or "")
            u = it.get("url")
            gv = grouped.get((k, v))
            if not gv:
                grouped[(k, v)] = {"key": k, "value": v, "where_list": [], "url": u}
            if w and w not in grouped[(k, v)]["where_list"]:
                grouped[(k, v)]["where_list"].append(w)
            if not grouped[(k, v)]["url"] and u:
                grouped[(k, v)]["url"] = u
        out: List[Dict[str, Any]] = []
        for (_k, _v), rec in grouped.items():
            out.append({
                "key": _k,
                "value": _v,
                "where": ", ".join(rec["where_list"]),
                "url": rec.get("url"),
            })
        return out

    def _readme_text(self) -> str:
        if self.mode_label == "Proxy Capture":
            header = [
                "이 폴더는 'Proxy Capture' 모드의 산출물입니다.",
                "이 모드는 이 PC를 프록시로 실행하고, 해당 프록시를 경유하는 요청/응답 트래픽을 캡처하여 OAuth 관련 이슈를 점검합니다.",
                "",
                "[파일 설명]",
                "- packets.jsonl: 캡처된 요청/응답을 한 줄당 한 건씩 순서대로 기록(type=request/response).",
                "- session_token.json: 쿠키/스토리지/Authorization/JWT 및 OAuth 파라미터(code/access_token/id_token 등) 요약.",
                "- run_meta.json: 실행 시간/모드/카운트/대상 정보 등의 메타데이터.",
            ]
        else:
            header = [
                "이 폴더는 'Browser Session Capture' 모드의 산출물입니다.",
                "이 모드는 도구가 띄운 브라우저의 한 세션 동안 발생한 요청/응답 트래픽을 캡처하여 OAuth 관련 이슈를 점검합니다.",
                "",
                "[파일 설명]",
                "- packets.jsonl: 캡처된 요청/응답을 한 줄당 한 건씩 순서대로 기록(type=request/response).",
                "- session_token.json: 쿠키/스토리지/Authorization/JWT 및 OAuth 파라미터(code/access_token/id_token 등) 요약.",
                "- run_meta.json: 실행 시간/모드/카운트/대상 정보 등의 메타데이터.",
            ]
        return os.linesep.join(header)

    def finalize(self, wired: bool, mode: str, extra: Optional[Dict[str, Any]] = None) -> None:
        # 리스트형 필드 기본 dedupe
        self._token_store["cookies"] = self._dedupe_list(self._token_store.get("cookies", []))
        self._token_store["auth_headers"] = self._dedupe_list(self._token_store.get("auth_headers", []))
        self._token_store["found_jwts"] = self._dedupe_list(self._token_store.get("found_jwts", []))
        self._token_store["jwt_claims"] = self._dedupe_list(self._token_store.get("jwt_claims", []))
        # oauth_tokens는 'key+value' 기준으로 통합(중복 완전 제거 + where 병합: 콤마)
        self._token_store["oauth_tokens"] = self._merge_oauth_tokens_by_key_value(
            self._token_store.get("oauth_tokens", [])
        )
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
    for k, v in kv.items():
        lk = str(k).lower()
        if lk in OAUTH_KEYS:
            out.append({"key": k, "value": v, "where": where, "url": url})
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
        up = parse_url_params(getattr(req_obj, 'url', '') or '')
        aw.add_tokens(oauth_tokens=_collect_from_kv(up.get('query', {}), 'request.query', up.get('url')))
        aw.add_tokens(oauth_tokens=_collect_from_kv(up.get('fragment', {}), 'request.fragment', up.get('url')))
        ct = ''
        try:
            ct = (getattr(req_obj, 'headers', {}) or {}).get('content-type') or ''
        except Exception:
            try:
                ct = req_obj.headers.get('Content-Type') or ''
            except Exception:
                ct = ''
        body_text = (req_body or b'').decode('latin-1', 'ignore')
        kv: Dict[str, Any] = {}
        if 'application/x-www-form-urlencoded' in ct or ('=' in body_text and '&' in body_text):
            kv = dict(parse_qsl(body_text, keep_blank_values=True))
        elif 'application/json' in ct:
            try:
                data = json.loads(body_text)
                if isinstance(data, dict):
                    kv = data
            except Exception:
                pass
        if kv:
            aw.add_tokens(oauth_tokens=_collect_from_kv(kv, 'request.body', up.get('url')))
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
        rtext = (resp_body or b'').decode('latin-1', 'ignore')
        tokens = scan_jwts(' '.join([body_text, rtext]))
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

def ensure_pip_package(pkg: str, import_name: Optional[str] = None) -> None:
    name = import_name or pkg.replace("-", "_")
    try:
        __import__(name)
        return
    except Exception:
        pass
    if ask_yes_no(f"'{pkg}'가 설치되어 있지 않습니다. 설치할까요?", default=True):
        rc = _run([sys.executable, "-m", "pip", "install", pkg], check=True)
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
        rc = _run([sys.executable, "-m", "pip", "install", "mitmproxy"], check=True)
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
        cmd = ["certutil", "-addstore", "-f", "ROOT", cer]
        rc = _run(cmd, check=True)
        if rc != 0:
            print("[경고] Windows에 CA 추가 실패. 관리자 PowerShell로 다시 시도해 주세요.")
            sys.exit(3)
    elif SELECTED_OS == "macos":
        cmd = ["sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot",
               "-k", "/Library/Keychains/System.keychain", pem]
        rc = _run(cmd, check=True)
        if rc != 0:
            print("[경고] macOS에 CA 추가 실패.")
            sys.exit(3)
    elif SELECTED_OS == "ubuntu":
        dst = "/usr/local/share/ca-certificates/mitmproxy-ca.crt"
        rc = _run(["sudo", "cp", pem, dst], check=True)
        rc |= _run(["sudo", "update-ca-certificates"], check=True)
        if rc != 0:
            print("[경고] Debian/Ubuntu에 CA 추가 실패.")
            sys.exit(3)
    elif SELECTED_OS == "rhel":
        dst = "/etc/pki/ca-trust/source/anchors/mitmproxy-ca.crt"
        rc = _run(["sudo", "cp", pem, dst], check=True)
        rc |= _run(["sudo", "update-ca-trust"], check=True)
        if rc != 0:
            print("[경고] RHEL/CentOS/Fedora에 CA 추가 실패.")
            sys.exit(3)
    else:
        print("[안내] 지원되지 않는 OS로 자동 추가를 건너뜁니다.")
        sys.exit(3)


def untrust_mitm_ca() -> None:
    """OS에 맞춰 mitm CA 신뢰 제거."""
    global SELECTED_OS
    if SELECTED_OS == "windows":
        cmd = ["powershell", "-Command",
               "Get-ChildItem Cert:\\LocalMachine\\Root | Where-Object { $_.Subject -like '*mitmproxy*' } | Remove-Item -Force"]
        _run(cmd)
    elif SELECTED_OS == "macos":
        _run(["sudo", "security", "delete-certificate", "-c", "mitmproxy", "/Library/Keychains/System.keychain"])
    elif SELECTED_OS == "ubuntu":
        _run(["sudo", "rm", "-f", "/usr/local/share/ca-certificates/mitmproxy-ca.crt"])
        _run(["sudo", "update-ca-certificates", "--fresh"])
    elif SELECTED_OS == "rhel":
        _run(["sudo", "rm", "-f", "/etc/pki/ca-trust/source/anchors/mitmproxy-ca.crt"])
        _run(["sudo", "update-ca-trust"])


def fetch_mitm_ca_via_proxy(proxy_host: str, proxy_port: int) -> bool:
    """Proxy Setup Assistant: 지정 프록시 경유로 pem 다운로드."""
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
        print(f"[경고] mitm CA 다운로드 실패: {e}")
        return False


# ====== 시스템 프록시 관리 ======
def _win_proxy_notify() -> None:
    try:
        INTERNET_OPTION_SETTINGS_CHANGED = 39
        INTERNET_OPTION_REFRESH = 37
        ctypes.windll.wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        ctypes.windll.wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
    except Exception:
        pass


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
            if ask_yes_no("macOS 시스템 프록시를 자동 설정할까요?", default=True):
                iface = input(f"네트워크 서비스 이름 입력 [기본 {self.macos_iface}]: ").strip() or self.macos_iface
                cmds = [
                    ["sudo", "networksetup", "-setwebproxy", iface, self.host, str(self.port)],
                    ["sudo", "networksetup", "-setsecurewebproxy", iface, self.host, str(self.port)],
                    ["sudo", "networksetup", "-setwebproxystate", iface, "on"],
                    ["sudo", "networksetup", "-setsecurewebproxystate", iface, "on"],
                ]
                ok = True
                for c in cmds:
                    if _run(c) != 0:
                        ok = False
                if ok:
                    self.did_configure_nonwin = True
                    self.macos_iface = iface
                    print("[proxy] macOS 시스템 프록시 설정 완료.")
                else:
                    print("[경고] 일부 명령 실패. 수동 확인이 필요할 수 있습니다.")
        elif self.os in ("ubuntu", "rhel"):
            if ask_yes_no("GNOME 시스템 프록시를 자동 설정할까요?", default=False):
                cmds = [
                    ["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"],
                    ["gsettings", "set", "org.gnome.system.proxy.http", "host", self.host],
                    ["gsettings", "set", "org.gnome.system.proxy.http", "port", str(self.port)],
                    ["gsettings", "set", "org.gnome.system.proxy.https", "host", self.host],
                    ["gsettings", "set", "org.gnome.system.proxy.https", "port", str(self.port)],
                ]
                ok = True
                for c in cmds:
                    if _run(c) != 0:
                        ok = False
                if ok:
                    self.did_configure_nonwin = True
                    print("[proxy] GNOME 시스템 프록시 설정 완료.")
                else:
                    print("[경고] 일부 명령 실패. 데스크톱 환경/권한을 확인하세요.")
        else:
            print("[안내] 시스템 프록시 자동 설정은 생략합니다.")

    def disable(self) -> None:
        if self.os == "windows" and self.backup is not None:
            _win_proxy_restore(self.backup)
            print("[proxy] 이전 프록시 설정을 복원했습니다.")
        elif self.os == "macos" and self.did_configure_nonwin:
            cmds = [
                ["sudo", "networksetup", "-setwebproxystate", self.macos_iface, "off"],
                ["sudo", "networksetup", "-setsecurewebproxystate", self.macos_iface, "off"],
            ]
            for c in cmds:
                _run(c)
            print("[proxy] macOS 시스템 프록시를 비활성화했습니다.")
        elif self.os in ("ubuntu", "rhel") and self.did_configure_nonwin:
            _run(["gsettings", "set", "org.gnome.system.proxy", "mode", "none"])
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


# ====== 캡처 실행 (Proxy/Browser) ======
def run_proxy_capture(listen_host: str, listen_port: int, ssl_insecure: bool, login_url: Optional[str]) -> None:
    """Proxy Capture"""
    mitmdump = ensure_mitmdump_available()
    if not (CA_PEM.exists() or CA_CER.exists()):
        ensure_mitm_ca_files(mitmdump)
    # 보수적으로 항상 질의 후 신뢰 추가
    trust_mitm_ca()

    aw = ArtifactWriter(PROXY_ARTIFACT_DIR, "Proxy Capture")

    tmp_flows = Path(tempfile.mkstemp(prefix="flows_", suffix=".mitm")[1])
    tmp_log = Path(tempfile.mkstemp(prefix="mitmdump_", suffix=".log")[1])

    spm = SystemProxyManager(listen_host, listen_port)
    spm.enable()

    cmd = [
        mitmdump,
        "--listen-host", listen_host,
        "--listen-port", str(listen_port),
        "-w", str(tmp_flows),
        "--set", "stream_large_bodies=5m",
    ]
    if ssl_insecure:
        cmd.append("--ssl-insecure")

    print(f"[proxy] mitmdump 실행: {' '.join(cmd)}")
    print(f"        이 PC/장치/컨테이너가 {listen_host}:{listen_port} 프록시를 사용하면 트래픽이 캡처됩니다.")
    print("        (브라우저 테스트: http://mitm.it)")

    with open(tmp_log, "w", encoding="utf-8") as lf:
        proc = subprocess.Popen(cmd, stdout=lf, stderr=lf)
    _wait_proxy_ready(listen_host, listen_port, proc, tmp_log)

    driver = None
    try:
        if login_url:
            ensure_pip_package("selenium", "selenium")
            from selenium.webdriver.chrome.options import Options as ChromeOptions  # type: ignore
            from selenium import webdriver  # type: ignore
            from selenium.common.exceptions import WebDriverException  # type: ignore

            chrome_options = ChromeOptions()
            chrome_options.add_argument(f"--proxy-server=http://{listen_host}:{listen_port}")
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

    try:
        ensure_pip_package("mitmproxy", "mitmproxy")
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

                        # ---- 요청 레코드 ----
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
                        # Authorization 헤더(요청에서 추출)
                        try:
                            auth = [v for k, v in req.headers.items(multi=True) if k.lower() == "authorization"]
                        except TypeError:
                            auth = [v for k, v in dict(req.headers).items() if k.lower() == "authorization"]
                        if auth:
                            aw.add_tokens(auth_headers=auth)
                        # 요청 쿠키 추출
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
                        except Exception:
                            pass
                        aw.add_packet(req_entry)

                        # ---- 응답 레코드(있다면) ----
                        resp_body = b""
                        if resp is not None:
                            resp_body = getattr(resp, "raw_content", None) or getattr(resp, "content", b"") or b""
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
                            # 응답 set-cookie 추출
                            try:
                                set_cookie_hdrs = (
                                    resp.headers.get_all("set-cookie") if hasattr(resp.headers, "get_all")
                                    else ([resp.headers.get("set-cookie")] if resp.headers.get("set-cookie") else [])
                                )
                                for raw in set_cookie_hdrs:
                                    c = SimpleCookie(); c.load(raw)
                                    for morsel in c.values():
                                        aw.add_tokens(cookies=[{"name": morsel.key, "value": morsel.value, "source": "response"}])
                            except Exception:
                                pass
                            aw.add_packet(resp_entry)

                        # OAuth & JWT(요청/응답 모두 고려)
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

        # 기본 세션 저장소 수집
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

        # 주소창 URL 파라미터 수집
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

                    # ---- 요청 ----
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
                    # Authorization 헤더
                    auth = [v for k, v in dict(req.headers).items() if k.lower() == "authorization"]
                    if auth:
                        aw.add_tokens(auth_headers=auth)
                    aw.add_packet(req_entry)

                    # ---- 응답(있으면) ----
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

                    # OAuth/JWT 추출
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


# ====== (신규) docker-compose.yml 자동 수정 유틸 ======
def _compose_find_path() -> Optional[Path]:
    for name in ("docker-compose.yml", "docker-compose.yaml"):
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
    ensure_pip_package("pyyaml", "yaml")
    import yaml  # type: ignore
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False)


def _compose_load(path: Path) -> Dict[str, Any]:
    ensure_pip_package("pyyaml", "yaml")
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
    # Java nonProxyHosts는 '|' 구분, 와일드카드 * 지원
    parts = [p.strip() for p in no_proxy.split(",") if p.strip()]
    if "127.0.0.1" in parts and "127.*" not in parts:
        parts.append("127.*")
    return "|".join(parts) if parts else "localhost|127.*|::1"


def compose_modify_services(compose_path: Path, proxy_host: str, proxy_port: int) -> None:
    data = _compose_load(compose_path)
    services = (data.get("services") or {})
    if not isinstance(services, dict) or not services:
        print("[compose] services 블록을 찾을 수 없습니다. 수정 없이 건너뜁니다.")
        return

    print("[compose] 발견한 서비스:", ", ".join(services.keys()))
    pick = input("수정할 서비스 이름들(쉼표, 기본=all): ").strip()
    if not pick or pick.lower() in ("all", "*"):
        target_names = list(services.keys())
    else:
        target_names = [s.strip() for s in pick.split(",") if s.strip() in services]
        if not target_names:
            print("[compose] 유효한 서비스가 없어 전체 적용으로 진행합니다.")
            target_names = list(services.keys())

    proxy_url = f"http://{proxy_host}:{proxy_port}"
    default_no_proxy = "localhost,127.0.0.1,::1,nginx,django,spring"

    no_proxy = input(f"NO_PROXY 값 입력 [기본 {default_no_proxy}]: ").strip() or default_no_proxy
    java_pick = input("Java(Spring) 서비스 이름들(쉼표, 없으면 엔터): ").strip()
    java_targets = [s.strip() for s in java_pick.split(",") if s.strip()] if java_pick else []

    for name in target_names:
        svc = services.get(name, {})
        env = _env_list_to_dict(svc.get("environment", {}))

        env["HTTP_PROXY"] = proxy_url
        env["HTTPS_PROXY"] = proxy_url
        env["NO_PROXY"] = _merge_no_proxy(env.get("NO_PROXY", ""), no_proxy)

        if name in java_targets:
            nph = _no_proxy_to_java_hosts(env["NO_PROXY"])
            jtool = env.get("JAVA_TOOL_OPTIONS", "")
            inject = f"-Dhttp.proxyHost={proxy_host} -Dhttp.proxyPort={proxy_port} -Dhttps.proxyHost={proxy_host} -Dhttps.proxyPort={proxy_port} -Dhttp.nonProxyHosts={nph}"
            if inject not in jtool:
                env["JAVA_TOOL_OPTIONS"] = (jtool + " " + inject).strip()

        # 다시 할당(리스트 대신 dict로 유지)
        svc["environment"] = env
        services[name] = svc

    data["services"] = services
    _compose_dump(compose_path, data)
    print(f"[compose] docker-compose 수정 완료 → {compose_path}")
    print("")
    print("[원복 가이드]")
    print("  Linux/macOS:")
    print("    rm -f docker-compose.yml && mv docker-compose.yml.bak docker-compose.yml")
    print("  Windows PowerShell:")
    print("    Remove-Item docker-compose.yml")
    print("    Rename-Item docker-compose.yml.bak docker-compose.yml")
    print("")

    # 적용 여부 확인
    if ask_yes_no("지금 바로 docker compose를 갱신(재배포)할까요? (up -d)", default=False):
        # 플러그인/별도 바이너리 둘 다 지원
        if shutil.which("docker") and _run(["docker", "compose", "version"]) == 0:
            _run(["docker", "compose", "up", "-d"])
        elif shutil.which("docker-compose"):
            _run(["docker-compose", "up", "-d"])
        else:
            print("[경고] docker compose/ docker-compose 명령을 찾지 못했습니다. 수동으로 배포하세요.")


# ====== (신규) Proxy Setup Assistant ======
def _tcp_test(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def create_revert_script(os_type: str, proxy_host: str, proxy_port: int) -> Path:
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    if os_type == "windows":
        path = Path(f"proxy_revert_{ts}.ps1").resolve()
        content = [
            '$path = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"',
            'Set-ItemProperty -Path $path -Name ProxyEnable -Type DWord -Value 0',
            'Remove-ItemProperty -Path $path -Name ProxyServer -ErrorAction SilentlyContinue',
            r"Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like '*mitmproxy*' } | Remove-Item -Force",
            'Write-Host "프록시 비활성화 및 mitmproxy CA 제거 완료"',
        ]
        path.write_text("\n".join(content), encoding="utf-8")
        return path
    else:
        path = Path(f"proxy_revert_{ts}.sh").resolve()
        lines = ["#!/usr/bin/env bash", "set -e"]
        if os_type == "macos":
            lines += [
                'IFACE="${1:-Wi-Fi}"',
                'networksetup -setwebproxystate "$IFACE" off || true',
                'networksetup -setsecurewebproxystate "$IFACE" off || true',
                'security delete-certificate -c mitmproxy /Library/Keychains/System.keychain || true',
                'echo "프록시 비활성화 및 mitmproxy CA 제거 완료"',
            ]
        elif os_type == "ubuntu":
            lines += [
                "gsettings set org.gnome.system.proxy mode 'none' || true",
                "rm -f /usr/local/share/ca-certificates/mitmproxy-ca.crt || true",
                "update-ca-certificates --fresh || true",
                'echo "프록시 비활성화 및 mitmproxy CA 제거 완료"',
            ]
        elif os_type == "rhel":
            lines += [
                "gsettings set org.gnome.system.proxy mode 'none' || true",
                "rm -f /etc/pki/ca-trust/source/anchors/mitmproxy-ca.crt || true",
                "update-ca-trust || true",
                'echo "프록시 비활성화 및 mitmproxy CA 제거 완료"',
            ]
        else:
            lines += [
                "echo '수동 환경입니다. 프록시는 수동으로 해제하고, CA는 시스템 신뢰 저장소에서 제거하세요.'",
            ]
        path.write_text("\n".join(lines), encoding="utf-8")
        try:
            os.chmod(path, 0o755)
        except Exception:
            pass
        return path


def docker_available() -> bool:
    return shutil.which("docker") is not None


def docker_configure_container(container: str, proxy_host: str, proxy_port: int, no_proxy: str) -> None:
    proxy_url = f"http://{proxy_host}:{proxy_port}"
    cmd1 = [
        "docker", "exec", container, "/bin/sh", "-lc",
        f'echo "export HTTP_PROXY={proxy_url}" > /etc/profile.d/proxy.sh && '
        f'echo "export HTTPS_PROXY={proxy_url}" >> /etc/profile.d/proxy.sh && '
        f'echo "export NO_PROXY={no_proxy}" >> /etc/profile.d/proxy.sh && '
        'chmod 644 /etc/profile.d/proxy.sh'
    ]
    _run(cmd1)

    cmd_fetch = [
        "docker", "exec", container, "/bin/sh", "-lc",
        'apk --version >/dev/null 2>&1 && PKG="apk add --no-cache ca-certificates curl" || '
        'PKG="apt-get update && apt-get install -y ca-certificates curl"; '
        '$PKG >/dev/null 2>&1 || true; '
        f'export http_proxy={proxy_url}; export https_proxy={proxy_url}; '
        'mkdir -p /usr/local/share/ca-certificates && '
        'curl -fsSL http://mitm.it/cert/pem -o /usr/local/share/ca-certificates/mitmproxy-ca.crt || true; '
        '(command -v update-ca-certificates >/dev/null && update-ca-certificates) || '
        '(command -v update-ca-trust >/dev/null && update-ca-trust) || true'
    ]
    _run(cmd_fetch)
    print(f"[docker] 컨테이너 '{container}'에 프록시/CA 설정을 적용했습니다. 컨테이너/서비스 재시작이 필요할 수 있습니다.")


def run_proxy_setup_assistant() -> None:
    """
    서비스 클라이언트(서버)에서 실행해, 지정한 Proxy Capture(진단 PC)의 IP:PORT로
    시스템 프록시/CA 신뢰를 자동 적용하고 테스트/롤백 스크립트를 제공.
    또한 동일 경로의 docker-compose.yml이 있으면 .bak 백업 후 자동 수정(주입) 지원.
    """
    print("\n[Proxy Setup Assistant]")
    proxy_host = input("진단 PC의 프록시 호스트/IP (예: 10.0.0.5): ").strip()
    if not proxy_host:
        print("[오류] 호스트가 필요합니다.")
        return
    try:
        proxy_port = int(input("프록시 포트 (예: 8080): ").strip())
    except ValueError:
        print("[오류] 올바른 포트를 입력하세요.")
        return

    # 연결 테스트
    if _tcp_test(proxy_host, proxy_port):
        print(f"[연결 확인] {proxy_host}:{proxy_port} TCP 연결 성공.")
    else:
        print(f"[경고] {proxy_host}:{proxy_port} 에 연결할 수 없습니다. 방화벽/네트워크를 확인하세요.")
        if not ask_yes_no("계속 진행하시겠습니까?", default=False):
            return

    # 시스템 프록시 설정
    spm = SystemProxyManager(proxy_host, proxy_port)
    spm.enable()

    # mitm CA 다운로드 & 신뢰
    if ask_yes_no("이 프록시의 mitm CA를 다운로드하여 신뢰로 추가할까요?", default=True):
        ok = fetch_mitm_ca_via_proxy(proxy_host, proxy_port)
        if ok:
            trust_mitm_ca()
        else:
            print("[안내] CA 다운로드에 실패하여 신뢰 추가를 생략합니다.")

    # ===== docker-compose.yml 자동 수정 =====
    compose_path = _compose_find_path()
    if compose_path:
        print(f"[compose] 감지: {compose_path.name}")
        if ask_yes_no("docker-compose.yml에 프록시 설정을 주입할까요?", default=True):
            _compose_backup(compose_path)
            # 사용자에게 프록시 정보 재확인(의도치 않은 값 방지)
            proxy_host2 = input(f"주입할 프록시 호스트 [기본 {proxy_host}]: ").strip() or proxy_host
            try:
                proxy_port2 = int(input(f"주입할 프록시 포트 [기본 {proxy_port}]: ").strip() or str(proxy_port))
            except ValueError:
                proxy_port2 = proxy_port
            compose_modify_services(compose_path, proxy_host2, proxy_port2)
        else:
            print("[compose] 파일 수정은 건너뜁니다.")
    else:
        print("[compose] 현재 경로에서 docker-compose.yml을 찾지 못했습니다. (자동 수정 생략)")

    # Docker 컨테이너 설정(선택)
    if docker_available() and ask_yes_no("실행 중인 Docker 컨테이너에도 프록시/CA를 적용할까요?", default=False):
        container = input("컨테이너 이름/ID: ").strip()
        if container:
            no_proxy_default = "localhost,127.0.0.1,::1"
            no_proxy = input(f"NO_PROXY 목록 입력 [기본 {no_proxy_default}]: ").strip() or no_proxy_default
            docker_configure_container(container, proxy_host, proxy_port, no_proxy)
        else:
            print("[안내] 컨테이너 식별자가 없어 Docker 단계는 건너뜁니다.")
    elif not docker_available():
        print("[안내] Docker CLI가 감지되지 않아 Docker 설정 단계는 건너뜁니다.")

    # 간단 테스트 (HTTP)
    if ask_yes_no("프록시 경유 HTTP 연결을 간단히 테스트할까요?(http://example.com)", default=True):
        try:
            import urllib.request
            proxy_url = f"http://{proxy_host}:{proxy_port}"
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
            )
            with opener.open("http://example.com", timeout=10) as resp:
                print(f"[테스트] HTTP 상태: {resp.status}")
        except Exception as e:
            print(f"[경고] HTTP 테스트 실패: {e}")

    # 롤백 스크립트 생성
    revert_path = create_revert_script((SELECTED_OS or "other").lower(), proxy_host, proxy_port)
    print(f"[준비 완료] 프록시/CA 설정을 적용했습니다. 필요 시 다음 스크립트로 원복하세요:\n  {revert_path}")


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
    print("모드 선택: 1) Proxy Capture  2) Browser Session Capture  3) Proxy Setup Assistant  q) 종료")

    choice = input("선택 입력 [1/2/3/q]: ").strip().lower()
    if choice in ("q", "quit"):
        print("종료합니다.")
        return

    if choice == "1":
        print("\n[Proxy Capture] 이 PC에서 mitmproxy를 실행해, 이 프록시를 경유하는 요청/응답 트래픽을 캡처합니다.")
        listen_host = input("프록시 호스트 [기본 127.0.0.1]: ").strip() or "127.0.0.1"
        try:
            listen_port = int(input("프록시 포트 [기본 8080]: ").strip() or "8080")
        except ValueError:
            print("잘못된 포트 값입니다. 8080으로 진행합니다.")
            listen_port = 8080
        ssl_insecure = ask_yes_no("서버 인증서 검증을 생략하시겠습니까?", default=False)

        open_login = ask_yes_no("로그인 페이지가 필요합니까?", default=True)
        login_url: Optional[str] = None
        if open_login:
            login_url = input("로그인 페이지 URL을 입력하세요 (예: example.com/login): ").strip() or None

        run_proxy_capture(listen_host, listen_port, ssl_insecure, login_url)
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
        run_proxy_setup_assistant()
        return

    print("알 수 없는 선택입니다. 다시 실행하세요.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[중단됨] 사용자에 의해 종료")
        sys.exit(130)

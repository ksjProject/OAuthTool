#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import argparse
import os
import sys
from pathlib import Path
import re
import base64

# =====================
# Fixed directory roots
# =====================
def oauthtool_base() -> Path:
    home = os.environ.get("USERPROFILE") or str(Path.home())
    return Path(home) / "Desktop" / "OAuthTool"

def fixed_session_path(base: Path, override: str | None) -> str | None:
    if override:
        return override
    for name in ("session.token.json", "session_token.json"):
        p = base / "proxy_artifacts" / name
        if p.exists():
            return str(p)
    return None

def fixed_discovery_path(base: Path, override: str | None) -> str | None:
    if override:
        return override
    p = base / "discovery_artifacts" / "openid_configuration.json"
    return str(p) if p.exists() else None

def fixed_jwks_path(base: Path, override: str | None) -> str | None:
    if override:
        return override
    p = base / "discovery_artifacts" / "jwks.json"
    return str(p) if p.exists() else None

def load_json(path: str | None):
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

# =====================
# Token discovery utils
# =====================
JWT_PART = r"[A-Za-z0-9_-]{10,}"
JWT_RE = re.compile(JWT_PART + r"\." + JWT_PART + r"\." + JWT_PART)
BEARER_RE = re.compile(r"Bearer\s+(" + JWT_PART + r"\." + JWT_PART + r"\." + JWT_PART + r")", re.IGNORECASE)

def looks_like_jwt(s: str) -> bool:
    if not isinstance(s, str) or s.count(".") != 2:
        return False
    h, p, *_ = s.split(".")
    return len(h) >= 10 and len(p) >= 10

def b64url_decode(b: str) -> bytes:
    try:
        pad = "=" * (-len(b) % 4)
        return base64.urlsafe_b64decode((b + pad).encode("utf-8"))
    except Exception:
        return b""

def jwt_header(token: str) -> dict:
    try:
        h = token.split(".")[0]
        return json.loads(b64url_decode(h).decode("utf-8", "ignore"))
    except Exception:
        return {}

def deep_scan_for_jwts(obj, path=""):
    hits = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            kp = f"{path}.{k}" if path else k
            if isinstance(v, (dict, list)):
                hits.extend(deep_scan_for_jwts(v, kp))
            elif isinstance(v, str):
                m = BEARER_RE.search(v)
                if m:
                    hits.append((kp, k.lower(), m.group(1), "bearer"))
                elif looks_like_jwt(v):
                    hits.append((kp, k.lower(), v, "raw"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            kp = f"{path}[{i}]"
            if isinstance(v, (dict, list)):
                hits.extend(deep_scan_for_jwts(v, kp))
            elif isinstance(v, str):
                m = BEARER_RE.search(v)
                if m:
                    hits.append((kp, "", m.group(1), "bearer"))
                elif looks_like_jwt(v):
                    hits.append((kp, "", v, "raw"))
    return hits

def extract_tokens(sess: dict):
    toks = {"id_token": None, "access_token": None, "client_assertion": None}
    found = []

    if not isinstance(sess, dict):
        return toks, found

    # Known shapes first
    for t in (sess.get("oauth_tokens") or []):
        k = (t.get("key") or "").lower()
        v = t.get("value")
        if k in ("id_token", "access_token") and looks_like_jwt(v):
            toks[k] = v
            found.append(("oauth_tokens[]", k, v, "known", jwt_header(v)))

    for container in ("token_response", "tokens", "oidc", "oauth"):
        c = sess.get(container)
        if isinstance(c, dict):
            for k in ("id_token", "access_token", "client_assertion"):
                v = c.get(k)
                if looks_like_jwt(v) and not toks.get(k):
                    toks[k] = v
                    found.append((f"{container}.{k}", k, v, "known", jwt_header(v)))

    for k in ("id_token", "access_token", "client_assertion", "clientAssertion", "assertion"):
        v = sess.get(k)
        kl = k.lower()
        if looks_like_jwt(v) and not toks.get(kl):
            toks[kl] = v
            found.append((k, kl, v, "known", jwt_header(v)))

    # Deep scan
    hits = deep_scan_for_jwts(sess)
    # Prefer keys with 'id_token'/'access_token'
    for path, kname, token, src in hits:
        if not toks["id_token"] and "id" in kname and "token" in kname:
            toks["id_token"] = token
            found.append((path, "id_token", token, src, jwt_header(token)))
        if not toks["access_token"] and "access" in kname and "token" in kname:
            toks["access_token"] = token
            found.append((path, "access_token", token, src, jwt_header(token)))

    # Fallback: assign by order if still missing
    remaining = [t for (_p, _k, t, _s) in hits if looks_like_jwt(t)]
    if not toks["id_token"] and remaining:
        tok = remaining.pop(0)
        toks["id_token"] = tok
        found.append(("(heuristic)", "id_token", tok, "heuristic", jwt_header(tok)))
    if not toks["access_token"] and remaining:
        tok = remaining.pop(0)
        toks["access_token"] = tok
        found.append(("(heuristic)", "access_token", tok, "heuristic", jwt_header(tok)))

    return toks, found

# =====================
# Checker loader
# =====================
def load_checker(path: str):
    import importlib.util
    spec = importlib.util.spec_from_file_location("vuln_key_rotation_checker", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod

# =====================
# Main
# =====================
def main():
    ap = argparse.ArgumentParser(description="Key rotation/JWKS adapter (fixed dirs only)")
    ap.add_argument("--session", help="(optional) override path to session json")
    ap.add_argument("--discovery", help="(optional) override path to openid_configuration.json")
    ap.add_argument("--jwks", help="(optional) override path to jwks.json")
    ap.add_argument("--checker", default=str(Path(__file__).with_name("vuln_key_rotation_checker.py")), help="checker module path")
    ap.add_argument("--outdir", help="(optional) override output directory")
    args = ap.parse_args()

    base = oauthtool_base()

    sess_path = fixed_session_path(base, args.session)
    disc_path = fixed_discovery_path(base, args.discovery)
    jwks_path = fixed_jwks_path(base, args.jwks)
    outdir = args.outdir or str(base / "module_reports")

    sess = load_json(sess_path) or {}
    disc = load_json(disc_path) or {}
    jwks = load_json(jwks_path) or {}

    print("[*] session file   :", sess_path or "(not found)")
    print("[*] discovery file :", disc_path or "(not found)")
    print("[*] jwks file      :", jwks_path or "(not found)")

    # Build payload for checker (module stays pure; no FS access)
    discovery_obj = {"issuer": None, "jwks_uri": None}
    if isinstance(disc, dict):
        discovery_obj["issuer"] = disc.get("issuer")
        discovery_obj["jwks_uri"] = disc.get("jwks_uri")

    tokens, found = extract_tokens(sess)
    print("[*] tokens found   : id_token=%s, access_token=%s, client_assertion=%s" % (
        "yes" if tokens.get("id_token") else "no",
        "yes" if tokens.get("access_token") else "no",
        "yes" if tokens.get("client_assertion") else "no",
    ))
    if found:
        print("[*] discovered JWT locations (up to 3):")
        for i, (path, k, _tok, src, hdr) in enumerate(found[:3], 1):
            alg = hdr.get("alg")
            kid = hdr.get("kid")
            print(f"    {i}. {k} @ {path} (src={src}, alg={alg}, kid={kid})")

    payload = {
        "discovery": discovery_obj,
        "as_metadata": (sess.get("as_metadata") if isinstance(sess, dict) else {}) or {},
        "jwks": jwks if isinstance(jwks, dict) else {"keys": []},
        "client_registration": (sess.get("client_registration") if isinstance(sess, dict) else {}) or {},
        "tokens": tokens,
    }

    checker = load_checker(args.checker)
    res = checker.run_checks(payload)

    outdir_path = Path(outdir)
    outdir_path.mkdir(parents=True, exist_ok=True)
    out_file = outdir_path / "key_rotation_check_result.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)

    print("[+] saved:", str(out_file))
    print("\n===== REPORT (console) =====\n")
    print(checker.pretty_report(res))

if __name__ == "__main__":
    main()

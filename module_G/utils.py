"""
공통 유틸리티: 마스킹, 샤논 엔트로피, JWT 디코딩 등
- 이 모듈은 다른 Analyzer들이 공통으로 사용하는 함수들을 포함합니다.
"""

import base64
import json
import math
import re
from typing import Optional, Dict, Any

JWT_REGEX = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}")

def mask_secret(v: Optional[str], keep: int = 4) -> str:
    """값을 마스킹. 뒤 keep 글자만 노출."""
    if v is None:
        return ""
    s = str(v)
    if len(s) <= keep:
        return "*" * len(s)
    return "*" * (len(s) - keep) + s[-keep:]

def shannon_entropy(s: str) -> float:
    """간단한 샤논 엔트로피 계산 (bit/char)."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    L = len(s)
    for c in freq.values():
        p = c / L
        ent -= p * math.log2(p)
    return ent

def looks_random_state(state: str) -> Dict[str, Any]:
    """
    state의 랜덤성 지표 반환.
    반환값: {ok:bool, length:int, entropy:float, classes:int}
    ok 기준: 길이>=16, entropy>=3.5, 문자군 >=2
    """
    if not state:
        return {"ok": False, "length": 0, "entropy": 0.0, "classes": 0}
    length = len(state)
    entropy = shannon_entropy(state)
    classes = 0
    if re.search(r"[0-9]", state): classes += 1
    if re.search(r"[a-z]", state): classes += 1
    if re.search(r"[A-Z]", state): classes += 1
    if re.search(r"[^0-9A-Za-z]", state): classes += 1
    ok = (length >= 16) and (entropy >= 3.5) and (classes >= 2)
    return {"ok": ok, "length": length, "entropy": entropy, "classes": classes}

def b64decode_str(s: str) -> Optional[bytes]:
    """Base64 문자열을 안전하게 디코딩 (padding 보정 포함)."""
    try:
        pad = '=' * (-len(s) % 4)
        return base64.b64decode(s + pad)
    except Exception:
        return None

def decode_jwt_payload(token: str) -> Optional[Dict[str, Any]]:
    """JWT의 payload(클레임) 디코딩(검증 아님)."""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        payload_b = b64decode_str(parts[1])
        if not payload_b:
            return None
        data = json.loads(payload_b.decode('utf-8', 'ignore'))
        # 보안상 전체를 그대로 저장하기보다 일부 키만 반환
        keep = {k: data.get(k) for k in ("iss", "sub", "aud", "exp", "iat", "nonce") if k in data}
        return keep
    except Exception:
        return None

def find_jwts_in_text(text: str):
    """텍스트에서 JWT-like 문자열을 찾음(중복 제거)."""
    if not text:
        return []
    return list(set(JWT_REGEX.findall(text)))

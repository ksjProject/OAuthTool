# utils_io.py  (예시 파일명)
"""
packets.jsonl / session_token.json 파싱 유틸 (개선판)
- mitmproxy가 생성한 packets.jsonl 라인 단위 JSON을 읽어 편리한 구조로 반환
- session_token.json 을 읽어 oauth_tokens 요약을 제공
- 안전한 base64 디코딩 / 헤더 정규화 / 쿼리·프래그먼트 파싱 보강
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qsl

import base64

logger = logging.getLogger(__name__)

# -------------------- 안전 유틸 --------------------

def safe_b64decode(b64: str) -> bytes:
    """패딩/URL-safe까지 고려한 안전 base64 디코더: 실패 시 b''."""
    if not b64:
        return b""
    try:
        padded = b64 + "=" * (-len(b64) % 4)
        return base64.b64decode(padded)
    except Exception:
        try:
            padded = b64 + "=" * (-len(b64) % 4)
            return base64.urlsafe_b64decode(padded)
        except Exception:
            return b""

def parse_query_fragment(url: str) -> Dict[str, Dict[str, str]]:
    """
    URL에서 query/fragment를 querystring으로 파싱해 반환.
    반환: {"query": {...}, "fragment": {...}}
    - 동일 키 다중 출현 시 마지막 값을 사용(필요 시 리스트로 바꿔도 됨)
    - 값 없음도 keep (keep_blank_values=True)
    """
    try:
        p = urlparse(url)
    except Exception:
        return {"query": {}, "fragment": {}}
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    frag_q = {}
    if p.fragment:
        try:
            frag_q = dict(parse_qsl(p.fragment, keep_blank_values=True))
        except Exception:
            frag_q = {}
    return {"query": q, "fragment": frag_q}

def normalize_headers(hdrs: Dict[str, Any]) -> Dict[str, str]:
    """헤더 키를 소문자로 정규화해 조회ミ스 방지."""
    return { (k or "").lower(): v for k, v in (hdrs or {}).items() }

def mask_secret(val: str, keep: int = 4) -> str:
    """증거(evidence) 출력용 간단 마스킹."""
    if not val:
        return ""
    s = str(val)
    if len(s) <= keep * 2:
        return s[:keep] + "..." + s[-keep:]
    return s[:keep] + "..." + s[-keep:]

# -------------------- 파일 로딩 --------------------

def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    """손상 라인은 건너뛰되 카운트 로깅."""
    out = []
    bad = 0
    with path.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                bad += 1
                logger.debug("read_jsonl: failed to parse line %d in %s", i, path)
                continue
    if bad:
        logger.warning("read_jsonl: %d invalid json lines in %s", bad, path)
    return out

def load_packets(packets_path: Path) -> List[Dict[str, Any]]:
    """packets.jsonl 읽기 (요청/응답 항목 한 줄에 하나)"""
    return read_jsonl(packets_path)

def load_session_tokens(session_token_path: Path) -> Dict[str, Any]:
    """
    session_token.json 로드.
    - 기대 스키마: {"oauth_tokens": [ {...}, ... ]}
    - 리스트로 온 경우 자동 래핑
    - 알 수 없으면 {} 반환하며 경고 로깅
    """
    if not session_token_path.exists():
        return {}
    try:
        data = json.loads(session_token_path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("oauth_tokens"), list):
            return data
        if isinstance(data, list):
            return {"oauth_tokens": data}
        logger.warning("load_session_tokens: unexpected schema in %s", session_token_path)
        return {}
    except Exception:
        logger.exception("load_session_tokens: failed to read %s", session_token_path)
        return {}

# -------------------- body 디코딩 --------------------

def extract_request_body_text(pkt: Dict[str, Any]) -> str:
    """
    packets.jsonl의 request.body_b64를 디코딩해 텍스트로 반환.
    없거나 실패 시 "" 반환, UTF-8 우선 + latin-1 폴백.
    """
    req = pkt.get("request") or {}
    b64 = req.get("body_b64") or ""
    if not b64:
        return ""
    b = safe_b64decode(b64)  # 개선: 안전 디코더
    if not b:
        return ""
    try:
        return b.decode("utf-8", "ignore")
    except Exception:
        return b.decode("latin-1", "ignore")

def extract_response_body_text(pkt: Dict[str, Any]) -> str:
    """response.body_b64 → 텍스트로 반환(동일 정책)."""
    resp = pkt.get("response") or {}
    b64 = resp.get("body_b64") or ""
    if not b64:
        return ""
    b = safe_b64decode(b64)
    if not b:
        return ""
    try:
        return b.decode("utf-8", "ignore")
    except Exception:
        return b.decode("latin-1", "ignore")


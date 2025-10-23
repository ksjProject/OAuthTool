
"""
packets.jsonl / session_token.json 파싱 유틸
- mitmproxy가 생성한 packets.jsonl 라인 단위 JSON을 읽어 편리한 구조로 반환
- session_token.json 을 읽어 oauth_tokens 요약을 제공
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from .utils import b64decode_str

def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    out = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                # 일부 항목이 손상되었을 경우 무시
                continue
    return out

def load_packets(packets_path: Path) -> List[Dict[str, Any]]:
    """packets.jsonl 읽기 (요청/응답 항목 한 줄에 하나)"""
    return read_jsonl(packets_path)

def load_session_tokens(session_token_path: Path) -> Dict[str, Any]:
    if not session_token_path.exists():
        return {}
    try:
        return json.loads(session_token_path.read_text(encoding="utf-8"))
    except Exception:
        return {}

def extract_request_body_text(pkt: Dict[str, Any]) -> str:
    """
    packets.jsonl의 request 부분에서 body_b64을 찾아 디코딩하여 텍스트로 반환.
    - 대부분의 토큰 교환은 application/x-www-form-urlencoded 형태이며 base64로 저장됨.
    """
    req = pkt.get("request") or {}
    b64 = req.get("body_b64") or ""
    if not b64:
        return ""
    b = b64decode_str(b64)
    if not b:
        return ""
    try:
        return b.decode("utf-8", "ignore")
    except Exception:
        return b.decode("latin-1", "ignore")

def extract_response_body_text(pkt: Dict[str, Any]) -> str:
    resp = pkt.get("response") or {}
    b64 = resp.get("body_b64") or ""
    if not b64:
        return ""
    b = b64decode_str(b64)
    if not b:
        return ""
    try:
        return b.decode("utf-8", "ignore")
    except Exception:
        return b.decode("latin-1", "ignore")

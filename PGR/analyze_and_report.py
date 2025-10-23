"""
간단 실행 스크립트: 프로젝트 루트에서 바로 실행 가능
"""
from pathlib import Path
from .runner import run_analysis
if __name__ == "__main__":
    packets = Path("./proxy_artifacts/packets.jsonl")
    session = Path("./proxy_artifacts/session_token.json")
    out = Path("./reports")
    run_analysis(packets, session, out)

# runner.py
# -*- coding: utf-8 -*-
import argparse
from pathlib import Path
import sys
import traceback
import json
import shutil

# 기존 로더 함수
from .parser import load_packets, load_session_tokens

# analyzers 모듈 import 처리
try:
    from .analyzers import analyze_and_report
except Exception:
    try:
        import analyzers
        analyze_and_report = analyzers.analyze_and_report
    except Exception as e:
        print("[error] analyzers 모듈 import 실패:", e, file=sys.stderr)
        analyze_and_report = None


def run_analysis(packets_path: Path, session_path: Path, outdir: Path):
    if analyze_and_report is None:
        print("[error] analyze_and_report 함수가 준비되지 않았습니다.", file=sys.stderr)
        return None

    if not packets_path.exists():
        print("[error] packets 파일을 찾을 수 없습니다:", packets_path, file=sys.stderr)
        return None

    if session_path is None or not session_path.exists():
        print("[warn] session_token 파일이 없거나 경로가 잘못되었습니다. 빈 dict 사용.", file=sys.stderr)
        session_data = {}
    else:
        session_data = load_session_tokens(session_path)  # Path 객체 그대로

    try:
        packets_data = load_packets(packets_path)  # Path 객체 그대로

        # analyzers.analyze_and_report 시그니처는 (packets, session_tokens)
        report = analyze_and_report(packets_data, session_data)

        print("[ok] analyze_and_report 완료.")

        # analyzers.py는 현재 작업 디렉토리에 oauth_report.json을 생성함.
        # 만약 생성되었다면 outdir로 이동(또는 덮어쓰기)하고, 없다면 runner가 report dict를 JSON으로 저장.
        generated_fname = Path("oauth_report.json")
        target_path = outdir / "oauth_report.json"

        if generated_fname.exists():
            try:
                # move (overwrite if exists)
                if target_path.exists():
                    target_path.unlink()
                shutil.move(str(generated_fname), str(target_path))
                print(f"[ok] JSON 리포트 파일을 {target_path}로 이동했습니다.")
            except Exception as e:
                print("[warn] oauth_report.json 이동 실패:", e, file=sys.stderr)
                # fallback: write report to outdir if available
                try:
                    with open(target_path, "w", encoding="utf-8") as f:
                        json.dump(report, f, ensure_ascii=False, indent=2)
                    print(f"[ok] JSON 리포트를 {target_path}에 저장했습니다 (fallback).")
                except Exception as e2:
                    print("[error] 리포트 저장 실패:", e2, file=sys.stderr)
        else:
            # analyzers가 파일을 생성하지 않은 경우, runner에서 저장
            try:
                with open(target_path, "w", encoding="utf-8") as f:
                    json.dump(report, f, ensure_ascii=False, indent=2)
                print(f"[ok] JSON 리포트를 {target_path}에 저장했습니다.")
            except Exception as e:
                print("[error] JSON 리포트 저장 실패:", e, file=sys.stderr)

        if isinstance(report, dict):
            print("리포트 요약:", report.get("overall", "없음"))
        else:
            print("리포트 결과:", str(report))

        return report

    except Exception as e:
        print("[error] analyze_and_report 실행 중 예외:", e, file=sys.stderr)
        traceback.print_exc()
        return None


def main():
    parser = argparse.ArgumentParser(description="OAuth 분석 리포트 생성기")
    parser.add_argument("--packets", "-p", required=True, help="packets.jsonl 경로")
    parser.add_argument("--session", "-s", required=False, help="session_token.json 경로")
    parser.add_argument("--out", "-o", default="./reports", help="리포트 출력 폴더")
    args = parser.parse_args()

    packets_path = Path(args.packets)
    session_path = Path(args.session) if args.session else Path(packets_path.parent) / "session_token.json"
    outdir = Path(args.out)

    # outdir 생성
    outdir.mkdir(parents=True, exist_ok=True)

    run_analysis(packets_path, session_path, outdir)


if __name__ == "__main__":
    main()

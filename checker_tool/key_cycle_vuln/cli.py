# cli.py — vuln_key_rotation_checker 모듈 실행 래퍼
import json, sys
from pathlib import Path

# 모듈 import
from vuln_key_rotation_checker import check_key_rotation

def main():
    if len(sys.argv) < 3:
        print("Usage: python cli.py <input_json> <output_json>")
        print(r"Example: python cli.py ..\session_token.json report.json")
        sys.exit(1)

    in_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    if not in_path.exists():
        print(f"[!] 입력 파일이 없습니다: {in_path}")
        sys.exit(2)

    with in_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    report = check_key_rotation(data)

    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[OK] 결과 저장: {out_path.resolve()}")

if __name__ == "__main__":
    main()

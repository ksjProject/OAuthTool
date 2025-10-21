from typing import List

def reportMaker(flags: List[bool]) -> str:

    html = [
        "<!DOCTYPE html>",
        "<html lang='ko'>",
        "<head><meta charset='UTF-8'><title>Report</title></head>",
        "<body>"
    ]
    result = ""

    if flags[0]:
        result += "<p>1번째 취약점이 발견되었습니다.</p>"
    if flags[1]:
        result += "<p>2번째 취약점이 발견되었습니다.</p>"
    if flags[2]:
        result += "<p>3번째 취약점이 발견되었습니다.</p>"
    if flags[3]:
        result += "<p>4번째 취약점이 발견되었습니다.</p>"
    if flags[4]:
        result += "<p>5번째 취약점이 발견되었습니다.</p>"
    if flags[5]:
        result += "<p>6번째 취약점이 발견되었습니다.</p>"
    if flags[6]:
        result += "<p>7번째 취약점이 발견되었습니다.</p>"
    if flags[7]:
        result += "<p>8번째 취약점이 발견되었습니다.</p>"
    if flags[8]:
        result += "<p>9번째 취약점이 발견되었습니다.</p>"
    if flags[9]:
        result += "<p>10번째 취약점이 발견되었습니다.</p>"

    # 아무 것도 참이 아니면 안내 문구 추가 (원치 않으면 이 부분 삭제)
    if result == "":
        result = "<p>진단 된 취약점이 없습니다.</p>"

    html.append(result)
    html.append("</body></html>")
    return "".join(html)

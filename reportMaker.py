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
        result += "<h4>STATE 파라미터 관련 취약점이 발견되었습니다.</h4>"
        result += "<p>STATE 파라미터 미사용, 미검증이 탐지되었습니다.</p>"
        result += "<p></p>"
    if flags[1]:
        result += "<h4>issuer 검증이 이루어지지 않고 있습니다.</h4>"
        result += "<p>iss는 예상되는 인가서버의 issuer와 합치 여부가 검증되야 합니다.</p>"
        result += "<p></p>"
    if flags[2]:
        result += "<h4>Audience 검증이 이루어지지 않고 있습니다.</h4>"
        result += "<p>aud 클레임이 검증되어야 합니다.</p>"
        result += "<p></p>"
    if flags[3]:
        result += "<h4>Scope 요청 범위가 너무 넓습니다.</h4>"
        result += "<p>Scope는 최소한으로 요구되어야 합니다.</p>"
        result += "<p></p>"
    if flags[4]:
        result += "<h4>ID 토큰과 Access 토큰의 혼용사용이 발견되었습니다.</h4>"
        result += "<p>토큰의 사용이 절절히 이루어지지 않았습니다.</p>"
        result += "<p></p>"
    if flags[5]:
        result += "<h4>토큰 저장의 취약이 발견되었습니다.</h4>"
        result += "<p>토큰 저장의 취약이 발견되었습니다.</p>"
        result += "<p></p>"
    if flags[6]:
        result += "<h4>리프레시 토큰 관련 취약점이 발견되었습니다.</h4>"
        result += "<p>리프레시 토큰 관련 취약점이 발견되었습니다.</p>"
        result += "<p></p>"
    if flags[7]:
        result += "<h4>외부로의 리다이렉트가 허용되어 있습니다.</h4>"
        result += "<p>검증되지 않은 사이트로 리다이렉트가 허용되지 않아야 합니다.</p>"
        result += "<p></p>"
    if flags[8]:
        result += "<h4>JWT 서명 검증이 부실합니다.</h4>"
        result += "<p>alg가 고정되어야 하며, 키 회전이 적절한 때에 이루어져야 합니다.</p>"
        result += "<p></p>"
    if flags[9]:
        result += "<h4>OIDC nonce 검증이 적절하지 않습니다.</h4>"
        result += "<p>nonce는 항시 사용되어야 하며, 1회성으로 사용되어야 합니다.</p>"
        result += "<p></p>"

    if result == "":
        result = "<p>진단 된 취약점이 없습니다.</p>"

    html.append(result)
    html.append("</body></html>")
    return "".join(html)

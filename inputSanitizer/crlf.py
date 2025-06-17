import re
import urllib.parse

def payloadTemizmi(text: str) -> bool:
    # CR, LF veya URL encode edilmiş halleri var mı?
    return not re.search(r'(%0[aAdD])|[\r\n]', text, re.IGNORECASE)

def crlfSanitize(girdi: str) -> str:
    current = girdi

    while True:
        decoded = urllib.parse.unquote(current)
        cleaned = re.sub(r'[\r\n]', '', decoded)

        if payloadTemizmi(cleaned):
            return cleaned

        current = cleaned

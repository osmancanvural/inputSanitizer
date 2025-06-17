import html

def xssSanitize(girdi: str) -> str:
    return html.escape(girdi)
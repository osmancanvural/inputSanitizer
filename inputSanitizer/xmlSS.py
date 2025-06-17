import xml.sax.saxutils as saxutils

def xmlSanitize(girdi: str) -> str:

    return saxutils.escape(girdi, {
        '"': "&quot;",
        "'": "&apos;"
    })

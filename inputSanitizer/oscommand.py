import re
import shlex

def osCommandSanitize(girdi: str, mod: int = 0) -> str:
    # mod 0: ozel karakterleri siler, bu sayede shell komutu calisitrilamaz
    if mod == 0:
        girdi = re.sub(r'[^a-zA-Z0-9_\. ]', '', girdi)
        return girdi
    
    # mode 1: girdiyi '' icine alir ve escapingin onune gecebilir. (kesin bi yol degil.)
    else:
        girdi = shlex.quote(girdi)
        return girdi

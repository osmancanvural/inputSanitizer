import re

def ldapSanitize(girdi:str, uzunluk=32) -> str:

    if not girdi:
        return ""
    
    girdi = girdi[:uzunluk]
    whitelist_karakterler = r'[a-zA-Z0-9@._-]'
    temiz_char = re.findall(whitelist_karakterler, girdi)
    girdi = ''.join(temiz_char)
    
    return girdi
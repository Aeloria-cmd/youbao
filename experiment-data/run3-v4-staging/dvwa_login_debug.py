#!/usr/bin/env python3
"""DVWA 登录调试: 打印登录响应全文.
用法: python3 dvwa_login_debug.py <base_url> <username> <password>
"""
import re, sys, urllib.request, http.cookiejar

base, user, pwd = sys.argv[1], sys.argv[2], sys.argv[3]
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

html = opener.open(base + "/login.php", timeout=10).read().decode(errors="replace")
m = re.search(r"name='user_token'\s+value='([0-9a-f]+)'", html)
token = m.group(1) if m else None
print("token:", token)

data = urllib.parse.urlencode({"username": user, "password": pwd,
                               "Login": "Login", "user_token": token}).encode()
resp = opener.open(base + "/login.php", data=data, timeout=10)
print(resp.read().decode(errors="replace"))

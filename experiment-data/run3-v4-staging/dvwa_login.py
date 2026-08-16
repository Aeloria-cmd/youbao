#!/usr/bin/env python3
"""DVWA 登录脚本: 自动抓取 CSRF token 并登录, 保存 cookie jar.
用法: python3 dvwa_login.py <base_url> <username> <password> <cookie_jar>
示例: python3 dvwa_login.py http://dvwa admin password /tmp/dvwa.cookies
"""
import re, sys, urllib.request, http.cookiejar

base, user, pwd, jar = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

cj = http.cookiejar.MozillaCookieJar(jar)
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# 1. 获取登录页的 user_token
html = opener.open(base + "/login.php", timeout=10).read().decode(errors="replace")
m = re.search(r"name='user_token'\s+value='([0-9a-f]+)'", html)
if not m:
    sys.exit("no token found")
token = m.group(1)
print("token:", token)

# 2. 提交登录
data = urllib.parse.urlencode({"username": user, "password": pwd,
                               "Login": "Login", "user_token": token}).encode()
resp = opener.open(base + "/login.php", data=data, timeout=10)
body = resp.read().decode(errors="replace")
print("login status:", resp.status, "| len:", len(body))

cj.save(ignore_discard=True, ignore_expires=True)
print("cookies saved:", jar)
# 3. 验证: 访问 index.php 是否重定向到 login.php
req = urllib.request.Request(base + "/index.php")
r = opener.open(req, timeout=10)
print("index final url:", r.geturl(), "| status:", r.status)

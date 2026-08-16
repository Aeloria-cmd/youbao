#!/usr/bin/env python3
"""DVWA 登录(通用): 抓 CSRF token -> 登录 -> 保存 cookies 文件 (Mozilla 格式).
用法: python3 dvwa_login2.py <base_url> <username> <password> <cookie_file>
"""
import re, sys, urllib.request, http.cookiejar

base, user, pwd, cfile = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
cj = http.cookiejar.MozillaCookieJar(cfile)
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

html = op.open(base + "/login.php", timeout=15).read().decode(errors="replace")
m = re.search(r"name='user_token'\s+value='([0-9a-f]+)'", html)
if not m:
    sys.exit("no token")
data = urllib.parse.urlencode({"username": user, "password": pwd,
                               "Login": "Login", "user_token": m.group(1)}).encode()
body = op.open(base + "/login.php", data=data, timeout=15).read().decode(errors="replace")
if "Login failed" in body:
    print("LOGIN FAILED")
    sys.exit(1)
print("LOGIN OK for", user)
# 验证
try:
    r = op.open(base + "/index.php", timeout=15)
    idx = r.read().decode(errors="replace")
    print("index:", r.status, r.geturl(), "len", len(idx))
    for kw in ["Welcome", "vulnerabilities", "security"]:
        if kw in idx:
            print("  contains:", kw)
except Exception as e:
    print("index err:", e)
cj.save(ignore_discard=True, ignore_expires=True)
print("cookies ->", cfile)

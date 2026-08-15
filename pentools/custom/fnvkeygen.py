#!/usr/bin/env python3
"""fnvkeygen.py - FNV-1a32 preimage finder (keygen).

蒸馏自 skills_staging/fnv_keygen.py 与 fnv_prefix_brute.py:
两者都在解决同一问题——逆向分析中遇到 FNV-1a32 校验值(串号/授权码/序列号检查, 常见于
firmware/CTF 二进制), 需要在 字符集 x 长度 x 固定前缀 约束下求出一个能通过校验的 key
(即哈希 preimage)。此工具将其参数化、去 numpy 依赖, 纯标准库实现。

原理 (meet-in-the-middle):
  FNV-1a32 每步 h = ((h ^ c) * P) mod 2^32, 因 P 为奇数, P^-1 mod 2^32 存在,
  可逐字节逆推: h_before = (h_after * P^-1) ^ c。
  * 正向表: 枚举前半段 A (长度 a), 存 hash(prefix||A) -> [A...]
  * 逆向:   枚举后半段 B (长度 b), 从 target 逆推得到所需的前半段中间哈希, 查表
  命中后做完整正向验证, 杜绝 MITM 数学/实现误差; 碰撞产生的多个 key 全部输出
  (任一通过正向验证的 key 都是可用授权码)。

用法:
  python3 pentools/custom/fnvkeygen.py --target 0xe868c44d
  python3 pentools/custom/fnvkeygen.py --target 0xe868c44d --charset alnum_dash --prefix A3-07- --maxlen 6
  python3 pentools/custom/fnvkeygen.py --target e868c44d --charset hex --maxlen 8 --split 4
  python3 pentools/custom/fnvkeygen.py --selftest

参数:
  --target   目标 32 位校验值 (支持 0x 前缀十六进制 / 裸十六进制 / 十进制)
  --charset  候选字符集: hex hexl alnum alnum_dash upper upper_dash lower_dash printable (默认 alnum_dash)
  --prefix   固定前缀(逐字节拼接在 key 前, 默认空)
  --minlen/--maxlen  需搜索部分的长度范围 (默认 1..6)
  --split    MITM 前半段长度 a (默认自动取 max(1, L//2)); 后半段 b = L - a
  --maxwork  单长度的候选上限 (n^a 或 n^b 超过则跳过该长度, 默认 2000000)
  --limit    每个长度最多打印的 key 数 (默认 20)
  --selftest 本地自检(无需网络): 构造已知 key->target, 验证逆推逻辑与搜索正确性后退出
"""
import argparse
import itertools
import random
import sys

P = 0x01000193          # FNV prime (odd -> 模 2^32 可逆)
MASK = 0xFFFFFFFF
OFFSET = 0x811C9DC5     # FNV offset basis
INVP = pow(P, -1, 1 << 32)   # P 在 mod 2^32 下的逆元

CHARSETS = {
    "hex":        b"0123456789ABCDEF",
    "hexl":       b"0123456789abcdef",
    "alnum":      b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "alnum_dash": b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    "upper":      b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "upper_dash": b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-",
    "lower_dash": b"abcdefghijklmnopqrstuvwxyz0123456789-",
    "printable":  bytes(range(0x20, 0x7F)),
}


def fnv1a32(data: bytes) -> int:
    """标准 FNV-1a32 前向哈希 (从 offset basis 开始)."""
    h = OFFSET
    for b in data:
        h = ((h ^ b) * P) & MASK
    return h


def fnv1a32_from(h: int, data: bytes) -> int:
    """从给定中间哈希 h 继续前向处理 data."""
    for b in data:
        h = ((h ^ b) * P) & MASK
    return h


def inv_step(h: int, c: int) -> int:
    """单字节逆推: h_after = (h_before ^ c) * P  =>  h_before = (h_after * P^-1) ^ c."""
    return ((h * INVP) ^ c) & MASK


def inv_from(target: int, data: bytes) -> int:
    """从 target 逆推: 处理 data 之前的中间哈希 (data 按原顺序从后往前逆推)."""
    h = target
    for c in reversed(data):
        h = inv_step(h, c)
    return h


def build_forward(prefix_hash: int, charset: bytes, a: int):
    """枚举前半段 A (长度 a), 返回 {中间哈希: [A, ...]}. a<=0 时只含空串."""
    tbl = {}
    if a <= 0:
        tbl.setdefault(prefix_hash, []).append(b"")
        return tbl
    for tup in itertools.product(charset, repeat=a):
        h = prefix_hash
        for c in tup:
            h = ((h ^ c) * P) & MASK
        tbl.setdefault(h, []).append(bytes(tup))
    return tbl


def find_len(target: int, prefix_hash: int, charset: bytes, a: int, b: int, limit):
    """对固定总长 L=a+b 求 preimage: 返回搜索部分的 key 字节 (不含用户 prefix),
    全部经完整正向验证. 最多返回 limit 个."""
    tbl = build_forward(prefix_hash, charset, a)
    hits = []
    for tup in itertools.product(charset, repeat=b):
        need = target
        for c in reversed(tup):
            need = inv_step(need, c)
        for A in tbl.get(need, ()):
            key = A + bytes(tup)
            if fnv1a32_from(prefix_hash, key) == target:
                hits.append(key)
                if limit and len(hits) >= limit:
                    return hits
    return hits


def search(target, charset, prefix=b"", minlen=1, maxlen=6, split=None,
           maxwork=2_000_000, limit=20, verbose=True):
    """在长度 [minlen..maxlen] 内搜索, 返回 [(L, key_bytes), ...]. key 不含用户 prefix."""
    n = len(charset)
    prefix_hash = fnv1a32(prefix)
    found = []
    if minlen <= 0:
        if prefix_hash == target:
            found.append((0, b""))
            if verbose:
                print(f"[L=0] prefix 本身即命中: {prefix!r}")
        minlen = 1
    for L in range(minlen, maxlen + 1):
        a = min(split if split else max(1, L // 2), L)
        b = L - a
        wa, wb = n ** a, n ** b
        if wa > maxwork or wb > maxwork:
            if verbose:
                print(f"[L={L}] 跳过: 工作量 n^{a}={wa:,} / n^{b}={wb:,} > maxwork={maxwork:,}"
                      f" (调小 --maxlen/--split 或改用更小字符集)")
            continue
        if verbose:
            print(f"[L={L}] 搜索 {wa:,}+{wb:,} 候选 ...")
        for k in find_len(target, prefix_hash, charset, a, b, limit):
            found.append((L, k))
            if verbose:
                print(f"  key={prefix + k!r} fnv1a32={fnv1a32(prefix + k):#010x} (verified)")
    return found


def parse_target(s: str) -> int:
    s = s.strip()
    try:
        v = int(s, 0)
    except ValueError:
        try:
            v = int(s, 16)
        except ValueError:
            raise SystemExit(f"无法解析 --target {s!r} (支持 0x 十六进制 / 裸十六进制 / 十进制)")
    return v & MASK


def selftest() -> int:
    """本地自检: 无需网络, 验证逆推数学 + MITM 搜索正确性 + 越界负例. 0 通过."""
    ok = True

    # 1) 单字节逆推往返 (固定种子随机 500 组)
    rng = random.Random(0x5EED)
    bad = 0
    for _ in range(500):
        h = rng.getrandbits(32)
        c = rng.randrange(256)
        if inv_step(((h ^ c) * P) & MASK, c) != h:
            bad += 1
    if bad:
        print(f"selftest FAIL: 逆推往返 {bad}/500 不一致"); ok = False
    else:
        print("selftest OK: inv_step 逆推往返 500/500 一致")

    # 2) 标准测试向量
    if fnv1a32(b"") != OFFSET:
        print("selftest FAIL: fnv1a32(b'') != offset basis"); ok = False
    else:
        print(f"selftest OK: fnv1a32(b'')={OFFSET:#010x}")
    if fnv1a32(b"a") != 0xE40C292C:
        print("selftest FAIL: fnv1a32(b'a') 标准向量不符"); ok = False
    else:
        print("selftest OK: fnv1a32(b'a')=0xe40c292c")

    # 3) 固定前缀 MITM 搜索能找到真实 key (hexl, L=4, split=2)
    prefix, secret = b"A3-07-", b"b9f3"
    target = fnv1a32(prefix + secret)
    found = search(target, CHARSETS["hexl"], prefix, 4, 4, split=2,
                   maxwork=100_000, limit=10, verbose=False)
    keys = [k for _, k in found]
    if secret not in keys:
        print(f"selftest FAIL: 前缀 MITM 未找到 {prefix + secret!r} (得到 {keys[:5]})"); ok = False
    else:
        print(f"selftest OK: 前缀 MITM 命中 {prefix + secret!r} (共 {len(keys)} 个碰撞 key)")

    # 4) 无前缀搜索 (alnum, L=3, split=1)
    secret2 = b"Qx9"
    target2 = fnv1a32(secret2)
    found2 = search(target2, CHARSETS["alnum"], b"", 3, 3, split=1,
                    maxwork=100_000, limit=10, verbose=False)
    keys2 = [k for _, k in found2]
    if secret2 not in keys2:
        print(f"selftest FAIL: 无前缀搜索未找到 {secret2!r} (得到 {keys2[:5]})"); ok = False
    else:
        print(f"selftest OK: 无前缀搜索命中 {secret2!r} (共 {len(keys2)} 个碰撞 key)")

    # 5) 负例: target 超出搜索空间应无命中
    target3 = fnv1a32(b"too-long-key-here")
    found3 = search(target3, CHARSETS["hexl"], b"", 1, 3, split=1,
                    maxwork=100_000, limit=10, verbose=False)
    if found3:
        print(f"selftest FAIL: 越界搜索应为空, 却得到 {found3[:5]}"); ok = False
    else:
        print("selftest OK: 越界搜索返回空 (无假阳性)")

    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(
        description="FNV-1a32 preimage finder (keygen): 给定校验值在 字符集x长度x前缀 约束下求 key")
    ap.add_argument("--target", help="目标 32 位校验值 (0x 十六进制 / 裸十六进制 / 十进制)")
    ap.add_argument("--charset", default="alnum_dash",
                    choices=sorted(CHARSETS), help="候选字符集 (默认 alnum_dash)")
    ap.add_argument("--prefix", default="", help="固定前缀, 拼在 key 前 (默认空)")
    ap.add_argument("--minlen", type=int, default=1, help="搜索部分最小长度 (默认 1)")
    ap.add_argument("--maxlen", type=int, default=6, help="搜索部分最大长度 (默认 6)")
    ap.add_argument("--split", type=int, default=None,
                    help="MITM 前半段长度 a (默认自动 max(1, L//2))")
    ap.add_argument("--maxwork", type=int, default=2_000_000,
                    help="单长度候选上限, 超过则跳过 (默认 2000000)")
    ap.add_argument("--limit", type=int, default=20,
                    help="每个长度最多打印的 key 数 (默认 20)")
    ap.add_argument("--selftest", action="store_true", help="本地自检核心逻辑后退出")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())

    if args.target is None:
        ap.error("需要 --target (或使用 --selftest)")

    target = parse_target(args.target)
    charset = CHARSETS[args.charset]
    prefix = args.prefix.encode("utf-8")
    print(f"[*] target={target:#010x} charset={args.charset}({len(charset)}) "
          f"prefix={prefix!r} len={args.minlen}..{args.maxlen} "
          f"split={args.split if args.split else 'auto'} maxwork={args.maxwork:,}")
    found = search(target, charset, prefix, args.minlen, args.maxlen,
                   args.split, args.maxwork, args.limit)
    print(f"[*] done: {len(found)} 个通过验证的 key")


if __name__ == "__main__":
    main()

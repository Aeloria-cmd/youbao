#!/usr/bin/env python3
"""pathgen.py - 语义化 Web 端点候选生成器 (semantic endpoint candidate generator)

蒸馏自 skills_staging 中 fuzz_api.py / fuzz_big.py / http_enum.py / scan_main.py 的共性:
这四个脚本都在做 HTTP 路径爆破, 但它们真正区别于 ffuf 的价值不在爆破本身(那是
ffuf 的活), 而在**候选路径的生成逻辑**: 由 动作词(approve/audit/review/check/verify...)
× 资源词(contract/status/flag/config...) × API 位置前缀(api/, admin/, api/admin/...)
× 扩展名(.php/.json) 组合出语义相关的隐藏端点候选(如 approve_contract.php、
api/admin/check_status 等), 这是人工手猜路径做不到的量级。

本工具把该生成逻辑参数化、通用化, 输出去重排序后的候选列表, 可直接喂给
ffuf/curl 等爆破器。与 ffuf 互补: ffuf 消费词表, pathgen 生产词表。

用法:
  # 生成默认候选列表到 stdout
  python3 pentools/custom/pathgen.py

  # 自定义词表 + 输出到文件, 再交给 ffuf
  python3 pentools/custom/pathgen.py --verbs approve,audit,verify --nouns contract,flag \
      --locations ',api/,admin/' --out /tmp/endpoints.txt
  ffuf -w /tmp/endpoints.txt -u http://target/FUZZ

  # 追加自定义词文件(每行一个, # 开头为注释)
  python3 pentools/custom/pathgen.py --wordlist ./my_words.txt --out /tmp/all.txt

  # 本地自检(无需网络, 退出码 0 为通过)
  python3 pentools/custom/pathgen.py --selftest

生成规则(与 staging 脚本一致):
  1. 单词 = verbs + nouns + 词文件追加, 去重。
  2. 单数: 每个 word × 每个 location × 每个 extension。
  3. 组合: 每个 verb×noun 生成 verb_sep_noun 与 noun_sep_verb 两种顺序 × location × extension。
  4. 扩展名规则: ''(无扩展名) 与 '.php' 应用到所有单词; 其余扩展名(如 .json)只应用到
     不含 '/' 的单段单词(与 fuzz_big.py 的 "if '/' not in w" 一致)。
  5. specials: 根级精确路径(robots.txt/.env/.git 等), 不加 location 前缀、不追加扩展名。

注: --locations/--extensions 为空串元素表示"无前缀/无扩展名", 直接以逗号开头传入
(如 --locations ',api/,admin/')。
"""
import argparse
import sys

DEFAULT_VERBS = (
    "approve approval audit review check verify confirm decide handle process "
    "action operate submit do manage set change mark update get list view add "
    "edit delete create read download export import test debug"
).split()
DEFAULT_NOUNS = (
    "contract status all user users account config configuration flag token key "
    "secret db database log logs report file files upload uploads download document "
    "info detail panel dashboard settings role permission session auth admin api "
    "home index main health monitor metrics history backup restore cron job jobs queue"
).split()
DEFAULT_SPECIALS = (
    "robots.txt sitemap.xml .env .git .htaccess index.php login.php admin.php "
    "phpinfo.php info.php test.php debug.php config.php database.php db.php conn.php "
    "shell cmd backdoor flag.txt readme.txt requirements.txt app.py main.py "
    "swagger.json openapi.json"
).split()
DEFAULT_LOCATIONS = ["", "api/", "api/admin/", "admin/"]
DEFAULT_EXTENSIONS = ["", ".php", ".json"]


def generate(verbs, nouns, specials, locations, extensions, sep="_",
             combos=True, singles=True, extra_words=()):
    """生成去重排序后的候选路径列表。纯本地计算, 无网络依赖。"""
    words = []
    if singles:
        words += list(verbs) + list(nouns)
    words += list(extra_words)
    # 去重且保持顺序
    words = list(dict.fromkeys(w for w in words if w))

    out = set()

    # 1. 单数: word × location × extension
    if singles:
        for w in words:
            for loc in locations:
                for ext in extensions:
                    # 非 ''/.php 的扩展名(如 .json)只用于单段单词
                    if ext and ext != ".php" and "/" in w:
                        continue
                    out.add(loc + w + ext)

    # 2. 组合: verb_noun 与 noun_verb 两种顺序 × location × extension
    if combos:
        for v in verbs:
            for n in nouns:
                for loc in locations:
                    for ext in extensions:
                        if ext and ext != ".php" and "/" in (v + sep + n):
                            continue
                        out.add(loc + v + sep + n + ext)
                        out.add(loc + n + sep + v + ext)

    # 3. 根级精确路径: 不加 location 前缀、不追加扩展名
    for s in specials:
        if s:
            out.add(s)

    return sorted(out)


def selftest():
    """本地自检: 用小词表验证生成逻辑, 不依赖外部网络。"""
    verbs = ["approve", "get"]
    nouns = ["contract", "flag"]
    specials = ["robots.txt"]
    locations = ["", "api/"]
    extensions = ["", ".php", ".json"]
    out = generate(verbs, nouns, specials, locations, extensions)

    checks = [
        ("single word", "approve" in out),
        ("single word .php", "approve.php" in out),
        ("single word .json (单段)", "flag.json" in out),
        ("location prefix", "api/approve" in out),
        ("verb_noun combo", "approve_contract" in out),
        ("noun_verb combo", "contract_approve" in out),
        ("combo .php", "approve_contract.php" in out),
        ("combo .json 无斜杠", "contract_approve.json" in out),
        ("combo .json 带 location", "api/approve_contract.json" in out),
        ("special 在根级", "robots.txt" in out),
        ("special 不加 location 前缀", "api/robots.txt" not in out),
        ("无重复", len(set(out)) == len(out)),
    ]
    failed = [name for name, ok in checks if not ok]

    # 期望数量: 组合 2动词*2名词*2顺序*2位置*3扩展=48
    #           单数 4词*2位置*3扩展=24  + 特殊 1  => 73
    expected = 2 * 2 * 2 * 2 * 3 + 4 * 2 * 3 + 1
    if len(out) != expected:
        failed.append("数量期望 %d 实际 %d" % (expected, len(out)))

    if failed:
        print("SELFTEST FAIL: " + "; ".join(failed))
        return 1
    print("SELFTEST PASS (%d candidates)" % len(out))
    return 0


def load_wordfile(path):
    words = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    words.append(line)
    except OSError as e:
        print("pathgen: 无法读取词文件 %s: %s" % (path, e), file=sys.stderr)
    return words


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="语义化 Web 端点候选生成器: 动作词×资源词×位置前缀×扩展名 组合出隐藏端点候选")
    ap.add_argument("--verbs", default=",".join(DEFAULT_VERBS),
                    help="动作词, 逗号分隔 (默认内置审计/审批类动词)")
    ap.add_argument("--nouns", default=",".join(DEFAULT_NOUNS),
                    help="资源词, 逗号分隔 (默认内置 contract/flag/config 等)")
    ap.add_argument("--specials", default=",".join(DEFAULT_SPECIALS),
                    help="根级精确路径, 逗号分隔 (robots.txt/.env/.git 等)")
    ap.add_argument("--locations", default=",".join(DEFAULT_LOCATIONS),
                    help="API 位置前缀, 逗号分隔; 空串元素表示根路径 (如 ',api/,admin/')")
    ap.add_argument("--extensions", default=",".join(DEFAULT_EXTENSIONS),
                    help="扩展名, 逗号分隔; 空串元素表示无扩展名 (如 ',.php')")
    ap.add_argument("--sep", default="_", help="组合分隔符 (默认 _)")
    ap.add_argument("--no-combos", action="store_true", help="只生成单数, 不生成组合")
    ap.add_argument("--no-singles", action="store_true", help="只生成组合, 不生成单数")
    ap.add_argument("--wordlist", default="", help="追加词文件(每行一个, # 开头为注释)")
    ap.add_argument("--out", default="", help="输出文件路径 (默认 stdout)")
    ap.add_argument("--selftest", action="store_true", help="本地自检生成逻辑, 退出码 0 为通过")
    args = ap.parse_args(argv)

    if args.selftest:
        sys.exit(selftest())

    verbs = [w for w in args.verbs.split(",") if w]
    nouns = [w for w in args.nouns.split(",") if w]
    specials = [w for w in args.specials.split(",") if w]
    locations = args.locations.split(",")          # 保留空串元素(根路径)
    extensions = args.extensions.split(",")        # 保留空串元素(无扩展名)
    extra = load_wordfile(args.wordlist) if args.wordlist else []

    candidates = generate(
        verbs, nouns, specials, locations, extensions,
        sep=args.sep,
        combos=not args.no_combos,
        singles=not args.no_singles,
        extra_words=extra,
    )

    print("# %d candidates (verbs=%d nouns=%d locations=%d extensions=%d)"
          % (len(candidates), len(verbs), len(nouns), len(locations), len(extensions)),
          file=sys.stderr)

    text = "\n".join(candidates) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()

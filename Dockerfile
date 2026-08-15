# 邮宝 YouBao —— TSecBench 托管模式提交镜像(linux/amd64)
# 与本地版差异:入口为 headless runner(启动即解题);build-assets 为 linux_amd64 二进制。
# 构建/导出:
#   docker build --platform linux/amd64 -t youbao:hosted .
#   docker save youbao:hosted | gzip > youbao-hosted.tar.gz

# 基础镜像经 DaoCloud 镜像源拉取(docker.io 在当前网络被阻断;
# 网络正常环境可改回 node:22-slim,效果相同)
FROM docker.m.daocloud.io/library/node:22-slim

# python3(pentool 脚本运行时)+ apt 源里的开源渗透工具 + 二进制分析工具链
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip nmap sqlmap whatweb curl ca-certificates unzip \
      gdb file binutils \
    && rm -rf /var/lib/apt/lists/*

# pwn Python 工具链(Debian PEP 668 需 --break-system-packages)
# 注:slither/solc 在 arm64 无官方二进制(solcjs 不兼容 crytic-compile),合约方向
# 以模型源码审计 + JSON-RPC 为主;需要完整合约工具链时用 --platform linux/amd64 构建。
RUN pip3 install --no-cache-dir --break-system-packages \
      pwntools ROPgadget

# ffuf / nuclei / nuclei 模板:宿主预先下载到 build-assets/(本目录为 linux_amd64 版本),
# 构建只 COPY 不解网。
COPY build-assets/ffuf.tar.gz /tmp/ffuf.tar.gz
COPY build-assets/nuclei.zip /tmp/nuclei.zip
COPY build-assets/nuclei-templates.zip /tmp/nt.zip
RUN set -e; \
    tar -xz -C /usr/local/bin -f /tmp/ffuf.tar.gz ffuf; \
    unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei; \
    unzip -q /tmp/nt.zip -d /tmp; \
    rm -rf /root/nuclei-templates; \
    mv /tmp/nuclei-templates-main /root/nuclei-templates; \
    rm /tmp/ffuf.tar.gz /tmp/nuclei.zip /tmp/nt.zip

# SecLists 常用路径字典(宿主预下载,同 build-assets 方案)
COPY build-assets/common.txt /opt/wordlists/common.txt

# 凭证/口令字典:多阶段题的内网喷洒、SSH/DB/OA 爆破用(2026-08-15 复盘:b-03 内网阶段因
# 容器内无词表只喷了 31 个密码)。均为仓库自带小字典,构建不解网。
COPY build-assets/wordlists/passwords-top.txt /opt/wordlists/passwords-top.txt
COPY build-assets/wordlists/usernames-top.txt /opt/wordlists/usernames-top.txt
COPY build-assets/wordlists/creds-common.txt /opt/wordlists/creds-common.txt
# 兼容历史引用路径(脚本里曾硬编码 /opt/wordlists/ssh-passwords.txt 等)
RUN ln -sf /opt/wordlists/passwords-top.txt /opt/wordlists/ssh-passwords.txt \
    && ln -sf /opt/wordlists/passwords-top.txt /opt/wordlists/mysql-passwords.txt \
    && ln -sf /opt/wordlists/passwords-top.txt /opt/wordlists/wp-passwords.txt

# 横向/隧道工具:构建前在宿主运行 bash build-assets/fetch-pivot-tools.sh 填充;
# 目录里只有 README 时此步为空操作
COPY build-assets/pivot /tmp/pivot
RUN set -e; mkdir -p /opt/pivot; \
    for f in /tmp/pivot/*; do \
      case "$f" in *.md) ;; *) [ -f "$f" ] && cp "$f" /opt/pivot/ && chmod +x "/opt/pivot/$(basename "$f")" || true;; esac; \
    done; rm -rf /tmp/pivot

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
COPY pentools ./pentools
COPY playbooks ./playbooks
COPY experience ./experience
COPY webui ./webui
COPY scripts ./scripts
RUN npm run build && npm prune --omit=dev \
    && mkdir -p runs skills_staging   # 运行时目录(不挂载也能跑,挂载则持久化)

EXPOSE 8080
# 托管模式入口:headless 跑分,容器启动即解题(无人值守,告警自动 skip)。
# 配置全部走平台注入的环境变量(BENCHMARK_TOKEN/BENCHMARK_BASE_URL 由平台下发,
# NANOPI_API_KEY/NANOPI_BASE_URL 等在本平台页面配置;镜像内不含 config.json)。
CMD ["node", "dist/runner.js"]

# 邮宝 YouBao —— 安全攻防 agent —— 一体化镜像
# Web UI + ReAct 跑分内核 + 内置渗透工具(ffuf/nmap/nuclei/sqlmap/whatweb/pwntools/slither)
#
# 构建(全部构建期资产已离线到 build-assets/,仅需拉基础镜像与 apt/pip/npm 源):
#   docker build -t youbao .
# 运行(config.json 为主配置;经验/staging/蒸馏工具/运行记录挂载持久化):
#   docker run -p 8080:8080 \
#     -v $(pwd)/config.json:/app/config.json \
#     -v $(pwd)/runs:/app/runs \
#     -v $(pwd)/experience:/app/experience \
#     -v $(pwd)/skills_staging:/app/skills_staging \
#     -v $(pwd)/pentools/custom:/app/pentools/custom \
#     youbao
# 也可 docker compose up -d(见 docker-compose.yml)

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

# ffuf / nuclei / nuclei 模板:宿主预先下载到 build-assets/(走宿主代理,绕开构建期网络问题),
# 构建只 COPY 不解网。当前资产为 linux_arm64;amd64 构建请替换 build-assets 内文件。
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
CMD ["node", "dist/webui.js"]

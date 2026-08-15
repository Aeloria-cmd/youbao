# 邮宝 YouBao —— 比赛托管 headless 版

本分支是 TSec Benchmark 托管提交的 **headless 构建快照**，与 `main` 的内核改动保持同步
（多 flag 题优先调度、多 pass 重试、战果簿/hint 缓存、超时误判修复等均包含）。

与 `main` 的差异：入口为 headless runner（无 Web UI 交互依赖），build-assets 为 linux/amd64 二进制。

## 构建（只需这一条指令）

```bash
docker build --platform linux/amd64 -t youbao:hosted .
```

导出提交包：

```bash
docker save youbao:hosted | gzip > youbao-hosted.tar.gz
```

可选：构建前拉取内网横向工具（chisel/socat → 镜像内 /opt/pivot/）：

```bash
bash build-assets/fetch-pivot-tools.sh amd64
```

## 运行行为

- 入口 `node dist/runner.js`：容器启动即开始跑分，无人值守（停滞注入 hint 提醒继续，人类告警不启用）。
- 配置全部由平台注入环境变量：`BENCHMARK_TOKEN` / `BENCHMARK_BASE_URL` / `NANOPI_API_KEY` / `NANOPI_BASE_URL` / `NANOPI_MODEL` 等，镜像内不含 config.json。
- 可调旋钮（环境变量）：`TASK_MINUTES`、`MAX_ROUNDS`、`STALL_ROUNDS`、`TASK_CAP_SINGLE_MIN`、`TASK_CAP_PER_FLAG_MIN`、`MAX_CONCURRENT`、`TURN_TIMEOUT_SEC`。

内核与文档见 `main` 分支。

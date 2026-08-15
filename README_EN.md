<div align="center">

  <h1>YouBao</h1>

  <img src="./docs/images/youbao-mascot.png" alt="YouBao" width="560">

  <p>
    An autonomous penetration-testing agent for security benchmarks — two-layer ReAct architecture, three-tier memory, and a self-expanding tool registry<br>
    Powered by nano-pi, a 600-line TypeScript agent kernel with zero black boxes and line-by-line auditability
  </p>

  <p>
    <a href="./LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
    <img src="https://img.shields.io/badge/TypeScript-5.x-3178C6?logo=typescript&logoColor=white" alt="TypeScript">
    <img src="https://img.shields.io/badge/Node.js-%E2%89%A522-339933?logo=node.js&logoColor=white" alt="Node.js >= 22">
    <img src="https://img.shields.io/badge/Docker-all--in--one-2496ED?logo=docker&logoColor=white" alt="Docker">
  </p>

  <p>
    <a href="./README.md">中文文档</a>
  </p>

  <p>
    <a href="#quick-start">Quick Start</a> ·
    <a href="#architecture">Architecture</a> ·
    <a href="#key-features">Features</a> ·
    <a href="#docker-deployment">Docker</a>
  </p>
</div>

---

## Introduction

YouBao is an autonomous penetration-testing agent built for the **TSec Benchmark** range: give it a target machine and it reconnoiters, picks tools, writes its own scripts, and reports flags — fully unattended, or under your supervision via the Web UI at any moment.

The whole system runs on the **nano-pi** kernel — a minimalist TypeScript coding agent of 5 files and 600+ lines (cli / tui / agent / tools / llm). The kernel has no framework magic: every LLM call and every tool execution is a visible event, which makes each step of YouBao's penetration behavior **observable, auditable, and replayable**.

## Architecture

<p align="center">
  <img src="./docs/images/youbao-architecture.png" alt="YouBao system architecture" width="900">
</p>

The outer layer is a **deterministic Task Manager**: task scheduling, container lifecycle, time limits, and stall alerts are all decided by code rather than the LLM, keeping benchmark runs stable and controllable. The inner layer is an **LLM ReAct loop**: inject a state snapshot → reason → invoke tools → report via a structured journal.

The full path of a single round:

<p align="center">
  <img src="./docs/images/youbao-round.png" alt="YouBao single-round execution flow" width="480">
</p>

## Key Features

- **Two-layer ReAct architecture** — the outer Task Manager handles deterministic control (scheduling / containers / time limits / stall alerts) while the inner ReAct loop handles intelligent decisions (snapshot injection → reasoning → tool action → journal reporting). The LLM only does what it's good at
- **Three-tier memory** — `state.json` (current snapshot injected every round), `rounds.jsonl` (fully auditable round log), and lessons (cross-task experience that carries over between targets)
- **Unified `pentool` registry** — ships with ffuf / nmap / nuclei / sqlmap / whatweb (bundled in the Docker image); scripts the agent writes while solving tasks accumulate in `skills_staging/` and can be distilled into newly registered tools with one click in the Web UI — **the toolset grows with every run**
- **Web UI human-in-the-loop** — real-time event stream, status panel, stall-alert decisions (continue / skip), and instruction injection: switch from observer to operator at any time
- **Self-collected metrics** — token cost, per-task duration, score, and alert history are automatically persisted to `summary.json`, ready for post-run review
- **All-in-one Docker image** — Web UI + benchmark kernel + the full pentest toolchain, with offline build assets bundled: one `docker build` and you're done

## Quick Start

Requires **Node.js 22+** and an OpenAI-compatible API.

```bash
git clone https://github.com/Aeloria-cmd/youbao.git
cd youbao
npm install
cp config.example.json config.json   # fill in NANOPI_API_KEY / BENCHMARK_TOKEN
```

Two run modes:

```bash
npm run sec            # CLI: unattended benchmark run
npm run web            # Web UI → http://localhost:8080 (the ⚙ icon edits the config directly)
```

Main configuration keys (`config.json`, takes precedence over environment variables):

| Key | Description |
| --- | --- |
| `NANOPI_API_KEY` / `NANOPI_BASE_URL` / `NANOPI_MODEL` | Key / endpoint / model of the OpenAI-compatible API |
| `BENCHMARK_TOKEN` / `BENCHMARK_BASE_URL` | TSec Benchmark credentials and endpoint |
| `TASK_MINUTES` | Time limit per task (minutes) |
| `STALL_ROUNDS` | Rounds without progress before a stall reminder (unattended: inject hint and continue, never auto-skip) |
| `MAX_ROUNDS` | Maximum rounds per task |
| `VPN_CHECK` | Connectivity probe address for the benchmark VPN |

## Docker Deployment

```bash
docker build -t youbao .
docker run -p 8080:8080 --env-file .env \
  -v $(pwd)/runs:/app/runs \
  -v $(pwd)/skills_staging:/app/skills_staging \
  -v $(pwd)/pentools/custom:/app/pentools/custom \
  youbao
```

> Offline build assets (ffuf / nuclei / nuclei-templates) are bundled under `build-assets/`, currently for linux_arm64 — replace them for amd64 builds. Container traffic is NAT-forwarded through the host by default, so once the host joins the benchmark VPN, containers can reach the targets directly.

## Project Structure

```
├── src/
│   ├── agent.ts / llm.ts / tools.ts / cli.ts / tui.ts   # nano-pi kernel (600+ lines)
│   ├── runner.ts        # outer Task Manager: scheduling / containers / time limits / stall alerts
│   ├── state.ts         # three-tier memory: state.json / rounds.jsonl / lessons
│   ├── sec_tools.ts     # benchmark integration and journal reporting tools
│   ├── pentools.ts      # unified pentool registry
│   ├── distill.ts       # distilling self-written scripts into registered tools
│   └── webui.ts         # Web UI server
├── webui/               # Web UI frontend (event stream / status panel / manual intervention)
├── web/                 # nano-pi tutorial site (Next.js): illustrated kernel walkthrough + Trace debugging
├── pentools/            # tool registry data and custom tool directory
├── playbooks/           # pentest playbook knowledge base
├── experience/          # cross-task experience (lessons)
├── build-assets/        # offline Docker build assets
└── Dockerfile           # all-in-one image: Web UI + kernel + pentest tools
```

## The nano-pi Kernel & Tutorial Site

YouBao's kernel, nano-pi, is a teaching project of its own: it follows the data flow of [pi](https://github.com/earendil-works/pi) and builds only what is needed, as it is needed. The companion tutorial site pairs the article with the source code — the editor on the right fills in the code as you read, and a Trace view lets you step through execution with breakpoints.

```bash
cd web && npm install && npm run dev
```

Read online (original author's site): <https://pi-from-scratch.vercel.app>

## Acknowledgements

- [pi](https://github.com/earendil-works/pi) — the source of nano-pi's data flow and core ideas
- [SaladDay/pi-from-scratch](https://github.com/SaladDay/pi-from-scratch) — the nano-pi kernel and tutorial site are derived from this MIT-licensed original work
- [pi-book](https://books.antinomie.org/pi/) — recommended reading for going deeper into pi

## License

Released under the MIT License; the kernel and tutorial site remain Copyright (c) SaladDay. See [LICENSE](LICENSE).

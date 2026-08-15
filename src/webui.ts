// src/webui.ts
// Web UI 服务(二次开发新增)—— agent 的 Web 人机交互层,零依赖(node:http + SSE)。
//
// 职责:
//   把 runner/distill 的事件流广播给浏览器(SSE);
//   把人类操作(启动/停止/告警决策/注入指令/触发蒸馏)回传给 runner/distill;
//   提供 state.json / staging 快照查询。
//
// 运行:npm run web(PORT 默认 8080)

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { promises as fs } from 'node:fs'
import * as path from 'node:path'
import { startRun, configFromEnv, type RunnerEvent, type RunSummary } from './runner.js'
import { runDistill, listStaging, ensureCustomDir, AUTO_DISTILL_THRESHOLD, type DistillEvent } from './distill.js'
import { CONFIG_FIELDS, readConfigFile, writeConfigFile, configValue, CONFIG_FILE } from './config.js'
import { listProjects, createProject, deleteProject, type Project } from './projects.js'
import { PROJECT_ROOT, loadRegistry, addCustomTool, removeCustomTool, STAGING_DIR } from './pentools.js'

const INDEX_HTML = path.join(PROJECT_ROOT, 'webui', 'index.html')

type SseEvent = ({ src: 'run' } & RunnerEvent) | ({ src: 'distill' } & DistillEvent) | { src: 'server'; type: string; message: string }

export function createWebServer(opts: { configFile?: string; runsDir?: string } = {}) {
  const configFile = opts.configFile ?? CONFIG_FILE
  const RUNS_DIR = opts.runsDir ?? path.join(PROJECT_ROOT, 'runs')
  const clients = new Set<ServerResponse>()
  const backlog: string[] = []           // 最近事件缓存,新连上的客户端补发
  let running = false
  let distilling = false
  let controller: AbortController | null = null
  const inbox: string[] = []
  const pendingAlerts = new Map<string, (d: 'continue' | 'skip') => void>()

  const broadcast = (ev: SseEvent) => {
    const line = `data: ${JSON.stringify(ev)}\n\n`
    backlog.push(line)
    if (backlog.length > 500) backlog.shift()
    for (const c of clients) c.write(line)
  }

  /** 启动一次工具蒸馏(手动/自动共用);已在进行或未配置 API key 时返回错误 */
  const startDistill = async (auto: boolean): Promise<{ ok: boolean; error?: string }> => {
    if (distilling) return { ok: false, error: '蒸馏进行中' }
    const config = await configFromEnv(configFile)
    if (!config.model.apiKey) return { ok: false, error: '服务器未配置 NANOPI_API_KEY' }
    distilling = true
    await ensureCustomDir()
    broadcast({ src: 'server', type: 'status', message: auto ? `staging 达 ${AUTO_DISTILL_THRESHOLD} 个脚本,自动工具蒸馏启动` : '工具蒸馏启动' })
    runDistill(config.model, (ev) => broadcast({ src: 'distill', ...ev }))
      .catch((e: Error) => broadcast({ src: 'server', type: 'error', message: e.message }))
      .finally(() => { distilling = false })
    return { ok: true }
  }

  const json = (res: ServerResponse, status: number, data: unknown) => {
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' })
    res.end(JSON.stringify(data))
  }

  const readBody = (req: IncomingMessage): Promise<Record<string, unknown>> =>
    new Promise((resolve) => {
      let buf = ''
      req.on('data', c => (buf += c))
      req.on('end', () => { try { resolve(JSON.parse(buf || '{}')) } catch { resolve({}) } })
    })

  /** 最近一次运行的 state.json(运行中/结束后都可读) */
  async function latestState(): Promise<unknown> {
    try {
      const dirs = (await fs.readdir(RUNS_DIR)).sort()
      const last = dirs[dirs.length - 1]
      if (!last) return {}
      return JSON.parse(await fs.readFile(path.join(RUNS_DIR, last, 'state.json'), 'utf-8'))
    } catch {
      return {}
    }
  }

  const SAFE_ID = /^(?!\.{1,2}$)[\w.-]+$/

  /** 解析 RUNS_DIR 内的运行目录;越界返回 null(SAFE_ID 之外的第二道防线) */
  function runDirOf(id: string): string | null {
    const root = path.resolve(RUNS_DIR)
    const p = path.resolve(root, id)
    return p.startsWith(root + path.sep) ? p : null
  }

  async function readJsonl(file: string): Promise<unknown[]> {
    try {
      const raw = await fs.readFile(file, 'utf-8')
      return raw.trim().split('\n').filter(Boolean).flatMap(l => {
        try { return [JSON.parse(l)] } catch { return [] }
      })
    } catch {
      return []
    }
  }

  /** 运行列表(项目管理):每场跑分一条 */
  async function listRuns(): Promise<unknown[]> {
    let dirs: string[]
    try { dirs = (await fs.readdir(RUNS_DIR)).sort().reverse() } catch { return [] }
    const runs = []
    for (const id of dirs) {
      if (!SAFE_ID.test(id)) continue
      const dir = path.join(RUNS_DIR, id)
      let summary: Record<string, unknown> = {}
      let state: Record<string, unknown> = {}
      try { summary = JSON.parse(await fs.readFile(path.join(dir, 'summary.json'), 'utf-8')) } catch { /* 运行中 */ }
      try { state = JSON.parse(await fs.readFile(path.join(dir, 'state.json'), 'utf-8')) } catch { continue }
      const challengeCount = Object.keys((state.challenges as object) ?? {}).length
      if (challengeCount === 0 && !summary.finished_at) continue // 空跑目录不展示
      runs.push({
        id,
        project: state.project ?? null,
        started_at: state.started_at ?? null,
        total_score: summary.total_score ?? state.total_score ?? 0,
        solved_count: summary.solved_count ?? null,
        challenge_count: challengeCount,
        total_tokens: summary.total_tokens ?? null,
        duration_min: summary.duration_min ?? null,
        finished: Boolean(summary.finished_at),
      })
    }
    return runs
  }

  async function startRunHandler(req: IncomingMessage, res: ServerResponse) {
    if (running) return json(res, 409, { error: '已有运行中的任务' })
    const body = await readBody(req)
    const projectId = String(body.projectId ?? '')
    const project = projectId ? (await listProjects()).find(p => p.id === projectId) : undefined
    if (projectId && !project) return json(res, 404, { error: '项目不存在' })

    const config = await configFromEnv(configFile)
    // 项目级配置覆盖(创建时填的 token 等优先于全局 config.json)
    if (project?.type === 'benchmark') {
      const c = project.config
      if (c.BENCHMARK_TOKEN) config.benchmarkToken = c.BENCHMARK_TOKEN
      if (c.BENCHMARK_BASE_URL) config.benchmarkBaseUrl = c.BENCHMARK_BASE_URL
      if (c.TASK_MINUTES) config.taskMinutes = Number(c.TASK_MINUTES)
      if (c.MAX_CONCURRENT) config.maxConcurrent = Math.max(1, Number(c.MAX_CONCURRENT))
      if (c.VPN_CHECK) config.vpnCheck = c.VPN_CHECK
    }
    if (project?.type === 'target') config.vpnCheck = 'off'
    if (project?.type !== 'target' && !config.benchmarkToken) return json(res, 400, { error: '未配置 BENCHMARK_TOKEN' })
    if (!config.model.apiKey) return json(res, 400, { error: '未配置 NANOPI_API_KEY' })

    running = true
    controller = new AbortController()
    broadcast({ src: 'server', type: 'status', message: `任务启动${project ? ` · 项目 ${project.name}` : ''}` })
    startRun(config, {
      emit: (ev) => broadcast({ src: 'run', ...ev }),
      signal: controller.signal,
      inbox,
      askHuman: (alert) => new Promise(resolve => { pendingAlerts.set(alert.id, resolve) }),
    }, project)
      .then((summary: RunSummary) => broadcast({ src: 'server', type: 'status', message: `任务结束:${summary.solved_count} 题 / ${summary.total_score} 分` }))
      .catch((e: Error) => broadcast({ src: 'server', type: 'error', message: e.message }))
      .finally(() => { running = false; controller = null })
    return json(res, 200, { ok: true })
  }

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost')
    const route = `${req.method} ${url.pathname}`

    try {
      if (route === 'GET /') {
        const html = await fs.readFile(INDEX_HTML, 'utf-8')
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
        return res.end(html)
      }
      if (route === 'GET /events') {
        res.writeHead(200, {
          'content-type': 'text/event-stream',
          'cache-control': 'no-cache',
          connection: 'keep-alive',
        })
        res.write(': connected\n\n')
        for (const line of backlog) res.write(line)
        clients.add(res)
        req.on('close', () => clients.delete(res))
        return
      }
      if (route === 'GET /api/state') return json(res, 200, await latestState())
      if (route === 'GET /api/projects') return json(res, 200, await listProjects())
      if (route === 'POST /api/projects') {
        const body = await readBody(req)
        try {
          const project = await createProject({
            name: String(body.name ?? ''),
            type: body.type === 'target' ? 'target' : 'benchmark',
            config: (body.config ?? {}) as Record<string, string>,
          })
          return json(res, 200, project)
        } catch (e) {
          return json(res, 400, { error: (e as Error).message })
        }
      }
      if (route === 'POST /api/projects/delete') {
        const body = await readBody(req)
        return json(res, 200, { ok: await deleteProject(String(body.id ?? '')) })
      }
      if (route === 'POST /api/runs/delete') {
        const body = await readBody(req)
        const id = String(body.id ?? '')
        if (!SAFE_ID.test(id)) return json(res, 400, { error: 'bad id' })
        const dir = runDirOf(id)
        if (!dir) return json(res, 400, { error: 'bad id' })
        // 正在运行时拒绝删除最新一场(与 latestState() 同序:排序后最后一个)
        if (running) {
          try {
            const dirs = (await fs.readdir(RUNS_DIR)).sort()
            if (dirs[dirs.length - 1] === id) return json(res, 409, { error: '该场次正在运行,不能删除' })
          } catch { /* runs 目录不可读时跳过该守卫 */ }
        }
        await fs.rm(dir, { recursive: true, force: true })
        return json(res, 200, { ok: true })
      }
      if (route === 'GET /api/runs') return json(res, 200, await listRuns())
      if (route === 'GET /api/run') {
        const id = url.searchParams.get('id') ?? ''
        if (!SAFE_ID.test(id)) return json(res, 400, { error: 'bad id' })
        const dir = runDirOf(id)
        if (!dir) return json(res, 400, { error: 'bad id' })
        let summary = null, state = null
        try { summary = JSON.parse(await fs.readFile(path.join(dir, 'summary.json'), 'utf-8')) } catch { }
        try { state = JSON.parse(await fs.readFile(path.join(dir, 'state.json'), 'utf-8')) } catch { }
        if (!state && !summary) return json(res, 404, { error: 'run 不存在' })
        return json(res, 200, { id, summary, state })
      }
      if (route === 'GET /api/run/challenge') {
        const id = url.searchParams.get('id') ?? ''
        const code = url.searchParams.get('code') ?? ''
        const kind = url.searchParams.get('kind') ?? 'rounds'
        if (!SAFE_ID.test(id) || !SAFE_ID.test(code)) return json(res, 400, { error: 'bad params' })
        if (kind !== 'rounds' && kind !== 'transcript') return json(res, 400, { error: 'kind 仅支持 rounds|transcript' })
        const dir = runDirOf(id)
        if (!dir) return json(res, 400, { error: 'bad id' })
        const records = await readJsonl(path.join(dir, `${kind}-${code}.jsonl`))
        return json(res, 200, records)
      }
      if (route === 'GET /api/run/log') {
        const id = url.searchParams.get('id') ?? ''
        if (!SAFE_ID.test(id)) return json(res, 400, { error: 'bad id' })
        const dir = runDirOf(id)
        if (!dir) return json(res, 400, { error: 'bad id' })
        return json(res, 200, await readJsonl(path.join(dir, 'events.jsonl')))
      }
      if (route === 'GET /api/tools') {
        // 工具集页数据:注册表(内置/蒸馏分开)+ 调用统计 + 临时工具
        let stats: Record<string, number> = {}
        try { stats = JSON.parse(await fs.readFile(path.join(PROJECT_ROOT, 'tool-stats.json'), 'utf-8')) } catch { }
        const registry = await loadRegistry()
        return json(res, 200, {
          builtin: registry.filter(e => e.source === 'builtin'),
          distilled: registry.filter(e => e.source === 'distilled'),
          staging: await listStaging(),
          stats,
        })
      }
      if (route === 'GET /api/config') {
        // 有效值 = config.json 覆盖后的结果(含 env 兜底),供设置页回显
        const fileValues = await readConfigFile(configFile)
        const values: Record<string, string> = {}
        for (const f of CONFIG_FIELDS) values[f.key] = configValue(f.key, fileValues, '') ?? ''
        return json(res, 200, { fields: CONFIG_FIELDS, values })
      }
      if (route === 'POST /api/config') {
        const body = await readBody(req)
        const values: Record<string, string> = {}
        for (const f of CONFIG_FIELDS) {
          if (typeof body[f.key] === 'string') values[f.key] = body[f.key] as string
        }
        await writeConfigFile(values, configFile)
        broadcast({ src: 'server', type: 'status', message: '配置已保存,下次启动跑分生效' })
        return json(res, 200, { ok: true })
      }
      if (route === 'GET /api/staging') {
        const files = await listStaging()
        return json(res, 200, { count: files.length, auto_threshold: AUTO_DISTILL_THRESHOLD, files, running, distilling })
      }
      if (route === 'POST /api/start') return await startRunHandler(req, res)
      if (route === 'POST /api/stop') {
        controller?.abort()
        return json(res, 200, { ok: controller != null })
      }
      if (route === 'POST /api/answer') {
        const body = await readBody(req)
        const resolve = pendingAlerts.get(String(body.id ?? ''))
        if (!resolve) return json(res, 404, { error: '告警不存在或已处理' })
        pendingAlerts.delete(String(body.id))
        resolve(body.decision === 'continue' ? 'continue' : 'skip')
        return json(res, 200, { ok: true })
      }
      if (route === 'POST /api/inject') {
        const body = await readBody(req)
        const text = String(body.text ?? '').trim()
        if (!text) return json(res, 400, { error: '空指令' })
        inbox.push(text)
        broadcast({ src: 'server', type: 'status', message: `已注入人类指令:${text.slice(0, 80)}` })
        return json(res, 200, { ok: true })
      }
      if (route === 'POST /api/distill') {
        const r = await startDistill(false)
        if (r.ok) return json(res, 200, { ok: true })
        return json(res, r.error === '蒸馏进行中' ? 409 : 400, { error: r.error })
      }

      if (route === 'POST /api/tools/create') {
        const body = await readBody(req)
        try {
          await addCustomTool(
            { name: String(body.name ?? ''), purpose: String(body.purpose ?? ''), usage: String(body.usage ?? ''), timeout: Number(body.timeout) || 120 },
            String(body.script ?? ''),
          )
          return json(res, 200, { ok: true })
        } catch (e) {
          return json(res, 400, { error: (e as Error).message })
        }
      }
      if (route === 'POST /api/tools/delete') {
        const body = await readBody(req)
        try {
          return json(res, 200, { ok: await removeCustomTool(String(body.name ?? '')) })
        } catch (e) {
          return json(res, 400, { error: (e as Error).message })
        }
      }
      if (route === 'POST /api/tools/staging/delete') {
        const body = await readBody(req)
        const file = path.basename(String(body.file ?? ''))
        if (!file.endsWith('.py') && !file.endsWith('.sh')) return json(res, 400, { error: 'bad file' })
        await fs.rm(path.join(STAGING_DIR, file), { force: true })
        return json(res, 200, { ok: true })
      }
      if (route === 'POST /api/tools/promote') {
        // 把 staging 临时脚本提升为注册工具
        const body = await readBody(req)
        const file = path.basename(String(body.file ?? ''))
        try {
          const script = await fs.readFile(path.join(STAGING_DIR, file), 'utf-8')
          await addCustomTool(
            { name: String(body.name ?? ''), purpose: String(body.purpose ?? ''), usage: String(body.usage ?? ''), timeout: Number(body.timeout) || 120 },
            script,
          )
          return json(res, 200, { ok: true })
        } catch (e) {
          return json(res, 400, { error: (e as Error).message })
        }
      }

      json(res, 404, { error: 'not found' })
    } catch (e) {
      json(res, 500, { error: (e as Error).message })
    }
  })

  // 自动工具整合:staging 积累到 AUTO_DISTILL_THRESHOLD(默认 20)个脚本时自动蒸馏一次。
  // 同一数量只触发一次(避免无产出时每分钟空转),有新增脚本使计数变化后再次达标会再触发。
  // 关键约束:只在跑分空闲时真正启动(不打断轮次)——运行中蒸馏会与 worker 抢 LLM 配额,
  // 且蒸馏改写 registry.json 期间 pentool 调用可能读到半截文件。运行结束后 60s 内补触发。
  let lastAutoCount = -1
  let distillPending = false
  const autoTimer = setInterval(async () => {
    try {
      if (distilling) return
      const count = (await listStaging()).length
      if (count >= AUTO_DISTILL_THRESHOLD && count !== lastAutoCount) {
        lastAutoCount = count
        distillPending = true
      }
      if (distillPending && !running) {
        distillPending = false
        await startDistill(true)
      }
    } catch { /* 自动触发失败不影响服务 */ }
  }, 60_000)
  autoTimer.unref?.()

  return server
}

// 只在直接运行时启动(npm run web)
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT ?? 8080)
  createWebServer().listen(port, () => {
    console.log(`[webui] http://localhost:${port}`)
  })
}

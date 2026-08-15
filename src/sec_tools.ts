// src/sec_tools.ts
// 安全 agent 专用工具（二次开发新增）：
//   benchmark_api —— TSec Benchmark 控制面（模型可用 list/hint/submit；
//                    start/close 归 runner 独占，模型调用会被拒绝），
//                    替代模型用 run_bash 裸 curl：认证、错误码、状态沉淀全部封死。
//   journal       —— ReAct 汇报工具：模型每轮结束前必须调用，
//                    把"推理/假设/动作/观察/进展/下一步"结构化写入状态库。
//
// 渗透动作本身（打 payload、访问靶机）仍走内置 run_bash，不在这里封装。

import type { AgentTool } from './agent.js'
import type { StateStore } from './state.js'

export type BenchmarkConfig = {
  baseUrl: string   // 如 https://tsecbench.zc.tencent.com
  token: string     // BENCHMARK_TOKEN
}

type ApiResult =
  | { ok: true; data: unknown }
  | { ok: false; code: string; message: string }

/** flag 本地预校验(对齐平台 422:长度 1~4096),越界返回错误文案,合法返回 null */
export function validateFlag(flag: string): string | null {
  if (typeof flag !== 'string' || flag.length < 1) return 'flag 不能为空'
  if (flag.length > 4096) return `flag 长度 ${flag.length} 超过平台上限 4096`
  return null
}

export async function callApi(cfg: BenchmarkConfig, action: string, params: { unique_code?: string; flag?: string }): Promise<ApiResult> {
  const base = `${cfg.baseUrl}/openapi/v1/challenges`
  const headers = { BENCHMARK_TOKEN: cfg.token, 'content-type': 'application/json' }

  // internal_error(500)按官方 SDK 建议自动重试一次
  for (let attempt = 1; attempt <= 2; attempt++) {
    let res: Response
    try {
      if (action === 'list') {
        res = await fetch(base, { headers })
      } else if (action === 'submit') {
        res = await fetch(`${base}/submit`, {
          method: 'POST', headers,
          body: JSON.stringify({ unique_code: params.unique_code, flag: params.flag }),
        })
      } else {
        // start / close / hint 都是 query 参数
        const url = `${base}/${action}?unique_code=${encodeURIComponent(params.unique_code ?? '')}`
        res = await fetch(url, { method: action === 'hint' ? 'GET' : 'POST', headers })
      }
    } catch (e) {
      return { ok: false, code: 'network_error', message: (e as Error).message }
    }

    const text = await res.text()
    let body: unknown = null
    try { body = JSON.parse(text) } catch { /* 非 JSON 响应原样返回 */ }

    if (!res.ok) {
      const err = body as { code?: string; message?: string } | null
      const code = err?.code ?? `http_${res.status}`
      const message = err?.message ?? text.slice(0, 300)
      if (code === 'internal_error' && attempt === 1) continue // 重试一次
      return { ok: false, code, message }
    }
    return { ok: true, data: body }
  }
  return { ok: false, code: 'internal_error', message: 'retry exhausted' }
}

/** 构造 benchmark_api + journal 两个工具(携带状态库闭包;journal 绑定到指定题目,支持并行 worker)。
 *  opts.benchmark === false 时(target 靶场模式)不含 benchmark_api */
export function securityTools(
  cfg: BenchmarkConfig, store: StateStore, journalCode: string,
  opts: { benchmark?: boolean } = {},
): AgentTool[] {
  const benchmarkApi: AgentTool = {
    name: 'benchmark_api',
    description:
      '调用 TSec Benchmark 平台接口。参数：action（list/hint/submit）、unique_code（submit/hint 时必填）、flag（submit 时必填）。' +
      'submit 正确会自动记分并更新状态；返回附带 [state] 当前总分与剩余时间。' +
      'hint 每题只能兑换一次（扣分），已兑换过的会直接返回缓存，不重复扣分。' +
      '容器生命周期（start/close）由调度器独占管理，模型不可用——需要刷新目标地址时用 list 查看 container_addr。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['list', 'hint', 'submit'], description: '接口动作' },
        unique_code: { type: 'string', description: '题目唯一标识' },
        flag: { type: 'string', description: '提交的 flag（仅 submit）' },
      },
      required: ['action'],
    },
    execute: async (args) => {
      const { action, unique_code, flag } = args as { action: string; unique_code?: string; flag?: string }

      // 容器生命周期归调度器独占：模型启动/关闭容器会打断其他题的链条状态(IP 变更/环境重置)
      if (action === 'start' || action === 'close') {
        return JSON.stringify({
          ok: false, code: 'not_allowed',
          message: 'start/close 由调度器管理，模型不可调用。目标失联时用 action=list 查看本题最新 container_addr。',
        })
      }

      // submit 前置本地校验(对齐平台 422,省一次往返)
      if (action === 'submit') {
        const err = validateFlag(flag ?? '')
        if (err) return JSON.stringify({ ok: false, code: 'validation_error', message: err })
      }

      // hint 缓存：每题只兑换一次。compaction 后模型不记得换过，直接调 API 会重复扣分
      if (action === 'hint' && unique_code) {
        const cached = store.state.challenges[unique_code]?.hint
        if (cached) {
          const stateLine = `[state] total_score=${store.state.total_score} time_left=${store.timeLeft() === null ? 'n/a' : Math.max(0, Math.round(store.timeLeft()! / 60000)) + 'min'}`
          return JSON.stringify({ ok: true, cached: true, data: { unique_code, hint: cached } }, null, 2)
            + '\n（本题 hint 已兑换过，本次为缓存返回，未重复扣分）\n' + stateLine
        }
      }

      const result = await callApi(cfg, action, { unique_code, flag })

      // submit 正确 → 记分落盘（多 flag 题靠 flags_found/total 推进）
      if (result.ok && action === 'submit' && unique_code) {
        const d = result.data as { correct?: boolean; awarded?: number; correct_flag_count?: number; total_flag_count?: number }
        if (d.correct) {
          await store.recordFlag(unique_code, d.awarded ?? 0, d.correct_flag_count ?? 0, d.total_flag_count ?? 1)
        }
      }

      // hint 兑换成功 → 文本缓存进状态库（随 [state] 快照跨 compaction 存活）
      if (result.ok && action === 'hint' && unique_code) {
        const hintText = (result.data as { hint?: string | null }).hint ?? null
        if (hintText) await store.setHint(unique_code, hintText)
      }

      // duplicate:幂等,给模型明确指引(对齐 SDK DuplicateSubmit 处理)
      if (!result.ok && result.code === 'duplicate') {
        result.message += '。该 flag 已计入得分,请换下一个 flag,不要重复提交'
      }

      const left = store.timeLeft()
      const stateLine = `[state] total_score=${store.state.total_score} time_left=${left === null ? 'n/a' : Math.max(0, Math.round(left / 60000)) + 'min'}`
      return JSON.stringify(result, null, 2) + '\n' + stateLine
    },
  }

  const journal: AgentTool = {
    name: 'journal',
    description:
      `【每轮结束前必须调用】把本轮 ReAct 循环结构化写入状态库(当前题目: ${journalCode}):推理、假设、动作、观察、是否有进展、下一步计划。` +
      '这是跨轮/跨题记忆的唯一载体——不写 journal，下轮你就忘了。' +
      '拿到 webshell/凭证/会话必须写进 access 字段，发现内网主机/服务必须写进 internal_hosts 字段——它们会随每轮 [state] 注入，context 压缩后仍在。',
    parameters: {
      type: 'object',
      properties: {
        thought: { type: 'string', description: '本轮推理：观察到什么、怎么判断的' },
        hypothesis: { type: 'string', description: '当前假设（怀疑的漏洞类型/入口）' },
        actions: { type: 'array', items: { type: 'string' }, description: '本轮关键动作' },
        observation: { type: 'string', description: '服务器/工具的关键返回' },
        progress: { type: 'boolean', description: '本轮是否有实质进展（新端点/新凭证/新立足点/新网段都算）' },
        finding: { type: 'string', description: '有进展时的具体发现（可选）' },
        access: { type: 'string', description: '新建立的访问能力（可选）：webshell URL 与参数、凭证 用户/密码、会话 cookie 等，写清用法' },
        internal_hosts: { type: 'string', description: '新发现的内网主机/服务（可选）：IP:端口 服务 指纹，多条用 ; 分隔' },
        lesson: { type: 'string', description: '可跨题复用的经验（可选）' },
        next_plan: { type: 'string', description: '下一步计划' },
      },
      required: ['thought', 'hypothesis', 'actions', 'observation', 'progress', 'next_plan'],
    },
    execute: async (args) => {
      const rec = args as Parameters<StateStore['appendRound']>[1]
      // 模型有时把 actions 写成字符串——入库前规整为数组,保证下游渲染安全
      if (!Array.isArray(rec.actions)) rec.actions = rec.actions ? [String(rec.actions)] : []
      const round = await store.appendRound(journalCode, rec)
      return `journal recorded: round ${round} (challenge ${journalCode})`
    },
  }

  return opts.benchmark === false ? [journal] : [benchmarkApi, journal]
}

// src/distill.ts
// 工具蒸馏工作流（二次开发新增）—— agent 自写脚本的沉淀管道。
//
// 流程（人工在 Web UI 点击触发,不自动跑）：
//   skills_staging/ 下的临时脚本积累到阈值
//   → runDistill 开一个独立 LLM 会话：读 staging 脚本 + 近期 rounds.jsonl
//   → 找出有共性的能力,重构成一个有独创性的通用工具(参数化 + --selftest)
//   → 写入 pentools/custom/<name>.py 并登记 pentools/custom/registry.json
//   → 跑 --selftest 验证,失败则回滚
// 成功后新工具立即进入统一注册表,后续 pentool 调用可见(每次调用重读注册表)。

import { promises as fs } from 'node:fs'
import * as path from 'node:path'
import { runAgent } from './agent.js'
import { builtinTools } from './tools.js'
import { CUSTOM_DIR, CUSTOM_REGISTRY, STAGING_DIR, loadRegistry } from './pentools.js'
import type { Model, Context } from './llm.js'

/** staging 积累到该数量时,UI 提示可以尝试工具整合 */
export const DISTILL_THRESHOLD = 5

export type DistillEvent =
  | { type: 'log'; text: string }
  | { type: 'assistant_text'; delta: string }
  | { type: 'tool_call'; name: string; preview: string }
  | { type: 'done'; ok: boolean; message: string }

/** 列出 staging 中积累的临时脚本 */
export async function listStaging(): Promise<string[]> {
  try {
    const files = await fs.readdir(STAGING_DIR)
    return files.filter(f => f.endsWith('.py')).sort()
  } catch {
    return []
  }
}

const DISTILL_PROMPT = `你是工具架构师。渗透 agent 在长期工作中把临时自写脚本积累在 STAGING_DIR_PLACEHOLDER 目录。
你的任务：审阅这些脚本，把其中有共性的能力蒸馏成一个**有独创性的通用工具**，登记进渗透工具注册表。

步骤（严格遵守）：
1. 用 read_file 逐个阅读 staging 脚本（目录列表已在下方给出）。
2. 识别共性：哪些脚本在解决同一类问题？提炼出一个参数化的通用工具能覆盖它们。
3. 查重：现有注册表条目已在下方给出。若你的构想与已有工具重复（功能等价），直接放弃并在最后说明，不要硬造。
4. 设计并实现：在 pentools/custom/ 下写 <name>.py：
   - 只用 Python 标准库；argparse 参数化（目标、端口、路径等一律走命令行参数，禁止硬编码）；
   - 文件头注释写清用途与用法；
   - 必须支持 --selftest：不依赖外部网络、本地自检核心逻辑（如构造本地数据验证解析/匹配函数），退出码 0 为通过。
5. 登记：用 edit 把新条目追加到 pentools/custom/registry.json（JSON 数组），格式：
   {"name": "<name>", "kind": "script", "command": "pentools/custom/<name>.py", "source": "distilled", "purpose": "<一句话用途>", "usage": "<用法示例>", "timeout": 120}
   注意保持整个文件仍是合法 JSON。
6. 验证：run_bash 执行 python3 pentools/custom/<name>.py --selftest。失败则修复;修不好就删除脚本并回滚 registry.json。
7. 完成后，用一段话总结：新工具名、解决的共性问题、与已有工具的差异。

约束：一次只蒸馏一个工具；宁缺毋滥——脚本没有共性或质量太差时，明确报告"本轮无产出"。`

/**
 * 跑一次蒸馏会话。events 经 emit 广播(供 Web UI 实时展示)。
 * 返回是否产出了新工具。
 */
export async function runDistill(model: Model, emit: (ev: DistillEvent) => void): Promise<{ ok: boolean; message: string }> {
  const scripts = await listStaging()
  if (scripts.length === 0) {
    const message = 'skills_staging/ 为空,没有可蒸馏的脚本'
    emit({ type: 'done', ok: false, message })
    return { ok: false, message }
  }

  const registry = await loadRegistry()
  const registrySummary = registry.map(e => `- ${e.name} (${e.source}): ${e.purpose}`).join('\n')

  const before = new Set(registry.map(e => e.name))
  const context: Context = {
    systemPrompt: DISTILL_PROMPT.replace('STAGING_DIR_PLACEHOLDER', STAGING_DIR),
    messages: [{
      role: 'user',
      content: `staging 脚本列表:\n${scripts.map(s => `- ${path.join(STAGING_DIR, s)}`).join('\n')}\n\n现有注册表:\n${registrySummary}\n\n近期跑分记录在 runs/ 下的 rounds.jsonl(可选参考,了解脚本是在什么场景写的)。开始蒸馏。`,
    }],
  }

  emit({ type: 'log', text: `[distill] 开始蒸馏:${scripts.length} 个 staging 脚本` })
  for await (const ev of runAgent(model, context, builtinTools())) {
    if (ev.type === 'assistant_text') emit({ type: 'assistant_text', delta: ev.delta })
    else if (ev.type === 'tool_call') emit({ type: 'tool_call', name: ev.name, preview: JSON.stringify(ev.args).slice(0, 200) })
    else if (ev.type === 'turn_end' && ev.stopReason === 'error') {
      const message = '蒸馏会话出错(LLM stream error)'
      emit({ type: 'done', ok: false, message })
      return { ok: false, message }
    }
  }

  // 判定产出:注册表是否新增条目
  const after = await loadRegistry()
  const added = after.filter(e => !before.has(e.name))
  if (added.length) {
    const message = `新工具已注册: ${added.map(e => e.name).join(', ')}`
    emit({ type: 'done', ok: true, message })
    return { ok: true, message }
  }
  const message = '蒸馏结束,无新工具产出(无共性/查重放弃/验证失败)'
  emit({ type: 'done', ok: false, message })
  return { ok: false, message }
}

/** 初始化 custom 目录与空注册表(幂等) */
export async function ensureCustomDir(): Promise<void> {
  await fs.mkdir(CUSTOM_DIR, { recursive: true })
  try {
    await fs.access(CUSTOM_REGISTRY)
  } catch {
    await fs.writeFile(CUSTOM_REGISTRY, '[]\n', 'utf-8')
  }
}

// src/experience.ts
// 经验层(二次开发新增)—— 跨会话的渗透经验积累。
//
// 设计规则(为 AI 快速阅读/检索优化,不是阅读负担):
//   - 存储:experience/<domain>.jsonl,四方向隔离(web / pwn / ai-llm / blockchain / misc)。
//     JSONL 追加友好、grep 友好、git diff 友好。
//   - 每条经验一行 JSON:kind(lesson/payload/pitfall/pattern)+ title(一句话)+ tags + score。
//     title 必须是自包含的一句话,模型扫一眼就能用;细节才进 detail。
//   - 去重:同 domain 同 title 不新增,score+1(被重复验证的经验排前面)。
//   - 注入:renderForPrompt() 把每个方向 top N 渲染成单行列表进 system prompt;
//     模型需要细节时 read_file experience/<domain>.jsonl 自己查。
//
// 沉淀时机:每轮跑分结束后,runner 自动从 rounds-<code>.jsonl 提炼(确定性,无 LLM)。

import { promises as fs } from 'node:fs'
import * as path from 'node:path'
import { PROJECT_ROOT } from './pentools.js'
import type { AgentState } from './state.js'

export const EXPERIENCE_DIR = path.join(PROJECT_ROOT, 'experience')

export type Domain = 'web' | 'pwn' | 'ai-llm' | 'blockchain' | 'misc'
export const DOMAINS: Domain[] = ['web', 'pwn', 'ai-llm', 'blockchain', 'misc']

export type ExperienceKind = 'lesson' | 'payload' | 'pitfall' | 'pattern'

export type ExperienceEntry = {
  id: string
  ts: string
  domain: Domain
  kind: ExperienceKind
  /** 一句话经验(自包含,≤120 字) */
  title: string
  detail?: string
  tags: string[]
  /** 来源场次/题目 */
  source?: string
  /** 重复验证次数(去重时 +1,排序依据) */
  score: number
}

/** 从题号/描述推断方向(四方向隔离) */
export function inferDomain(code: string, description?: string | null): Domain {
  const text = `${code} ${description ?? ''}`
  if (/合约|以太坊|区块链|solidity|web3|token|链上/i.test(text)) return 'blockchain'
  if (/pwn|二进制|溢出|ROP|格式化字符串|逆向|ELF/i.test(text)) return 'pwn'
  if (/LLM|大模型|提示词|prompt|AI 助手|智能体|模型/i.test(text)) return 'ai-llm'
  if (/web|http|php|注入|上传|xss|ssrf|xxe|路径|遍历|登录/i.test(text)) return 'web'
  if (/^[a-z]+-\d+$/i.test(code) && code.startsWith('a')) return 'web' // 靶场 a- 系为 Web
  return 'misc'
}

function domainFile(domain: Domain, root: string): string {
  return path.join(root, `${domain}.jsonl`)
}

export async function loadDomain(domain: Domain, root: string = EXPERIENCE_DIR): Promise<ExperienceEntry[]> {
  try {
    const raw = await fs.readFile(domainFile(domain, root), 'utf-8')
    return raw.trim().split('\n').filter(Boolean).map(l => JSON.parse(l) as ExperienceEntry)
  } catch {
    return []
  }
}

/** 追加经验;同 domain 同 title 去重为 score+1。返回新增条数 */
export async function appendExperience(
  entries: Omit<ExperienceEntry, 'id' | 'ts' | 'score'>[],
  root: string = EXPERIENCE_DIR,
): Promise<number> {
  await fs.mkdir(root, { recursive: true })
  let added = 0
  const byDomain = new Map<Domain, typeof entries>()
  for (const e of entries) {
    const list = byDomain.get(e.domain) ?? []
    list.push(e)
    byDomain.set(e.domain, list)
  }
  for (const [domain, list] of byDomain) {
    const existing = await loadDomain(domain, root)
    for (const e of list) {
      const dup = existing.find(x => x.title === e.title)
      if (dup) { dup.score += 1; continue }
      existing.push({
        ...e,
        id: `${domain}-${Date.now().toString(36)}-${existing.length + 1}`,
        ts: new Date().toISOString(),
        score: 1,
      })
      added++
    }
    // 全量重写(去重后要更新 score;文件小,重写最简单可靠)
    await fs.writeFile(
      domainFile(domain, root),
      existing.map(x => JSON.stringify(x)).join('\n') + '\n',
      'utf-8',
    )
  }
  return added
}

/** 注入提示词的紧凑渲染:每方向 top N,一行一条 */
export async function renderForPrompt(maxPerDomain = 8, root: string = EXPERIENCE_DIR): Promise<string> {
  const sections: string[] = []
  for (const domain of DOMAINS) {
    const entries = await loadDomain(domain, root)
    if (!entries.length) continue
    const top = entries.sort((a, b) => b.score - a.score).slice(0, maxPerDomain)
    sections.push(`[${domain}]`)
    for (const e of top) {
      sections.push(`- (${e.kind}×${e.score}) ${e.title}${e.tags.length ? ` #${e.tags.join(' #')}` : ''}`)
    }
  }
  return sections.join('\n')
}

/** 清洗经验文本:flag 值是题目动态实例噪声,替换为占位符 */
function sanitize(text: string): string {
  return text.replace(/flag\{[^}]*\}/g, 'flag{...}').slice(0, 120)
}

/** 赛后沉淀:从一轮运行的 rounds 文件中提炼经验(确定性规则,无 LLM) */
export async function collectFromRun(runDir: string, root: string = EXPERIENCE_DIR): Promise<number> {
  const state: AgentState = JSON.parse(await fs.readFile(path.join(runDir, 'state.json'), 'utf-8'))
  const runName = path.basename(runDir)
  const entries: Omit<ExperienceEntry, 'id' | 'ts' | 'score'>[] = []
  const seen = new Set<string>()

  for (const file of await fs.readdir(runDir)) {
    const m = file.match(/^rounds-(.+)\.jsonl$/)
    if (!m) continue
    const code = m[1]
    const ch = state.challenges[code]
    const domain = inferDomain(code, ch?.description)
    const solved = ch?.status === 'solved'
    const raw = await fs.readFile(path.join(runDir, file), 'utf-8').catch(() => '')
    for (const line of raw.trim().split('\n').filter(Boolean)) {
      let rec: { finding?: string; lesson?: string; progress?: boolean }
      try { rec = JSON.parse(line) } catch { continue }
      // 通关题的 finding = 验证有效的打法(pattern);未通关题的 finding = 线索(lesson)
      if (rec.finding && !seen.has(rec.finding)) {
        seen.add(rec.finding)
        entries.push({
          domain, kind: solved ? 'pattern' : 'lesson',
          title: sanitize(rec.finding),
          tags: [code], source: `${runName}/${code}`,
        })
      }
      if (rec.lesson && !seen.has(rec.lesson)) {
        seen.add(rec.lesson)
        entries.push({
          domain, kind: 'lesson',
          title: sanitize(rec.lesson),
          tags: [code], source: `${runName}/${code}`,
        })
      }
    }
  }
  return appendExperience(entries, root)
}

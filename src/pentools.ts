// src/pentools.ts
// 渗透工具统一注册表 + pentool 调用层（二次开发新增）。
//
// 三层工具体系，一个注册表：
//   builtin   —— 开源工具（ffuf/nmap/nuclei/sqlmap/whatweb），Docker 镜像内置。
//               本地 dev 未安装时明确报错提示，不写自写替代品。
//   distilled —— agent 自写脚本经蒸馏沉淀的自定义工具，
//               从 pentools/custom/registry.json 运行时加载（每次调用重读，即时生效）。
//
// agent 纪律（由 runner 注入提示词）：渗透工具一律先查注册表、经 pentool 调用；
// 开源工具办不到时才自写脚本到 skills_staging/。

import { exec } from 'node:child_process'
import { promisify } from 'node:util'
import { promises as fs } from 'node:fs'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'
import type { AgentTool } from './agent.js'
import { truncateOutput } from './tools.js'

const execAsync = promisify(exec)

/** 仓库根目录（src/ 与 dist/ 下均指向根） */
export const PROJECT_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')
export const CUSTOM_DIR = path.join(PROJECT_ROOT, 'pentools', 'custom')
export const CUSTOM_REGISTRY = path.join(CUSTOM_DIR, 'registry.json')
export const STAGING_DIR = path.join(PROJECT_ROOT, 'skills_staging')

export type PenToolEntry = {
  name: string
  /** binary = 镜像内二进制; script = python3 运行的仓库内脚本(相对仓库根路径) */
  kind: 'binary' | 'script'
  command: string
  source: 'builtin' | 'distilled'
  purpose: string
  usage: string
  /** 默认超时秒数 */
  timeout: number
}

/** 内置开源工具(Docker 镜像安装,见 Dockerfile) */
export const BUILTIN_PENTOOLS: PenToolEntry[] = [
  {
    name: 'ffuf', kind: 'binary', command: 'ffuf', source: 'builtin',
    purpose: '目录/端点/参数爆破(配合字典,比手猜路径快几个量级)',
    usage: 'ffuf -u http://TARGET/FUZZ -w /opt/wordlists/common.txt -mc all -fc 404',
    timeout: 180,
  },
  {
    name: 'nmap', kind: 'binary', command: 'nmap', source: 'builtin',
    purpose: '端口与服务扫描(容器可能开放非 Web 端口)',
    usage: 'nmap -sV --top-ports 100 TARGET_IP',
    timeout: 300,
  },
  {
    name: 'nuclei', kind: 'binary', command: 'nuclei', source: 'builtin',
    purpose: '模板化已知漏洞检测(社区模板库,误报低)',
    usage: 'nuclei -u http://TARGET -silent',
    timeout: 300,
  },
  {
    name: 'sqlmap', kind: 'binary', command: 'sqlmap', source: 'builtin',
    purpose: 'SQL 注入自动检测与利用(盲注/时间注比手工试错省 token)',
    usage: 'sqlmap -u "http://TARGET/page.php?id=1" --batch --level=2 --risk=1',
    timeout: 300,
  },
  {
    name: 'whatweb', kind: 'binary', command: 'whatweb', source: 'builtin',
    purpose: 'Web 指纹识別(框架/CMS/服务器版本)',
    usage: 'whatweb http://TARGET',
    timeout: 60,
  },
  {
    name: 'ROPgadget', kind: 'binary', command: 'ROPgadget', source: 'builtin',
    purpose: 'ROP 链 gadget 搜索(pwn 题找 pop rdi 等)',
    usage: 'ROPgadget --binary ./vuln | grep "pop rdi"',
    timeout: 120,
  },
  {
    name: 'pwn', kind: 'binary', command: 'pwn', source: 'builtin',
    purpose: 'pwntools 工具箱(checksec 查保护/模板生成);Python 库用法:python3 -c "from pwn import *; ..."',
    usage: 'pwn checksec ./vuln',
    timeout: 60,
  },
]

/** 各注册表文件最近一次成功解析出的蒸馏条目快照。
 *  蒸馏改写 registry.json 不是原子操作,运行中的 pentool 调用可能读到半截 JSON——
 *  此时回退到最近一次成功快照,自定义工具不瞬断(2026-08-15 复盘) */
const lastGoodCustomByFile = new Map<string, PenToolEntry[]>()

/** 加载合并后的注册表:内置 + 蒸馏(自定义注册表损坏/冲突的条目跳过) */
export async function loadRegistry(customFile: string = CUSTOM_REGISTRY): Promise<PenToolEntry[]> {
  const registry = [...BUILTIN_PENTOOLS]
  let raw: string
  try {
    raw = await fs.readFile(customFile, 'utf-8')
  } catch {
    return registry // 文件不存在 = 还没有蒸馏工具
  }
  let custom: unknown
  try { custom = JSON.parse(raw) } catch { custom = undefined }
  if (!Array.isArray(custom)) {
    const cached = lastGoodCustomByFile.get(customFile)
    return cached ? [...registry, ...cached] : registry
  }

  const customs: PenToolEntry[] = []
  for (const item of custom as Partial<PenToolEntry>[]) {
    const valid = item && typeof item.name === 'string' && typeof item.command === 'string'
      && (item.kind === 'binary' || item.kind === 'script')
      && typeof item.purpose === 'string' && typeof item.usage === 'string'
    if (!valid) continue
    if (registry.some(e => e.name === item.name)) continue // 不允许覆盖已有条目
    customs.push({
      name: item.name!, kind: item.kind!, command: item.command!, source: 'distilled',
      purpose: item.purpose!, usage: item.usage!,
      timeout: typeof item.timeout === 'number' ? item.timeout : 120,
    })
  }
  lastGoodCustomByFile.set(customFile, customs)
  return [...registry, ...customs]
}

// ===== 工具增删(工具集页面用) =====

const NAME_RE = /^[a-zA-Z][\w-]{0,63}$/

async function readCustomRegistry(): Promise<PenToolEntry[]> {
  try {
    const raw = JSON.parse(await fs.readFile(CUSTOM_REGISTRY, 'utf-8'))
    return Array.isArray(raw) ? raw : []
  } catch {
    return []
  }
}

async function writeCustomRegistry(entries: PenToolEntry[]): Promise<void> {
  await fs.mkdir(CUSTOM_DIR, { recursive: true })
  const tmp = `${CUSTOM_REGISTRY}.tmp`
  await fs.writeFile(tmp, JSON.stringify(entries, null, 2) + '\n', 'utf-8')
  await fs.rename(tmp, CUSTOM_REGISTRY)
}

/** 注册一个自定义工具(脚本内容 + 注册表条目);名称冲突/非法报错 */
export async function addCustomTool(
  entry: { name: string; purpose: string; usage: string; timeout?: number },
  scriptContent: string,
): Promise<void> {
  if (!NAME_RE.test(entry.name)) throw new Error('工具名非法(字母开头的字母数字下划线)')
  if (!entry.purpose?.trim() || !entry.usage?.trim()) throw new Error('用途与用法必填')
  const registry = await loadRegistry()
  if (registry.some(e => e.name === entry.name)) throw new Error(`工具已存在: ${entry.name}`)

  const rel = `pentools/custom/${entry.name}.py`
  await fs.mkdir(CUSTOM_DIR, { recursive: true })
  await fs.writeFile(path.join(PROJECT_ROOT, rel), scriptContent, 'utf-8')
  const custom = await readCustomRegistry()
  custom.push({
    name: entry.name, kind: 'script', command: rel, source: 'distilled',
    purpose: entry.purpose.trim(), usage: entry.usage.trim(),
    timeout: entry.timeout ?? 120,
  })
  await writeCustomRegistry(custom)
}

/** 删除自定义工具(仅 distilled;内置工具拒绝) */
export async function removeCustomTool(name: string): Promise<boolean> {
  if (BUILTIN_PENTOOLS.some(e => e.name === name)) throw new Error('内置工具不可删除')
  const custom = await readCustomRegistry()
  const entry = custom.find(e => e.name === name)
  if (!entry) return false
  await writeCustomRegistry(custom.filter(e => e.name !== name))
  if (entry.kind === 'script') {
    await fs.rm(path.join(PROJECT_ROOT, entry.command), { force: true })
  }
  return true
}

async function which(bin: string): Promise<boolean> {
  try { await execAsync(`which ${bin}`); return true } catch { return false }
}

/** 注册表摘要,注入系统提示词用 */
export async function registryStatusLine(registry?: PenToolEntry[]): Promise<string> {
  const reg = registry ?? await loadRegistry()
  const lines: string[] = []
  for (const e of reg) {
    const avail = e.kind === 'script' ? true : await which(e.command)
    const tag = e.source === 'distilled' ? '自定义' : (avail ? '可用' : '未安装')
    lines.push(`- ${e.name}(${tag}):${e.purpose}。用法示例: ${e.usage}`)
  }
  return lines.join('\n')
}

/** 构造 pentool 工具(loadFn 可注入,便于测试) */
export function createPenTool(loadFn: typeof loadRegistry = loadRegistry): AgentTool {
  return {
    name: 'pentool',
    description:
      '调用注册表中的渗透工具(开源内置 + 蒸馏沉淀的自定义工具)。' +
      '参数:tool(工具名)、args(命令行参数字符串)、timeout(可选,秒)。' +
      '不知道有什么工具时,先随便调一下看报错里列出的注册表。',
    parameters: {
      type: 'object',
      properties: {
        tool: { type: 'string', description: '注册表中的工具名' },
        args: { type: 'string', description: '传给工具的命令行参数' },
        timeout: { type: 'number', description: '超时秒数,默认按工具配置,最大 600' },
      },
      required: ['tool', 'args'],
    },
    execute: async (args) => {
      const { tool, args: toolArgs, timeout } = args as { tool: string; args?: string; timeout?: number }
      const registry = await loadFn()
      const entry = registry.find(e => e.name === tool)
      if (!entry) {
        return `error: 注册表中没有工具 "${tool}"。当前注册表:\n${registry.map(e => `- ${e.name}: ${e.purpose}`).join('\n')}`
      }
      if (entry.kind === 'binary' && !(await which(entry.command))) {
        return `error: ${tool} 未安装(Docker 镜像内置该工具,本地 dev 环境可用 docker 运行或自行安装)。可换注册表其他工具,或用 run_bash 手工实现。`
      }
      const cmd = entry.kind === 'binary'
        ? `${entry.command} ${toolArgs ?? ''}`
        : `python3 ${path.isAbsolute(entry.command) ? entry.command : path.join(PROJECT_ROOT, entry.command)} ${toolArgs ?? ''}`
      const timeoutMs = Math.min(600, Math.max(1, timeout ?? entry.timeout)) * 1000
      try {
        const { stdout, stderr } = await execAsync(cmd, { maxBuffer: 4 * 1024 * 1024, timeout: timeoutMs })
        const output = stderr ? `[stderr] ${stderr}\n[stdout] ${stdout}` : stdout
        return await truncateOutput(output || '(no output)')
      } catch (e: unknown) {
        const err = e as NodeJS.ErrnoException & { code?: number | string; stdout?: string; stderr?: string }
        return `[exit ${err.code}] ${err.stderr ?? ''}${err.stdout ?? ''}`
      }
    },
  }
}

// src/state.ts
// ReAct 状态库 —— 安全 agent 的持久化记忆（二次开发新增）。
//
// 文件布局（一次运行一个 runs/<ts>/ 目录）：
//   state.json        运行级快照(原子写):总分、跨题经验、各题状态汇总。
//                     每轮开始前注入 context —— 对模型来说,读一份紧凑 JSON 最高效。
//   rounds-<code>.jsonl  每题一个轮次记录文件(一个题目一个库,并行 worker 互不干扰)。
//   alerts.jsonl      停滞/放弃告警记录 —— 抛给人类的信号。
//
// 写路径只有一条:工具(journal / benchmark_api)→ StateStore → 落盘。
// 模型不直接写文件,保证状态结构不被自由文本污染。
// 并行说明:多个 worker 共享同一 StateStore;计数变更都是对共享对象的同步修改,
// save() 全量快照写盘,JS 单线程下无丢失更新。

import { promises as fs } from 'node:fs'
import * as path from 'node:path'

/** 一轮 ReAct 循环的结构化记录 —— 由 journal 工具在每轮结束时写入 */
export type RoundRecord = {
  round: number
  ts: string
  challenge: string
  /** Reason：本轮推理——观察到什么、据此怎么判断 */
  thought: string
  /** 当前假设（怀疑的漏洞类型 / 入口点） */
  hypothesis: string
  /** Act：本轮关键动作（打了什么 payload / 访问了什么端点） */
  actions: string[]
  /** Observe：服务器 / 工具的关键返回 */
  observation: string
  /** 本轮是否有实质进展（新端点 / 新凭证 / 新漏洞迹象 / 新 flag / 新立足点） */
  progress: boolean
  /** 有进展时的具体发现，会沉淀进快照的 findings 列表（跨 compaction 存活） */
  finding?: string
  /** 新建立的访问能力（webshell URL / 凭证 / 会话），沉淀进快照的 access 列表（跨 compaction 存活） */
  access?: string
  /** 新发现的内网主机/服务，沉淀进快照的 internal_hosts 列表（跨 compaction 存活） */
  internal_hosts?: string
  /** 可跨题复用的经验（某类 payload 有效 / 某 WAF 特征），进入全局 lessons */
  lesson?: string
  /** 下一步计划 */
  next_plan: string
}

export type ChallengeState = {
  code: string
  status: 'active' | 'solved' | 'abandoned'
  addr: string[]
  description?: string
  flags_found: number
  flags_total: number
  score: number
  rounds: number
  /** 连续无进展轮数 —— 停滞告警的依据 */
  no_progress: number
  findings: string[]
  /** 战果簿：已建立的访问能力（webshell/凭证/会话）。多阶段题的链条状态，每轮注入快照 */
  access: string[]
  /** 已发现的内网主机/服务拓扑，每轮注入快照 */
  internal_hosts: string[]
  /** 已兑换的 hint 文本（缓存，防止 compaction 后重复兑换重复扣分） */
  hint?: string
}

export type AlertRecord = {
  ts: string
  challenge: string
  kind: 'stalled' | 'abandoned' | 'error'
  message: string
  rounds: number
}

export type AgentState = {
  started_at: string
  /** ISO 截止时间，null 表示不限时 */
  deadline: string | null
  /** 运行归属的项目(target 模式时为靶场项目) */
  project?: { id: string; name: string; type: string }
  total_score: number
  /** 全局轮次计数（跨题递增） */
  round: number
  /** 跨题可复用经验，每轮注入 */
  lessons: string[]
  challenges: Record<string, ChallengeState>
}

export class StateStore {
  private constructor(
    readonly dir: string,
    readonly state: AgentState,
  ) {}

  /** 创建一次新运行的状态库：runs/<timestamp>/ */
  static async create(root = 'runs'): Promise<StateStore> {
    const dir = path.join(root, new Date().toISOString().replace(/[:.]/g, '-'))
    await fs.mkdir(dir, { recursive: true })
    const store = new StateStore(dir, {
      started_at: new Date().toISOString(),
      deadline: null,
      total_score: 0,
      round: 0,
      lessons: [],
      challenges: {},
    })
    await store.save()
    return store
  }

  /** 每题独立的轮次记录文件(文件名安全化) */
  private roundsFile(code: string) {
    return path.join(this.dir, `rounds-${code.replace(/[^\w.-]/g, '_')}.jsonl`)
  }

  private get alertsFile() { return path.join(this.dir, 'alerts.jsonl') }

  /** 原子写 state.json（tmp + rename，崩溃不留半个文件） */
  private async save(): Promise<void> {
    const tmp = path.join(this.dir, 'state.json.tmp')
    await fs.writeFile(tmp, JSON.stringify(this.state, null, 2), 'utf-8')
    await fs.rename(tmp, path.join(this.dir, 'state.json'))
  }

  setDeadline(deadline: Date | null): Promise<void> {
    this.state.deadline = deadline ? deadline.toISOString() : null
    return this.save()
  }

  setProject(project: { id: string; name: string; type: string }): Promise<void> {
    this.state.project = project
    return this.save()
  }

  startChallenge(code: string, addr: string[], flagsTotal: number, description?: string): Promise<void> {
    this.state.challenges[code] = {
      code, status: 'active', addr, description,
      flags_found: 0, flags_total: flagsTotal, score: 0,
      rounds: 0, no_progress: 0, findings: [], access: [], internal_hosts: [],
    }
    return this.save()
  }

  /** 环境地址刷新：容器重建后 IP 会变，runner 每轮从平台 list 同步 */
  updateAddr(code: string, addr: string[]): Promise<void> {
    const ch = this.state.challenges[code]
    if (ch) ch.addr = addr
    return this.save()
  }

  /** 缓存已兑换的 hint（compaction 后模型不记得换过，重复兑换会重复扣分） */
  setHint(code: string, hint: string): Promise<void> {
    const ch = this.state.challenges[code]
    if (ch) ch.hint = hint
    return this.save()
  }

  /** 再次尝试(多 pass 调度):保留 findings/hint(题目知识仍然有效),
   *  清空 access/internal_hosts(旧容器已销毁,shell/拓扑失效),
   *  按平台记录恢复 flags_found;rounds 总数跨 attempt 累计保留 */
  async reactivateChallenge(code: string, addr: string[], flagsFound: number, flagsTotal: number): Promise<void> {
    const ch = this.state.challenges[code]
    if (!ch) return this.startChallenge(code, addr, flagsTotal)
    ch.status = 'active'
    ch.addr = addr
    ch.flags_found = flagsFound
    ch.flags_total = flagsTotal
    ch.no_progress = 0
    ch.access = []
    ch.internal_hosts = []
    await this.save()
  }

  /** journal 工具调用:向指定题目追加一轮记录并更新快照计数 */
  async appendRound(code: string, rec: Omit<RoundRecord, 'round' | 'ts' | 'challenge'>): Promise<number> {
    const ch = this.state.challenges[code]
    if (!ch) throw new Error(`challenge not active: ${code}`)
    this.state.round += 1
    ch.rounds += 1
    ch.no_progress = rec.progress ? 0 : ch.no_progress + 1
    if (rec.finding && !ch.findings.includes(rec.finding)) ch.findings.push(rec.finding)
    if (rec.access && !ch.access.includes(rec.access)) ch.access.push(rec.access)
    if (rec.internal_hosts && !ch.internal_hosts.includes(rec.internal_hosts)) ch.internal_hosts.push(rec.internal_hosts)
    if (rec.lesson && !this.state.lessons.includes(rec.lesson)) this.state.lessons.push(rec.lesson)

    const full: RoundRecord = {
      round: this.state.round, ts: new Date().toISOString(), challenge: code, ...rec,
    }
    await fs.appendFile(this.roundsFile(code), JSON.stringify(full) + '\n', 'utf-8')
    await this.save()
    return this.state.round
  }

  /** benchmark_api submit 正确时调用 */
  async recordFlag(code: string, awarded: number, flagsFound: number, flagsTotal: number): Promise<void> {
    const ch = this.state.challenges[code]
    if (!ch) return
    ch.flags_found = flagsFound
    ch.flags_total = flagsTotal
    ch.score += awarded
    ch.no_progress = 0
    this.state.total_score += awarded
    if (flagsFound >= flagsTotal) ch.status = 'solved'
    await this.save()
  }

  async finishChallenge(code: string, status: 'solved' | 'abandoned'): Promise<void> {
    const ch = this.state.challenges[code]
    if (ch) ch.status = status
    await this.save()
  }

  async appendAlert(alert: Omit<AlertRecord, 'ts'>): Promise<void> {
    await fs.appendFile(this.alertsFile, JSON.stringify({ ts: new Date().toISOString(), ...alert }) + '\n', 'utf-8')
  }

  /** 剩余毫秒，无 deadline 返回 null */
  timeLeft(): number | null {
    if (!this.state.deadline) return null
    return new Date(this.state.deadline).getTime() - Date.now()
  }
}

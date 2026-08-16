// src/state.test.ts
// 调度优化(2026-08-16)新增状态字段的守卫测试:
// attempts/busy_ms/submit_streak/next_plan 的生命周期是熔断与重试退避的正确性基础。
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { promises as fs } from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { StateStore } from './state.js'

let store: StateStore
let root: string

beforeEach(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), 'statestore-test-'))
  store = await StateStore.create(root)
})

afterEach(async () => {
  await fs.rm(root, { recursive: true, force: true })
})

describe('调度状态字段', () => {
  it('startChallenge 初始化调度字段', async () => {
    await store.startChallenge('c-1', ['10.0.0.1:80'], 1)
    const ch = store.state.challenges['c-1']
    expect(ch.attempts).toBe(1)
    expect(ch.busy_ms).toBe(0)
    expect(ch.submit_streak).toBe(0)
  })

  it('reactivateChallenge 保留知识与累计占用,递增 attempts 并清零熔断计数', async () => {
    await store.startChallenge('c-1', ['10.0.0.1:80'], 2)
    await store.appendRound('c-1', {
      thought: 't', hypothesis: 'h', actions: [], observation: 'o',
      progress: true, finding: 'f1', next_plan: 'plan-a',
    })
    await store.recordSubmitFail('c-1')
    await store.addBusyMs('c-1', 60_000)
    await store.setHint('c-1', 'hint-text')

    await store.reactivateChallenge('c-1', ['10.0.0.2:80'], 1, 2)
    const ch = store.state.challenges['c-1']
    expect(ch.attempts).toBe(2)                 // 递增
    expect(ch.busy_ms).toBe(60_000)             // 累计保留(退避依据)
    expect(ch.submit_streak).toBe(0)            // 新环境重新计数
    expect(ch.next_plan).toBe('plan-a')         // 传承:计划不丢
    expect(ch.findings).toEqual(['f1'])         // 传承:发现不丢
    expect(ch.hint).toBe('hint-text')           // 传承:hint 缓存不丢
    expect(ch.access).toEqual([])               // 旧容器战果清空
    expect(ch.flags_found).toBe(1)              // 平台进度恢复
  })

  it('submit_streak: 失败累加,成功(recordFlag)清零', async () => {
    await store.startChallenge('c-1', ['10.0.0.1:80'], 1)
    expect(await store.recordSubmitFail('c-1')).toBe(1)
    expect(await store.recordSubmitFail('c-1')).toBe(2)
    await store.recordFlag('c-1', 100, 1, 1)
    expect(store.state.challenges['c-1'].submit_streak).toBe(0)
    expect(store.state.challenges['c-1'].status).toBe('solved')
  })

  it('next_plan 随 journal 更新', async () => {
    await store.startChallenge('c-1', ['10.0.0.1:80'], 1)
    await store.appendRound('c-1', {
      thought: '', hypothesis: '', actions: [], observation: '',
      progress: false, next_plan: '换攻击面',
    })
    expect(store.state.challenges['c-1'].next_plan).toBe('换攻击面')
  })
})

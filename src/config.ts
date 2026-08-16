// src/config.ts
// 统一配置(二次开发新增):config.json 为主,环境变量兜底。
//
// 取值优先级:config.json > process.env > 默认值。
// Web UI 设置页读写 config.json;Docker/CI 场景仍可纯环境变量运行。

import { promises as fs } from 'node:fs'
import * as path from 'node:path'
import { PROJECT_ROOT } from './pentools.js'

export const CONFIG_FILE = path.join(PROJECT_ROOT, 'config.json')

export type ConfigField = {
  key: string
  label: string
  secret?: boolean
  placeholder?: string
}

/** 受管配置项(Web UI 设置页按此渲染表单) */
export const CONFIG_FIELDS: ConfigField[] = [
  { key: 'NANOPI_API_KEY', label: 'LLM API Key', secret: true, placeholder: 'sk-...' },
  { key: 'NANOPI_BASE_URL', label: 'LLM Base URL', placeholder: 'https://api.deepseek.com' },
  { key: 'NANOPI_MODEL', label: '模型', placeholder: 'deepseek-v4-flash(练习)/ deepseek-v4-pro(比赛)' },
  { key: 'NANOPI_THINKING', label: '思考模式', placeholder: 'enabled(默认)/ disabled / adaptive' },
  { key: 'NANOPI_REASONING_EFFORT', label: '推理强度', placeholder: 'low / high(默认)/ max' },
  { key: 'NANOPI_MAX_TOKENS', label: '单轮输出上限', placeholder: '16384(思考模式别低于 8192)' },
  { key: 'BENCHMARK_TOKEN', label: 'Benchmark Token', secret: true, placeholder: '平台下发的 UUID' },
  { key: 'BENCHMARK_BASE_URL', label: 'Benchmark Base URL', placeholder: 'https://tsecbench.zc.tencent.com' },
  { key: 'TASK_MINUTES', label: '跑分时限(分钟)', placeholder: '360' },
  { key: 'MAX_CONCURRENT', label: '并行 worker 数', placeholder: '3(对齐平台容器上限)' },
  { key: 'STALL_ROUNDS', label: '停滞告警轮数', placeholder: '6' },
  { key: 'MAX_ROUNDS', label: '单题轮数上限', placeholder: '30' },
  { key: 'TURN_TIMEOUT_SEC', label: '单轮硬超时(秒)', placeholder: '480' },
  { key: 'TASK_CAP_SINGLE_MIN', label: '单 flag 题时限(分钟)', placeholder: '35' },
  { key: 'TASK_CAP_PER_FLAG_MIN', label: '多 flag 题每 flag 预算(分钟)', placeholder: '20' },
  { key: 'RETRY_BUSY_CAP_MIN', label: '单题累计占用上限(分钟)', placeholder: '60(激进省 token 用 40)' },
  { key: 'MAX_ATTEMPTS', label: '单题最大尝试次数', placeholder: '2' },
  { key: 'ENDGAME_MIN', label: '末段窗口(分钟)', placeholder: '75' },
  { key: 'SUBMIT_BREAKER_FAILS', label: '提交熔断连错阈值', placeholder: '3' },
  { key: 'SUBMIT_ABANDON_FAILS', label: '熔断重启后放弃阈值', placeholder: '6' },
  { key: 'ALERT_MODE', label: '告警模式(CLI)', placeholder: 'auto / wait' },
  { key: 'ALERT_TIMEOUT_SEC', label: '告警等待(秒)', placeholder: '120' },
  { key: 'VPN_CHECK', label: 'VPN 预检地址', placeholder: 'http://10.0.100.58(off 跳过)' },
]

export type ConfigValues = Record<string, string>

/** 读 config.json(只接受受管 key、非空字符串);文件不存在/损坏返回 {} */
export async function readConfigFile(file: string = CONFIG_FILE): Promise<ConfigValues> {
  try {
    const raw = JSON.parse(await fs.readFile(file, 'utf-8')) as Record<string, unknown>
    const out: ConfigValues = {}
    for (const f of CONFIG_FIELDS) {
      const v = raw[f.key]
      if (typeof v === 'string' && v.trim() !== '') out[f.key] = v.trim()
    }
    return out
  } catch {
    return {}
  }
}

/** 写 config.json(原子写;只写受管 key 的非空值,空值等于删除该项) */
export async function writeConfigFile(values: ConfigValues, file: string = CONFIG_FILE): Promise<void> {
  const out: ConfigValues = {}
  for (const f of CONFIG_FIELDS) {
    const v = (values[f.key] ?? '').trim()
    if (v) out[f.key] = v
  }
  const tmp = `${file}.tmp`
  await fs.writeFile(tmp, JSON.stringify(out, null, 2) + '\n', 'utf-8')
  await fs.rename(tmp, file)
}

/** 单项取值:config.json 优先,process.env 兜底。
 *  统一 trim:平台表单粘贴的值常带尾部空格——2026-08-16 正赛第一轮 NANOPI_THINKING
 *  被填成 'enabled ',API 反序列化 400,全场 LLM 调用全灭(练有此坑,赛后加固) */
export function configValue(key: string, fileValues: ConfigValues, fallback?: string): string | undefined {
  const v = fileValues[key] ?? process.env[key]
  if (v === undefined) return fallback
  const t = v.trim()
  return t !== '' ? t : fallback
}

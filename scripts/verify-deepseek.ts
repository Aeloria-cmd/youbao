// scripts/verify-deepseek.ts
// DeepSeek 接入一键体检(真实 API,练习日前必跑):
//   1. 工具调用闭环(模型调 echo 工具并读回结果)
//   2. 多轮引用(第二轮追问第一轮结果——exercising reasoning_content 回传,防思考模式 400)
//   3. usage 统计(成本计量链路)
// 运行:NANOPI_API_KEY=... npx tsx scripts/verify-deepseek.ts
import { runAgent, type AgentTool } from '../src/agent.js'
import type { Model, Context } from '../src/llm.js'

const model: Model = {
  apiKey: process.env.NANOPI_API_KEY ?? '',
  model: process.env.NANOPI_MODEL ?? 'deepseek-v4-flash',
  baseUrl: process.env.NANOPI_BASE_URL ?? 'https://api.deepseek.com',
  maxTokens: 2048,
  includeUsage: true,
}
if (!model.apiKey) { console.error('请设置 NANOPI_API_KEY'); process.exit(1) }

const MAGIC = 'MAGIC_7429'
const echo: AgentTool = {
  name: 'echo',
  description: '原样返回输入文本。参数:text(字符串)',
  parameters: {
    type: 'object',
    properties: { text: { type: 'string', description: '要返回的文本' } },
    required: ['text'],
  },
  execute: async (args) => `ECHO: ${(args as { text: string }).text}`,
}

let failed = false
let totalTokens = 0
const seenTexts: string[] = []

async function turn(context: Context, prompt: string) {
  context.messages.push({ role: 'user', content: prompt })
  let text = ''
  for await (const ev of runAgent(model, context, [echo])) {
    if (ev.type === 'assistant_text') { text += ev.delta; process.stdout.write(ev.delta) }
    else if (ev.type === 'tool_call') console.log(`\n  [tool] ${ev.name} ${JSON.stringify(ev.args)}`)
    else if (ev.type === 'tool_result') console.log(`  [result] ${ev.result}`)
    else if (ev.type === 'usage') totalTokens += ev.usage.total_tokens ?? 0
    else if (ev.type === 'turn_end' && (ev.stopReason === 'error' || ev.stopReason === 'aborted')) failed = true
  }
  console.log()
  seenTexts.push(text)
}

const context: Context = {
  systemPrompt: '你是测试助手。用户要求调用工具时必须调用,不要自己编造结果。',
  messages: [],
}

console.log('=== Turn 1: 工具调用闭环 ===')
await turn(context, `请调用 echo 工具,text 填 ${MAGIC},然后把工具的返回原样告诉我`)

console.log('=== Turn 2: 多轮引用(reasoning_content 回传) ===')
await turn(context, '第一轮工具返回的完整字符串是什么?原样复述,不要改动任何字符')

const t1ok = seenTexts[0].includes(MAGIC)
const t2ok = seenTexts[1].includes(MAGIC)
console.log('---')
console.log(`Turn1 含 ${MAGIC}: ${t1ok ? 'OK' : 'FAIL'}`)
console.log(`Turn2 含 ${MAGIC}: ${t2ok ? 'OK' : 'FAIL'}`)
console.log(`usage 统计: ${totalTokens} tokens ${totalTokens > 0 ? 'OK' : 'FAIL(未收到 usage)'}`)
console.log(`运行错误: ${failed ? 'FAIL' : 'OK'}`)

if (t1ok && t2ok && totalTokens > 0 && !failed) {
  console.log('\n✅ PASS — DeepSeek 接入全链路正常')
} else {
  console.error('\n❌ FAIL — 见上方各项')
  process.exit(1)
}

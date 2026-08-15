// src/llm.ts
// 统一 LLM API —— 把 OpenAI Completions SSE 响应解析成四种事件流。
// 教学版只支持 OpenAI 兼容格式（GLM、DeepSeek、Ollama 等均兼容）。

// ===== 类型 =====

/** 模型配置 */
export type Model = {
  apiKey: string
  model: string          // 如 "deepseek-v4-pro" 或 "deepseek-v4-flash"
  baseUrl?: string       // 默认 https://api.deepseek.com
  maxTokens?: number     // 不设则由 API 决定默认值（cli.ts 设为 4096）
  includeUsage?: boolean // 请求流式 usage 统计（成本计量，runner 开启）
  /** DeepSeek 思考模式开关;不设则用服务商默认(v4 默认开启) */
  thinking?: 'enabled' | 'disabled'
  /** 推理强度:low / high(默认)/ max */
  reasoningEffort?: 'low' | 'high' | 'max'
}

/**
 * content block：消息内容的结构化单元。
 * 注意：tool_result 放在 ContentBlock 里再塞进 user message，
 * pi 里它是独立的 ToolResultMessage 类型，nanopi 简化为统一结构。
 * reasoning：DeepSeek 思考模式的推理内容——API 要求多轮时回传，否则 400。
 */
export type ContentBlock =
  | { type: 'text'; text: string }
  | { type: 'reasoning'; text: string }
  | { type: 'tool_use'; id: string; name: string; input: unknown }
  | { type: 'tool_result'; tool_use_id: string; content: string }

/** 消息：user / assistant 共用同一结构 */
export type Message = {
  role: 'user' | 'assistant'
  content: string | ContentBlock[]
}

/** Context：纯 JSON，可 stringify 落盘 */
export type Context = {
  systemPrompt?: string
  messages: Message[]
}

/** token 用量（includeUsage 开启后由流末 chunk 携带） */
export type Usage = {
  prompt_tokens?: number
  completion_tokens?: number
  total_tokens?: number
}

/** 流事件：llm 模块对外的统一输出 */
export type StreamEvent =
  | { type: 'text_delta'; delta: string }
  | { type: 'reasoning_delta'; delta: string }
  | { type: 'tool_call'; id: string; name: string; args: unknown }
  | { type: 'usage'; usage: Usage }
  | { type: 'done'; stopReason: 'end_turn' | 'tool_use' | 'max_tokens' | 'aborted' }
  | { type: 'error'; error: Error }

/** agent 模块传入的 tool 定义格式 */
export type ToolDef = {
  name: string
  description: string
  parameters: object
}

// ===== 辅助函数 =====

/**
 * 把 nanopi Context 转成 OpenAI messages 格式。
 * 纯转换函数，不含网络逻辑。
 */
export function contextToOpenAIMessages(context: Context): object[] {
  const messages: object[] = []
  if (context.systemPrompt) messages.push({ role: 'system', content: context.systemPrompt })

  for (const msg of context.messages) {
    if (typeof msg.content === 'string') {
      messages.push({ role: msg.role, content: msg.content })
      continue
    }

    const blocks = msg.content
    if (msg.role === 'assistant') {
      const toolCalls: object[] = []
      let text = ''
      let reasoning = ''
      for (const b of blocks) {
        if (b.type === 'text') text += b.text
        else if (b.type === 'reasoning') reasoning += b.text
        else if (b.type === 'tool_use') {
          toolCalls.push({ id: b.id, type: 'function', function: { name: b.name, arguments: JSON.stringify(b.input) } })
        }
      }
      // OpenAI 要求 assistant 消息必须有 content（非 null）或 tool_calls。
      // 纯 tool_call 时 content 为 null；两者皆空（如 abort/error 后的无内容轮次）用空串占位，避免 API 400。
      const content = text || (toolCalls.length ? null : '')
      const assistantMsg: Record<string, unknown> = { role: 'assistant', content, tool_calls: toolCalls.length ? toolCalls : undefined }
      // DeepSeek 思考模式:带 tool_calls 的轮次必须回传 reasoning_content(否则下一轮 400);
      // 无工具调用的纯文本轮回传也会被官方忽略——剥掉省 token
      if (reasoning && toolCalls.length) assistantMsg.reasoning_content = reasoning
      messages.push(assistantMsg)
    } else {
      // user message 里的 tool_result block → OpenAI 要求独立的 role:tool 消息
      for (const b of blocks) {
        if (b.type === 'tool_result') {
          messages.push({ role: 'tool', tool_call_id: b.tool_use_id, content: b.content })
        } else if (b.type === 'text') {
          messages.push({ role: 'user', content: b.text })
        }
      }
    }
  }
  return messages
}

/** OpenAI SSE chunk 的最小类型(含 DeepSeek 思考模式扩展字段) */
type OpenAIChunk = {
  choices: Array<{
    delta?: {
      content?: string
      reasoning_content?: string
      tool_calls?: Array<{ index?: number; id?: string; function?: { name?: string; arguments?: string } }>
    }
    finish_reason?: string
  }>
  usage?: Usage
}

/** 解析一行 SSE data，累积 tool_call，返回 text/reasoning delta 和 stop_reason */
function handleSSELine(
  data: string,
  toolCallBuffers: Map<number, { id: string; name: string; argsBuf: string }>,
): { textDelta: string | null; reasoningDelta: string | null; stopReason: 'end_turn' | 'tool_use' | 'max_tokens' | null; usage: Usage | null } {
  let chunk: OpenAIChunk
  try { chunk = JSON.parse(data) as OpenAIChunk } catch { return { textDelta: null, reasoningDelta: null, stopReason: null, usage: null } }

  // usage chunk（choices 为空、只带 usage）—— includeUsage 开启后流末出现
  if (chunk.usage) return { textDelta: null, reasoningDelta: null, stopReason: null, usage: chunk.usage }

  const choice = chunk.choices[0]
  if (!choice) return { textDelta: null, reasoningDelta: null, stopReason: null, usage: null }

  let textDelta: string | null = null
  let reasoningDelta: string | null = null
  let stopReason: 'end_turn' | 'tool_use' | 'max_tokens' | null = null

  if (choice.delta?.content) textDelta = choice.delta.content
  if (choice.delta?.reasoning_content) reasoningDelta = choice.delta.reasoning_content

  // tool_call 增量：按 index 累积 name + arguments 的 partial JSON
  if (choice.delta?.tool_calls) {
    for (const tc of choice.delta.tool_calls) {
      const idx = tc.index ?? 0
      if (!toolCallBuffers.has(idx)) {
        toolCallBuffers.set(idx, { id: tc.id ?? `call_${idx}`, name: '', argsBuf: '' })
      }
      const entry = toolCallBuffers.get(idx)!
      if (tc.id) entry.id = tc.id
      if (tc.function?.name) entry.name = tc.function.name
      if (tc.function?.arguments) entry.argsBuf += tc.function.arguments
    }
  }

  // finish_reason 映射：tool_calls → tool_use，length → max_tokens，stop → end_turn（默认值）
  if (choice.finish_reason === 'tool_calls') stopReason = 'tool_use'
  else if (choice.finish_reason === 'length') stopReason = 'max_tokens'

  return { textDelta, reasoningDelta, stopReason, usage: null }
}

/** 流结束：把累积的 tool_calls 按顺序发出 */
function flushToolCalls(
  toolCallBuffers: Map<number, { id: string; name: string; argsBuf: string }>,
): { id: string; name: string; args: unknown }[] {
  const calls: { id: string; name: string; args: unknown }[] = []
  for (const [, tc] of [...toolCallBuffers].sort((a, b) => a[0] - b[0])) {
    let args: unknown = {}
    if (tc.argsBuf) {
      try { args = JSON.parse(tc.argsBuf) } catch { args = {} }
    }
    calls.push({ id: tc.id, name: tc.name, args })
  }
  return calls
}

// ===== stream 函数 =====

/**
 * 调用 OpenAI Completions API（streaming），返回统一事件流。
 *
 * @param model    模型配置
 * @param context  对话上下文
 * @param opts     tools + abort signal
 */
export async function* stream(
  model: Model,
  context: Context,
  opts: { tools?: ToolDef[]; signal?: AbortSignal } = {},
): AsyncGenerator<StreamEvent> {
  const url = `${model.baseUrl ?? 'https://api.openai.com/v1'}/chat/completions`
  const messages = contextToOpenAIMessages(context)

  const body: Record<string, unknown> = { model: model.model, stream: true, messages }
  if (model.maxTokens) body.max_tokens = model.maxTokens
  if (model.includeUsage) body.stream_options = { include_usage: true }
  if (model.thinking) body.thinking = { type: model.thinking }
  if (model.reasoningEffort) body.reasoning_effort = model.reasoningEffort
  if (opts.tools?.length) {
    body.tools = opts.tools.map(t => ({
      type: 'function',
      function: { name: t.name, description: t.description, parameters: t.parameters },
    }))
  }

  // 发请求（连接阶段失败重试：网络抖动 / 429 / 5xx，指数退避，最多 3 次。
  // 无人值守长跑必须扛住网关抖动；流式中途出错不重试，避免重复已产出的内容）
  const MAX_ATTEMPTS = 3
  let response: Response | null = null
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${model.apiKey}` },
        body: JSON.stringify(body),
        signal: opts.signal,
      })
      if (res.ok && res.body) { response = res; break }
      const text = await res.text().catch(() => 'unknown error')
      const retryable = res.status === 429 || res.status >= 500
      if (!retryable || attempt === MAX_ATTEMPTS) {
        yield { type: 'error', error: new Error(`API ${res.status}: ${text}`) }; return
      }
    } catch (e) {
      if (opts.signal?.aborted) { yield { type: 'done', stopReason: 'aborted' }; return }
      if (attempt === MAX_ATTEMPTS) { yield { type: 'error', error: e as Error }; return }
    }
    await new Promise(r => setTimeout(r, 1000 * attempt))
  }
  if (!response?.body) { yield { type: 'error', error: new Error('API request failed after retries') }; return }

  // 逐行解析 SSE
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buf = ''
  let stopReason: 'end_turn' | 'tool_use' | 'max_tokens' = 'end_turn'
  const toolCallBuffers = new Map<number, { id: string; name: string; argsBuf: string }>()

  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      buf += decoder.decode(value, { stream: true })

      let nl: number
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl).trim()
        buf = buf.slice(nl + 1)
        if (!line.startsWith('data: ')) continue
        const data = line.slice(6)
        if (data === '[DONE]') continue

        const result = handleSSELine(data, toolCallBuffers)
        if (result.textDelta) yield { type: 'text_delta', delta: result.textDelta }
        if (result.reasoningDelta) yield { type: 'reasoning_delta', delta: result.reasoningDelta }
        if (result.stopReason) stopReason = result.stopReason
        if (result.usage) yield { type: 'usage', usage: result.usage }
      }
    }
  } catch (e) {
    if (opts.signal?.aborted) { yield { type: 'done', stopReason: 'aborted' }; return }
    yield { type: 'error', error: e as Error }; return
  }

  // 发出累积的 tool_calls
  for (const tc of flushToolCalls(toolCallBuffers)) {
    yield { type: 'tool_call', id: tc.id, name: tc.name, args: tc.args }
  }
  yield { type: 'done', stopReason: opts.signal?.aborted ? 'aborted' : stopReason }
}

// ===== message 构建辅助函数 =====

/** 从一轮 stream 的事件中累积出 assistant message(reasoning 为思考模式推理内容,需随多轮回传) */
export function buildAssistantMessage(
  text: string,
  toolCalls: { id: string; name: string; args: unknown }[],
  reasoning?: string,
): Message {
  const content: ContentBlock[] = []
  if (reasoning) content.push({ type: 'reasoning', text: reasoning })
  if (text) content.push({ type: 'text', text })
  for (const tc of toolCalls) {
    content.push({ type: 'tool_use', id: tc.id, name: tc.name, input: tc.args })
  }
  return { role: 'assistant', content }
}

/** 构造 tool_result user message */
export function buildToolResultMessage(
  results: { tool_use_id: string; content: string }[],
): Message {
  return {
    role: 'user',
    content: results.map(r => ({
      type: 'tool_result' as const,
      tool_use_id: r.tool_use_id,
      content: r.content,
    })),
  }
}

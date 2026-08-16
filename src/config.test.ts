// src/config.test.ts
// configValue 的 env trim 回归测试(2026-08-16 正赛事故:平台表单粘贴的
// NANOPI_THINKING='enabled ' 带尾部空格,API 反序列化 400,全场 LLM 调用全灭)。
// 注:仓库的 test/ 目录按 .gitignore 约定本地保留不发布,入库的回归测试放 src/ 下。
import { describe, it, expect, afterEach } from 'vitest'
import { configValue } from './config.js'

afterEach(() => { delete process.env.TEST_CFG_KEY })

describe('configValue', () => {
  it('config.json > process.env > fallback', () => {
    process.env.TEST_CFG_KEY = 'from-env'
    expect(configValue('TEST_CFG_KEY', { TEST_CFG_KEY: 'from-file' })).toBe('from-file')
    expect(configValue('TEST_CFG_KEY', {})).toBe('from-env')
    expect(configValue('TEST_CFG_MISSING', {}, 'dft')).toBe('dft')
  })

  it('env 值 trim:尾部空格被去掉;纯空白回退默认值', () => {
    process.env.TEST_CFG_KEY = 'enabled '
    expect(configValue('TEST_CFG_KEY', {})).toBe('enabled')
    process.env.TEST_CFG_KEY = '   '
    expect(configValue('TEST_CFG_KEY', {}, 'dft')).toBe('dft')
  })
})

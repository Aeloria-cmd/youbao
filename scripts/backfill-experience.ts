// scripts/backfill-experience.ts
// 手工回填:把历史运行(rounds)提炼进经验层。
// 用法:npx tsx scripts/backfill-experience.ts runs/<目录名>
import { collectFromRun, renderForPrompt } from '../src/experience.js'

const runDir = process.argv[2]
if (!runDir) { console.error('用法: npx tsx scripts/backfill-experience.ts runs/<目录名>'); process.exit(1) }

const added = await collectFromRun(runDir)
console.log(`新增经验: ${added} 条`)
console.log('--- 当前经验层(top 8/方向) ---')
console.log(await renderForPrompt(8))

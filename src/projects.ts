// src/projects.ts
// 项目模型(二次开发新增)—— 一个项目 = 一次可独立启动的跑分/打靶任务。
//
// 两类项目:
//   benchmark —— 跑分项目,接 TSec Benchmark 平台(token 等在创建时配置,缺省回落 config.json)
//   target    —— 普通靶场项目,只需目标 URL + 题目描述,agent 单目标打靶,不走平台
//
// 持久化:projects.json(仓库根;token 属敏感信息——文件已加入 .gitignore/.dockerignore)

import { promises as fs } from 'node:fs'
import * as path from 'node:path'
import { PROJECT_ROOT } from './pentools.js'

export const PROJECTS_FILE = path.join(PROJECT_ROOT, 'projects.json')

export type ProjectType = 'benchmark' | 'target'

export type Project = {
  id: string
  name: string
  type: ProjectType
  /** benchmark: BENCHMARK_TOKEN / BENCHMARK_BASE_URL / TASK_MINUTES / MAX_CONCURRENT…
   *  target: url / description / creds */
  config: Record<string, string>
  created: string
}

export async function listProjects(file: string = PROJECTS_FILE): Promise<Project[]> {
  try {
    const raw = JSON.parse(await fs.readFile(file, 'utf-8'))
    return Array.isArray(raw) ? raw as Project[] : []
  } catch {
    return []
  }
}

async function saveProjects(projects: Project[], file: string = PROJECTS_FILE): Promise<void> {
  const tmp = `${file}.tmp`
  await fs.writeFile(tmp, JSON.stringify(projects, null, 2) + '\n', 'utf-8')
  await fs.rename(tmp, file)
}

export async function createProject(
  input: { name: string; type: ProjectType; config: Record<string, string> },
  file: string = PROJECTS_FILE,
): Promise<Project> {
  const name = input.name.trim()
  if (!name) throw new Error('项目名不能为空')
  if (input.type !== 'benchmark' && input.type !== 'target') throw new Error('type 仅支持 benchmark|target')
  if (input.type === 'target' && !(input.config.url ?? '').trim()) throw new Error('target 项目需要 url')

  const projects = await listProjects(file)
  if (projects.some(p => p.name === name)) throw new Error(`项目名已存在: ${name}`)
  const project: Project = {
    id: `p-${Date.now().toString(36)}`,
    name,
    type: input.type,
    config: input.config,
    created: new Date().toISOString(),
  }
  projects.push(project)
  await saveProjects(projects, file)
  return project
}

export async function deleteProject(id: string, file: string = PROJECTS_FILE): Promise<boolean> {
  const projects = await listProjects(file)
  const next = projects.filter(p => p.id !== id)
  if (next.length === projects.length) return false
  await saveProjects(next, file)
  return true
}

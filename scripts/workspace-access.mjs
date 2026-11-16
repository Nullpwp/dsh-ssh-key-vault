#!/usr/bin/env node
/**
 * 只读查询某个工作区被授权的主机，以及每台主机绑定的密钥文件路径。
 *
 * 数据来源：GET /ssh-key-vault/state（access.hostIds）。
 * 密钥路径按插件的数据目录约定拼接：<vaultDir>/keys/<keyId>-<filename>。
 *
 * 用法：node scripts/workspace-access.mjs [工作区名称|ID|路径] [--url URL] [--vault-dir DIR] [--json]
 */
import { existsSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const USAGE = `用法: dsh-ssh-targets [工作区名称|ID|路径] [选项]
       node scripts/workspace-access.mjs [工作区名称|ID|路径] [选项]

选项:
  --url <地址>        DSH Web 地址，默认 $DSH_WEB_URL 或 http://127.0.0.1:3080
  --vault-dir <目录>  密钥库数据目录，默认 $DSH_HOME/ssh-key-vault
  --json              输出 JSON
  -h, --help          显示本帮助

不传工作区时，按当前目录匹配工作区路径。`

function fail(message) {
  console.error(message)
  process.exit(1)
}

const opts = { url: '', vaultDir: '', json: false, workspace: '' }
const argv = process.argv.slice(2)
for (let i = 0; i < argv.length; i += 1) {
  const arg = argv[i]
  if (arg === '--json') {
    opts.json = true
  } else if (arg === '--url') {
    opts.url = argv[++i] ?? ''
  } else if (arg === '--vault-dir') {
    opts.vaultDir = argv[++i] ?? ''
  } else if (arg === '-h' || arg === '--help') {
    console.log(USAGE)
    process.exit(0)
  } else if (arg.startsWith('-')) {
    fail(`未知选项: ${arg}\n\n${USAGE}`)
  } else if (!opts.workspace) {
    opts.workspace = arg
  } else {
    fail(`多余参数: ${arg}\n\n${USAGE}`)
  }
}

const dshHome = process.env.DSH_HOME?.trim() || path.join(os.homedir(), '.dsh')
const vaultDir = path.resolve(opts.vaultDir || path.join(dshHome, 'ssh-key-vault'))
const keysDir = path.join(vaultDir, 'keys')
const baseUrl = opts.url || process.env.DSH_WEB_URL || 'http://127.0.0.1:3080'
const stateUrl = new URL('/ssh-key-vault/state', baseUrl)

let state
try {
  const response = await fetch(stateUrl, { signal: AbortSignal.timeout(5000) })
  if (!response.ok) fail(`请求失败: ${response.status} ${response.statusText} (${stateUrl})`)
  state = await response.json()
} catch (error) {
  fail(`无法读取密钥库状态 (${stateUrl}): ${error instanceof Error ? error.message : String(error)}`)
}
if (!state?.ok) fail(`密钥库返回错误: ${state?.error ?? 'unknown'} (${state?.code ?? 'no_code'})`)

const workspaces = Array.isArray(state.workspaces) ? state.workspaces : []
let workspace
if (opts.workspace) {
  workspace = workspaces.find(
    (item) => item.id === opts.workspace || item.title === opts.workspace || item.path === opts.workspace,
  )
  if (!workspace) {
    fail(`找不到工作区 "${opts.workspace}"。可用工作区:\n${workspaces.map((item) => `  - ${item.title}  (${item.id})`).join('\n')}`)
  }
} else {
  const cwd = path.resolve(process.cwd())
  workspace = workspaces
    .filter((item) => typeof item.path === 'string' && item.path && (cwd === item.path || cwd.startsWith(item.path + path.sep)))
    .sort((a, b) => b.path.length - a.path.length)[0]
  if (!workspace) {
    fail(`当前目录 ${cwd} 不属于任何已登记工作区，请显式传入工作区名称或 ID。\n可用工作区:\n${workspaces.map((item) => `  - ${item.title}  (${item.id})`).join('\n')}`)
  }
}

const access = state.access?.[workspace.id] ?? {}
const hostIds = Array.isArray(access.hostIds) ? access.hostIds : []
const keyById = new Map((Array.isArray(state.keys) ? state.keys : []).map((key) => [key.id, key]))
const hostById = new Map((Array.isArray(state.hosts) ? state.hosts : []).map((host) => [host.id, host]))

function describeKey(key) {
  const keyPath = key ? path.join(keysDir, `${key.id}-${key.filename}`) : ''
  return {
    keyId: key?.id ?? '',
    keyName: key?.name ?? '',
    keyFile: key?.filename ?? '',
    keyPath,
    keyExists: keyPath ? existsSync(keyPath) : false,
  }
}

const hosts = []
for (const hostId of hostIds) {
  const host = hostById.get(hostId)
  if (!host) continue
  const key = keyById.get(host.keyId) ?? null
  const described = describeKey(key)
  const target = host.address.includes(':') && !host.address.startsWith('[') ? `[${host.address}]` : host.address
  hosts.push({
    hostId: host.id,
    label: host.label,
    address: host.address,
    port: host.port,
    username: host.username,
    ...described,
    ssh: described.keyPath
      ? `ssh -i ${described.keyPath} -o IdentitiesOnly=yes ${host.username}@${target}${host.port === 22 ? '' : ` -p ${host.port}`}`
      : '',
  })
}

if (opts.json) {
  console.log(JSON.stringify({ ok: true, workspace, vaultDir, hosts }, null, 2))
} else {
  console.log(`工作区: ${workspace.title}`)
  console.log(`路径:   ${workspace.path}`)
  console.log(`密钥库: ${vaultDir}`)
  if (hosts.length === 0) {
    console.log('\n该工作区没有授权主机。')
  } else {
    console.log('\n授权主机与绑定密钥:')
    for (const host of hosts) {
      console.log(`\n- ${host.label}  ${host.username}@${host.address}:${host.port}`)
      console.log(`  密钥: ${host.keyName || host.keyId}  ${host.keyPath || '(未知)'}${host.keyExists ? '' : '  [文件不存在]'}`)
      if (host.ssh) console.log(`  连接: ${host.ssh}`)
    }
  }
}

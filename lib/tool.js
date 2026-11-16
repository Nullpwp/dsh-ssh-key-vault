import { existsSync } from 'node:fs'
import path from 'node:path'
import { buildState } from './model.js'

export const SSH_TARGETS_TOOL = 'ssh_targets'

const DESCRIPTION = [
  'List the SSH hosts and their bound vault key files authorized for a workspace.',
  'Read-only: returns each host address/port/username, the bound key name, its absolute key file path, and a ready-to-run ssh command.',
  'It never reads or returns private key contents and never connects. Use it to discover the exact -i path before running ssh.',
  'Omit workspace to use the calling session workspace; pass a workspace title, id, or absolute path to inspect another one.',
].join(' ')

function keySchema() {
  return {
    type: 'object',
    additionalProperties: false,
    required: ['id', 'name', 'filename', 'path', 'exists'],
    properties: {
      id: { type: 'string' },
      name: { type: 'string' },
      filename: { type: 'string' },
      path: { type: 'string' },
      exists: { type: 'boolean' },
    },
  }
}

const OUTPUT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['workspace', 'hosts'],
  properties: {
    workspace: {
      type: 'object',
      additionalProperties: false,
      required: ['id', 'title', 'path'],
      properties: {
        id: { type: 'string' },
        title: { type: 'string' },
        path: { type: 'string' },
      },
    },
    hosts: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['id', 'label', 'address', 'port', 'username', 'key', 'ssh'],
        properties: {
          id: { type: 'string' },
          label: { type: 'string' },
          address: { type: 'string' },
          port: { type: 'integer' },
          username: { type: 'string' },
          key: keySchema(),
          ssh: { type: 'string' },
        },
      },
    },
  },
}

function listOfNames(workspaces) {
  return workspaces
    .map(function (workspace) {
      return (workspace.title || workspace.id) + ' (' + workspace.id + ')'
    })
    .join(', ')
}

function matchWorkspace(workspaces, selector) {
  const wanted = selector.trim()
  const byId = workspaces.find(function (workspace) { return workspace.id === wanted })
  if (byId) return byId
  const byPath = workspaces.find(function (workspace) { return workspace.path === wanted })
  if (byPath) return byPath
  if (path.isAbsolute(wanted)) {
    const resolved = path.resolve(wanted)
    const resolvedMatch = workspaces.find(function (workspace) { return workspace.path === resolved })
    if (resolvedMatch) return resolvedMatch
  }
  const byTitle = workspaces.filter(function (workspace) {
    return (workspace.title || workspace.id) === wanted
  })
  if (byTitle.length > 1) {
    throw new Error('Workspace name "' + wanted + '" is ambiguous; pass its id or absolute path instead.')
  }
  return byTitle[0]
}

function sessionWorkspace(workspaces, session) {
  const sessionId = session?.id === undefined ? '' : String(session.id)
  if (sessionId) {
    const bySession = workspaces.find(function (workspace) {
      return Array.isArray(workspace.sessionIds)
        && workspace.sessionIds.some(function (id) { return String(id) === sessionId })
    })
    if (bySession) return bySession
  }
  const cwd = typeof session?.header?.cwd === 'string' ? session.header.cwd : ''
  if (!cwd) return undefined
  let best
  for (const workspace of workspaces) {
    if (typeof workspace.path !== 'string' || !workspace.path) continue
    const prefix = workspace.path.endsWith(path.sep) ? workspace.path : workspace.path + path.sep
    if (cwd !== workspace.path && !cwd.startsWith(prefix)) continue
    if (!best || workspace.path.length > best.path.length) best = workspace
  }
  return best
}

function keyView(key, keysDir, resolveKeyPath) {
  if (!key) return { id: '', name: '', filename: '', path: '', exists: false }
  const absolute = typeof key.relativePath === 'string' && typeof resolveKeyPath === 'function'
    ? resolveKeyPath(key.relativePath)
    : path.join(keysDir, key.id + '-' + key.filename)
  return {
    id: key.id,
    name: key.name,
    filename: key.filename,
    path: absolute,
    exists: existsSync(absolute),
  }
}

function sshCommand(host, key) {
  if (!key.path) return ''
  const address = host.address.includes(':') && !host.address.startsWith('[')
    ? '[' + host.address + ']'
    : host.address
  const port = host.port === 22 ? '' : ' -p ' + host.port
  return 'ssh -i ' + key.path + ' -o IdentitiesOnly=yes ' + host.username + '@' + address + port
}

/** Human-readable target listing for the Agent tool result. */
export function renderSshTargets(value) {
  const lines = ['Workspace ' + value.workspace.title + ' (' + value.workspace.path + ')']
  if (value.hosts.length === 0) {
    lines.push('No SSH hosts are authorized for this workspace.')
  } else {
    lines.push('', 'Authorized hosts:')
    for (const host of value.hosts) {
      lines.push('- ' + host.label + '  ' + host.username + '@' + host.address + ':' + host.port)
      if (host.key.path) {
        lines.push('  key: ' + (host.key.name || host.key.id) + '  ' + host.key.path + (host.key.exists ? '' : '  [missing]'))
      }
      if (host.ssh) lines.push('  ssh: ' + host.ssh)
    }
  }
  return lines.join('\n')
}

/** Resolve one workspace's granted hosts and key paths; throws on bad selectors. */
export async function collectSshTargets({ keysDir, resolveKeyPath, readVault, listWorkspaces, workspace: selectorInput, session }) {
  const selector = typeof selectorInput === 'string' ? selectorInput.trim() : ''
  const workspaces = (await listWorkspaces()) ?? []
  if (!Array.isArray(workspaces) || workspaces.length === 0) {
    throw new Error('No workspaces are registered, so no SSH targets can be resolved.')
  }

  const workspace = selector
    ? matchWorkspace(workspaces, selector)
    : sessionWorkspace(workspaces, session)
  if (!workspace) {
    const detail = selector
      ? 'Unknown workspace "' + selector + '". Available workspaces: ' + listOfNames(workspaces)
      : 'Cannot determine the current workspace for this session; pass workspace explicitly.'
    throw new Error(detail)
  }

  const vault = await readVault()
  const state = buildState(vault, workspaces)
  const access = state.access[workspace.id] ?? { hostIds: [] }
  const rawKeys = vault && typeof vault.keys === 'object' && vault.keys !== null ? vault.keys : {}
  const hostById = new Map(state.hosts.map(function (host) { return [host.id, host] }))

  const hosts = []
  for (const hostId of access.hostIds) {
    const host = hostById.get(hostId)
    if (!host) continue
    const key = keyView(rawKeys[host.keyId], keysDir, resolveKeyPath)
    hosts.push({
      id: host.id,
      label: host.label,
      address: host.address,
      port: host.port,
      username: host.username,
      key,
      ssh: sshCommand(host, key),
    })
  }

  return {
    workspace: {
      id: workspace.id,
      title: workspace.title || workspace.id,
      path: typeof workspace.path === 'string' ? workspace.path : '',
    },
    hosts,
  }
}

/**
 * Build the model-facing ssh_targets tool from injected vault access.
 * Kept free of DSH imports so the definition can be unit-tested directly.
 */
export function createSshTargetsTool({ keysDir, readVault, listWorkspaces, resolveKeyPath }) {
  return {
    name: SSH_TARGETS_TOOL,
    description: DESCRIPTION,
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        workspace: {
          type: 'string',
          description: 'Workspace title, id, or absolute path. Omit to use the calling session workspace.',
        },
      },
    },
    output: {
      schema: OUTPUT_SCHEMA,
      render(_args, value) {
        return [{ type: 'text', text: renderSshTargets(value) }]
      },
    },
    async execute(args, exec) {
      if (args === null || typeof args !== 'object' || Array.isArray(args)) {
        throw new Error('ssh_targets expects an object argument')
      }
      if (args.workspace !== undefined && typeof args.workspace !== 'string') {
        throw new Error('workspace must be a string when provided')
      }
      return collectSshTargets({
        keysDir,
        resolveKeyPath,
        readVault,
        listWorkspaces,
        workspace: args.workspace,
        session: exec?.agent?.session,
      })
    },
  }
}

/** Register the global ssh_targets tool on the Host tools service. */
export function registerSshTargets(ctx, options) {
  ctx.tools.register(createSshTargetsTool(options))
}

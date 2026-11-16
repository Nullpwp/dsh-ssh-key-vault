import crypto from 'node:crypto'
import net from 'node:net'
import { isPlainObject, vaultError } from './errors.js'

export const MAX_KEY_BYTES = 64 * 1024
export const MAX_KEY_NAME = 80
export const MAX_HOST_LABEL = 80
export const MAX_ADDRESS = 255
export const MAX_USERNAME = 64
export const MAX_NOTE = 500
export const MAX_FILENAME = 96

const CONTROL = /[\u0000-\u001f\u007f]/
const BAD_NOTE_CONTROL = /[\u0001-\u0008\u000b\u000c\u000e-\u001f\u007f]/
const USERNAME_PATTERN = /^[A-Za-z0-9._-]{1,64}$/
const HOSTNAME_PATTERN =
  /^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?$/

/** Generate a random identifier with the given prefix. */
export function newId(prefix) {
  return `${prefix}_${crypto.randomBytes(8).toString('hex')}`
}

/** Keep a filename inside the key store: no separators, no leading dots, safe characters only. */
export function sanitizeFilename(raw) {
  const input = String(raw ?? '')
  const base = input.split(/[\\/]/).pop() ?? ''
  let name = base
    .replace(/[^A-Za-z0-9._-]/g, '')
    .replace(/^\.+/, '')
    .slice(0, MAX_FILENAME)
  if (!name || name === '.' || name === '..') name = 'ssh_private_key'
  return name
}

/** Trim and reject control characters in short single-line labels. */
function cleanLabel(raw, field, maxLength) {
  if (typeof raw !== 'string') {
    throw vaultError(400, `${field}必须是字符串`, 'invalid_field')
  }
  const value = raw.trim()
  if (!value) throw vaultError(400, `${field}不能为空`, 'invalid_field')
  if (value.length > maxLength) {
    throw vaultError(400, `${field}不能超过 ${maxLength} 个字符`, 'invalid_field')
  }
  if (CONTROL.test(value)) {
    throw vaultError(400, `${field}不能包含换行或控制字符`, 'invalid_field')
  }
  return value
}

/** Validate a key display name and enforce case-insensitive uniqueness. */
export function normalizeKeyName(raw, keys = {}, excludeId) {
  const name = cleanLabel(raw, '密钥名称', MAX_KEY_NAME)
  const folded = name.toLowerCase()
  for (const key of Object.values(keys)) {
    if (!key || key.id === excludeId) continue
    if (String(key.name ?? '').trim().toLowerCase() === folded) {
      throw vaultError(409, `密钥名称「${name}」已存在`, 'key_name_conflict')
    }
  }
  return name
}

/** Derive a unique generated name from a filename (used when upload omits a name). */
export function uniqueKeyName(base, keys = {}) {
  const plain = sanitizeFilename(base)
  const used = new Set(
    Object.values(keys)
      .map((key) => String(key?.name ?? '').trim().toLowerCase())
      .filter(Boolean),
  )
  if (!used.has(plain.toLowerCase())) return plain
  for (let index = 2; index < 100; index += 1) {
    const suffix = ` (${index})`
    const candidate = `${plain.slice(0, MAX_KEY_NAME - suffix.length)}${suffix}`
    if (!used.has(candidate.toLowerCase())) return candidate
  }
  throw vaultError(409, '无法为密钥生成唯一名称，请手动指定名称', 'key_name_conflict')
}

/** Validate a host display label and enforce case-insensitive uniqueness. */
export function normalizeHostLabel(raw, hosts = {}, excludeId) {
  const label = cleanLabel(raw, '主机名称', MAX_HOST_LABEL)
  const folded = label.toLowerCase()
  for (const host of Object.values(hosts)) {
    if (!host || host.id === excludeId) continue
    if (String(host.label ?? '').trim().toLowerCase() === folded) {
      throw vaultError(409, `主机名称「${label}」已存在`, 'host_label_conflict')
    }
  }
  return label
}

/** Accept an IPv4 literal, a hostname, bracketed IPv6, or a bare IPv6 literal. */
export function normalizeAddress(raw) {
  if (typeof raw !== 'string') {
    throw vaultError(400, '主机地址必须是字符串', 'invalid_address')
  }
  const value = raw.trim()
  if (!value) throw vaultError(400, '主机地址不能为空', 'invalid_address')
  if (value.length > MAX_ADDRESS) {
    throw vaultError(400, `主机地址不能超过 ${MAX_ADDRESS} 个字符`, 'invalid_address')
  }
  if (/\s/.test(value) || CONTROL.test(value)) {
    throw vaultError(400, '主机地址不能包含空白或控制字符', 'invalid_address')
  }
  if (net.isIP(value) === 4 || net.isIP(value) === 6) return value
  const bracketed = /^\[([^\]]+)\]$/.exec(value)
  if (bracketed && net.isIPv6(bracketed[1])) return value
  if (/^\d+(?:\.\d+){3}$/.test(value)) {
    throw vaultError(400, 'IPv4 地址格式无效', 'invalid_address')
  }
  if (!HOSTNAME_PATTERN.test(value)) {
    throw vaultError(400, '主机地址必须是 IPv4、主机名或 [IPv6] 地址', 'invalid_address')
  }
  return value
}

/** Validate a TCP port; accepts an integer number or a digit-only string. */
export function normalizePort(raw) {
  if (typeof raw !== 'number' && typeof raw !== 'string') {
    throw vaultError(400, '端口必须是 1-65535 的整数', 'invalid_port')
  }
  if (typeof raw === 'string' && !/^\d+$/.test(raw.trim())) {
    throw vaultError(400, '端口必须是 1-65535 的整数', 'invalid_port')
  }
  const port = Number(typeof raw === 'string' ? raw.trim() : raw)
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw vaultError(400, '端口必须是 1-65535 的整数', 'invalid_port')
  }
  return port
}

/** Validate a login user name. */
export function normalizeUsername(raw) {
  if (typeof raw !== 'string') {
    throw vaultError(400, '用户名必须是字符串', 'invalid_username')
  }
  const value = raw.trim()
  if (!USERNAME_PATTERN.test(value)) {
    throw vaultError(400, '用户名只能包含字母、数字、点、下划线和连字符（1-64 位）', 'invalid_username')
  }
  return value
}

/** Validate the optional free-form host note. */
export function normalizeNote(raw) {
  if (raw === undefined || raw === null) return ''
  if (typeof raw !== 'string') {
    throw vaultError(400, '备注必须是字符串', 'invalid_note')
  }
  const value = raw.replace(/\u0000/g, '').replace(/\r\n?/g, '\n').trim()
  if (value.length > MAX_NOTE) {
    throw vaultError(400, `备注不能超过 ${MAX_NOTE} 个字符`, 'invalid_note')
  }
  if (BAD_NOTE_CONTROL.test(value)) {
    throw vaultError(400, '备注包含不支持的控制字符', 'invalid_note')
  }
  return value
}

/**
 * Validate host form input against the current vault.
 * @param {object} raw request body.
 * @param {object} vault current vault (keys/hosts).
 * @param {string} [hostId] id of the host being edited.
 */
export function normalizeHostInput(raw, vault, hostId) {
  if (!isPlainObject(raw)) throw vaultError(400, '请求格式无效', 'invalid_body')
  const keys = isPlainObject(vault?.keys) ? vault.keys : {}
  const hosts = isPlainObject(vault?.hosts) ? vault.hosts : {}
  if (hostId !== undefined && !hosts[hostId]) {
    throw vaultError(404, '主机不存在', 'host_not_found')
  }
  if (typeof raw.keyId !== 'string' || !raw.keyId.trim()) {
    throw vaultError(400, '请选择一把关联密钥', 'invalid_key_id')
  }
  const keyId = raw.keyId.trim()
  if (!keys[keyId]) {
    throw vaultError(400, '关联的密钥不存在', 'key_not_found')
  }
  return {
    label: normalizeHostLabel(raw.label, hosts, hostId),
    address: normalizeAddress(raw.address),
    port: normalizePort(raw.port),
    username: normalizeUsername(raw.username),
    keyId,
    note: normalizeNote(raw.note),
  }
}

/** Deduplicate and validate an array of referenced ids. */
function normalizeIdArray(raw, field, exists, kind) {
  if (!Array.isArray(raw)) {
    throw vaultError(400, `${field} 必须是数组`, 'invalid_access')
  }
  const result = []
  const seen = new Set()
  for (const item of raw) {
    if (typeof item !== 'string' || !item.trim() || item.length > 128) {
      throw vaultError(400, `${field} 包含无效的 ${kind} ID`, 'invalid_access')
    }
    const id = item.trim()
    if (!exists(id)) {
      throw vaultError(400, `${kind}不存在：${id}`, 'invalid_access')
    }
    if (!seen.has(id)) {
      seen.add(id)
      result.push(id)
    }
  }
  return result
}

/** Validate a complete access/set payload against the current vault. */
export function normalizeAccessInput(vault, raw) {
  if (!isPlainObject(raw)) throw vaultError(400, '请求格式无效', 'invalid_body')
  if (typeof raw.workspaceId !== 'string' || !raw.workspaceId.trim()) {
    throw vaultError(400, '工作区 ID 不能为空', 'invalid_workspace')
  }
  if (raw.keyIds !== undefined) {
    throw vaultError(400, '授权已改为按主机，请刷新页面后重试', 'invalid_access')
  }
  const hosts = isPlainObject(vault?.hosts) ? vault.hosts : {}
  return {
    workspaceId: raw.workspaceId.trim(),
    hostIds: normalizeIdArray(raw.hostIds, 'hostIds', (id) => Boolean(hosts[id]), '主机'),
  }
}

/** Store a workspace's granted hosts; empty grants remove the entry entirely. */
export function applyAccess(vault, workspaceId, hostIds) {
  if (!vault.access || typeof vault.access !== 'object') vault.access = {}
  if (hostIds.length === 0) {
    delete vault.access[workspaceId]
    return
  }
  vault.access[workspaceId] = { hostIds: [...hostIds] }
}

/** Remove a host id from every workspace grant. */
export function removeHostFromAccess(vault, hostId) {
  for (const [workspaceId, entry] of Object.entries(vault.access ?? {})) {
    if (!entry || !Array.isArray(entry.hostIds)) continue
    entry.hostIds = entry.hostIds.filter((id) => id !== hostId)
    if (entry.hostIds.length === 0) delete vault.access[workspaceId]
  }
}

/** Direct host grants filtered to records that still exist. */
export function directAccess(vault, workspaceId) {
  const entry = isPlainObject(vault?.access) ? vault.access[workspaceId] : undefined
  const hosts = isPlainObject(vault?.hosts) ? vault.hosts : {}
  const hostIds = Array.isArray(entry?.hostIds)
    ? [...new Set(entry.hostIds.filter((id) => typeof id === 'string' && Boolean(hosts[id])))]
    : []
  return { hostIds }
}

/** Public key metadata; never includes private material or storage paths. */
function publicKey(key, hostCount, authorizedWorkspaceIds) {
  return {
    id: key.id,
    name: key.name,
    filename: key.filename,
    fingerprint: key.fingerprint,
    algorithm: key.algorithm,
    bits: key.bits,
    comment: key.comment ?? '',
    createdAt: key.createdAt,
    updatedAt: key.updatedAt,
    hostCount,
    authorizedWorkspaceIds,
  }
}

/** Public host profile. */
function publicHost(host, authorizedWorkspaceIds) {
  return {
    id: host.id,
    label: host.label,
    address: host.address,
    port: host.port,
    username: host.username,
    keyId: host.keyId,
    note: host.note ?? '',
    createdAt: host.createdAt,
    updatedAt: host.updatedAt,
    authorizedWorkspaceIds,
  }
}

function normalizeWorkspaces(workspaces) {
  const list = Array.isArray(workspaces) ? workspaces : []
  const result = []
  const seen = new Set()
  for (const workspace of list) {
    const id = typeof workspace?.id === 'string' ? workspace.id.trim() : ''
    if (!id || seen.has(id)) continue
    seen.add(id)
    result.push({
      id,
      title: typeof workspace.title === 'string' && workspace.title.trim() ? workspace.title.trim() : id,
      path: typeof workspace.path === 'string' ? workspace.path : '',
    })
  }
  return result
}

function byCreatedAt(a, b) {
  const left = String(a?.createdAt ?? '')
  const right = String(b?.createdAt ?? '')
  if (left !== right) return left < right ? -1 : 1
  return String(a?.id ?? '').localeCompare(String(b?.id ?? ''))
}

/**
 * Project the vault into the browser-safe state document.
 * Workspace entries for IDs no longer in the registry are omitted.
 */
export function buildState(vault, workspaces) {
  const wsList = normalizeWorkspaces(workspaces)
  const keys = isPlainObject(vault?.keys) ? vault.keys : {}
  const hosts = isPlainObject(vault?.hosts) ? vault.hosts : {}

  const access = Object.create(null)
  const keyWorkspaces = new Map()
  const hostWorkspaces = new Map()
  for (const workspace of wsList) {
    const direct = directAccess(vault, workspace.id)
    access[workspace.id] = { hostIds: direct.hostIds }
    for (const hostId of direct.hostIds) {
      const host = hosts[hostId]
      if (!host) continue
      if (!hostWorkspaces.has(hostId)) hostWorkspaces.set(hostId, [])
      hostWorkspaces.get(hostId).push(workspace.id)
      const keyId = host.keyId
      if (typeof keyId !== 'string' || !keys[keyId]) continue
      if (!keyWorkspaces.has(keyId)) keyWorkspaces.set(keyId, [])
      const workspaceIds = keyWorkspaces.get(keyId)
      if (!workspaceIds.includes(workspace.id)) workspaceIds.push(workspace.id)
    }
  }

  const keyRows = Object.values(keys)
    .filter((key) => key && typeof key.id === 'string')
    .sort(byCreatedAt)
    .map((key) => {
      const hostCount = Object.values(hosts).filter((host) => host && host.keyId === key.id).length
      return publicKey(key, hostCount, keyWorkspaces.get(key.id) ?? [])
    })

  const hostRows = Object.values(hosts)
    .filter((host) => host && typeof host.id === 'string')
    .sort(byCreatedAt)
    .map((host) => publicHost(host, hostWorkspaces.get(host.id) ?? []))

  const grantedWorkspaces = wsList.filter((workspace) => {
    return access[workspace.id].hostIds.length > 0
  }).length

  return {
    keys: keyRows,
    hosts: hostRows,
    workspaces: wsList,
    access,
    stats: { keys: keyRows.length, hosts: hostRows.length, grantedWorkspaces },
  }
}

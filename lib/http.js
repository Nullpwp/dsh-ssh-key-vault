import {
  applyAccess,
  buildState,
  newId,
  normalizeAccessInput,
  normalizeHostInput,
  normalizeKeyName,
  removeHostFromAccess,
  sanitizeFilename,
  uniqueKeyName,
} from './model.js'
import { findSshKeygen, validatePrivateKey } from './ssh.js'
import { isPlainObject, vaultError } from './errors.js'

export const ROUTE_PATH = '/ssh-key-vault'
export const MAX_BODY_BYTES = 256 * 1024

/** Send a JSON response with the API's fixed no-store / nosniff headers. */
export function sendJson(res, status, payload) {
  if (!res || res.writableEnded) return
  const body = Buffer.from(JSON.stringify(payload))
  res.statusCode = status
  res.setHeader('content-type', 'application/json; charset=utf-8')
  res.setHeader('content-length', String(body.length))
  res.setHeader('cache-control', 'no-store')
  res.setHeader('x-content-type-options', 'nosniff')
  res.end(body)
}

/** Send a private key file as a download; never cached and never inline. */
export function sendKeyDownload(res, content, filename) {
  if (!res || res.writableEnded) return
  const safe = String(filename ?? '').replace(/[^A-Za-z0-9._-]/g, '_').replace(/^\.+/, '') || 'ssh_private_key'
  res.statusCode = 200
  res.setHeader('content-type', 'application/octet-stream')
  res.setHeader('content-length', String(content.length))
  res.setHeader('content-disposition', `attachment; filename="${safe}"`)
  res.setHeader('cache-control', 'no-store')
  res.setHeader('pragma', 'no-cache')
  res.setHeader('x-content-type-options', 'nosniff')
  res.setHeader('x-download-options', 'noopen')
  res.end(content)
}

/**
 * Read and parse a JSON object request body with a hard byte limit.
 * @param {import('node:http').IncomingMessage} req
 * @param {number} [maxBytes]
 */
export function readJsonBody(req, maxBytes = MAX_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers?.['content-length'])
    if (Number.isFinite(declared) && declared > maxBytes) {
      reject(vaultError(413, '请求体过大', 'body_too_large'))
      return
    }
    const chunks = []
    let size = 0
    let settled = false
    const cleanup = () => {
      req.off?.('data', onData)
      req.off?.('end', onEnd)
      req.off?.('error', onError)
      req.off?.('aborted', onAborted)
    }
    const finish = (callback, value) => {
      if (settled) return
      settled = true
      cleanup()
      callback(value)
    }
    const onData = (chunk) => {
      if (settled) return
      size += chunk.length
      if (size > maxBytes) {
        finish(reject, vaultError(413, '请求体过大', 'body_too_large'))
        req.resume?.()
        return
      }
      chunks.push(chunk)
    }
    const onEnd = () => {
      if (settled) return
      const text = Buffer.concat(chunks).toString('utf8')
      if (!text.trim()) {
        finish(reject, vaultError(400, '请求体为空', 'empty_body'))
        return
      }
      let parsed
      try {
        parsed = JSON.parse(text)
      } catch {
        finish(reject, vaultError(400, '请求体不是有效的 JSON', 'invalid_json'))
        return
      }
      if (!isPlainObject(parsed)) {
        finish(reject, vaultError(400, '请求体格式无效', 'invalid_body'))
        return
      }
      finish(resolve, parsed)
    }
    const onError = (error) => finish(reject, error)
    const onAborted = () => finish(reject, vaultError(400, '请求已中断', 'request_aborted'))
    req.on('data', onData)
    req.on('end', onEnd)
    req.on('error', onError)
    req.on('aborted', onAborted)
  })
}

/** Same-origin check for state-changing requests, compatible with a missing Origin header. */
export function isSameOrigin(ctx, req) {
  const origin = req.headers?.origin
  if (origin === undefined) return true
  if (typeof origin !== 'string' || !origin || origin === 'null') return false
  let parsed
  try {
    parsed = new URL(origin)
  } catch {
    return false
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false
  const hostHeader = req.headers?.host
  if (typeof hostHeader === 'string' && hostHeader.trim()) {
    if (parsed.host.toLowerCase() === hostHeader.trim().toLowerCase()) return true
  }
  try {
    const configured = ctx.webServer?.getOrigin?.()
    if (typeof configured === 'string' && configured) {
      return parsed.origin === new URL(configured).origin
    }
  } catch {
    // Fall through to rejection.
  }
  return false
}

function isJsonContentType(req) {
  const raw = String(req.headers?.['content-type'] ?? '')
    .split(';')[0]
    .trim()
    .toLowerCase()
  return raw === 'application/json'
}

async function getWorkspaces(ctx) {
  const registry = ctx.workspaceRegistry
  if (!registry || typeof registry.list !== 'function') return []
  const list = await registry.list()
  return Array.isArray(list) ? list : []
}

async function publicState(ctx, store) {
  const [vault, workspaces, sshKeygen] = await Promise.all([
    store.readVault(),
    getWorkspaces(ctx),
    findSshKeygen(),
  ])
  return {
    capabilities: { sshKeygen: Boolean(sshKeygen) },
    ...buildState(vault, workspaces),
  }
}

function requireString(value, field, maxLength = 255) {
  if (typeof value !== 'string') {
    throw vaultError(400, `${field}必须是字符串`, 'invalid_field')
  }
  const trimmed = value.trim()
  if (!trimmed) throw vaultError(400, `${field}不能为空`, 'invalid_field')
  if (trimmed.length > maxLength) {
    throw vaultError(400, `${field}不能超过 ${maxLength} 个字符`, 'invalid_field')
  }
  return trimmed
}

function requireObjectId(value) {
  return requireString(value, 'ID', 128)
}

function notFound(message) {
  return vaultError(404, message, 'not_found')
}

async function uploadRoute(ctx, store, body) {
  const filename = requireString(body.filename, '文件名', 255)
  if (typeof body.content !== 'string') {
    throw vaultError(400, '私钥内容必须是文本', 'invalid_key_content')
  }
  if (body.name !== undefined && body.name !== null && typeof body.name !== 'string') {
    throw vaultError(400, '密钥名称必须是字符串', 'invalid_name')
  }
  const desiredName = typeof body.name === 'string' ? body.name.trim() : ''
  const sshKeygen = await findSshKeygen()
  if (!sshKeygen) {
    throw vaultError(503, '服务器未安装 ssh-keygen，无法校验私钥', 'ssh_keygen_unavailable')
  }
  const parsed = await validatePrivateKey({ content: body.content, sshKeygen })
  let relativePath = ''
  let saved = false
  let created
  try {
    created = await store.update(async (vault) => {
      const duplicate = Object.values(vault.keys).some(
        (key) => String(key.fingerprint).toLowerCase() === parsed.fingerprint.toLowerCase(),
      )
      if (duplicate) {
        throw vaultError(409, '相同指纹的私钥已经上传过', 'duplicate_key')
      }
      const id = newId('key')
      const safeFilename = sanitizeFilename(filename)
      const name = desiredName
        ? normalizeKeyName(desiredName, vault.keys)
        : uniqueKeyName(safeFilename, vault.keys)
      relativePath = `keys/${id}-${safeFilename}`
      await store.saveKeyFile(relativePath, parsed.content)
      saved = true
      const now = new Date().toISOString()
      vault.keys[id] = {
        id,
        name,
        filename: safeFilename,
        relativePath,
        fingerprint: parsed.fingerprint,
        algorithm: parsed.algorithm,
        bits: parsed.bits,
        comment: parsed.comment,
        createdAt: now,
        updatedAt: now,
      }
      return vault.keys[id]
    })
  } catch (error) {
    if (saved && relativePath) await store.deleteKeyFile(relativePath).catch(() => {})
    throw error
  }
  const state = await publicState(ctx, store)
  return { ok: true, key: state.keys.find((key) => key.id === created.id), state }
}

async function renameRoute(ctx, store, body) {
  const id = requireObjectId(body.id)
  const name = requireString(body.name, '密钥名称', 80)
  let renamed
  await store.update((vault) => {
    const key = vault.keys[id]
    if (!key) throw notFound('密钥不存在')
    key.name = normalizeKeyName(name, vault.keys, id)
    key.updatedAt = new Date().toISOString()
    renamed = key
  })
  const state = await publicState(ctx, store)
  return { ok: true, key: state.keys.find((key) => key.id === renamed.id), state }
}

async function downloadKeyRoute(ctx, store, body, res) {
  const id = requireObjectId(body.id)
  const vault = await store.readVault()
  const key = vault.keys[id]
  if (!key) throw notFound('密钥不存在')
  let content
  try {
    content = await store.readKeyFile(key.relativePath)
  } catch (error) {
    if (error?.code === 'ENOENT') {
      throw vaultError(404, '密钥文件不存在，可能已被移动或删除', 'key_file_missing')
    }
    throw error
  }
  sendKeyDownload(res, content, key.filename)
}

async function deleteKeyRoute(ctx, store, body) {
  const id = requireObjectId(body.id)
  let relativePath = ''
  await store.update((vault) => {
    const key = vault.keys[id]
    if (!key) throw notFound('密钥不存在')
    const referencing = Object.values(vault.hosts).filter((host) => host.keyId === id)
    if (referencing.length > 0) {
      throw vaultError(
        409,
        `该密钥仍被 ${referencing.length} 台主机引用，请先删除或改绑这些主机`,
        'key_in_use',
      )
    }
    relativePath = key.relativePath
    delete vault.keys[id]
  })
  if (relativePath) {
    await store.deleteKeyFile(relativePath).catch(() => {
      ctx.logger?.warn?.(`[ssh-key-vault] key file cleanup failed (${id})`)
    })
  }
  const state = await publicState(ctx, store)
  return { ok: true, deletedId: id, state }
}

async function saveHostRoute(ctx, store, body) {
  let id
  if (body.id !== undefined && body.id !== null && body.id !== '') {
    id = requireObjectId(body.id)
  }
  let saved
  await store.update((vault) => {
    const input = normalizeHostInput(body, vault, id)
    const now = new Date().toISOString()
    if (id) {
      const host = vault.hosts[id]
      Object.assign(host, input, { updatedAt: now })
      saved = host
      return
    }
    const hostId = newId('host')
    const host = { id: hostId, ...input, createdAt: now, updatedAt: now }
    vault.hosts[hostId] = host
    saved = host
  })
  const state = await publicState(ctx, store)
  return { ok: true, host: state.hosts.find((host) => host.id === saved.id), state }
}

async function deleteHostRoute(ctx, store, body) {
  const id = requireObjectId(body.id)
  let keyId = ''
  let keyRelativePath = ''
  let keyRetained = false
  await store.update((vault) => {
    const host = vault.hosts[id]
    if (!host) throw notFound('主机不存在')
    keyId = host.keyId
    const key = vault.keys[keyId]
    const stillUsed = Object.values(vault.hosts).some(
      (candidate) => candidate.id !== id && candidate.keyId === keyId,
    )
    delete vault.hosts[id]
    removeHostFromAccess(vault, id)
    if (!key) return
    if (stillUsed) {
      keyRetained = true
      return
    }
    keyRelativePath = key.relativePath
    delete vault.keys[keyId]
  })
  if (keyRelativePath) {
    await store.deleteKeyFile(keyRelativePath).catch(() => {
      ctx.logger?.warn?.(`[ssh-key-vault] key file cleanup failed (${keyId})`)
    })
  }
  const state = await publicState(ctx, store)
  return {
    ok: true,
    deletedId: id,
    ...(keyRelativePath ? { deletedKeyId: keyId } : {}),
    ...(keyRetained ? { keyRetained: true } : {}),
    state,
  }
}

async function setAccessRoute(ctx, store, body) {
  if (typeof body.workspaceId !== 'string' || !body.workspaceId.trim()) {
    throw vaultError(400, '工作区 ID 不能为空', 'invalid_workspace')
  }
  const workspaceId = body.workspaceId.trim()
  const workspaces = await getWorkspaces(ctx)
  const known = new Set(
    workspaces
      .map((workspace) => (typeof workspace?.id === 'string' ? workspace.id : ''))
      .filter(Boolean),
  )
  if (!known.has(workspaceId)) {
    throw vaultError(400, '工作区不存在', 'workspace_not_found')
  }
  await store.update((vault) => {
    const checked = normalizeAccessInput(vault, body)
    applyAccess(vault, checked.workspaceId, checked.hostIds)
  })
  const state = await publicState(ctx, store)
  return {
    ok: true,
    workspaceId,
    access: state.access[workspaceId] ?? null,
    state,
  }
}

async function route(ctx, store, req, res) {
  const method = String(req.method ?? 'GET').toUpperCase()
  if (method === 'POST' && !isSameOrigin(ctx, req)) {
    throw vaultError(403, '请求来源不被允许', 'origin_forbidden')
  }
  let pathname
  try {
    pathname = new URL(req.url ?? '/', 'http://localhost').pathname
  } catch {
    throw vaultError(400, '请求路径无效', 'invalid_path')
  }
  const normalizedPath = pathname.replace(/\/+$/, '') || '/'
  if (normalizedPath === ROUTE_PATH) {
    if (method !== 'GET') throw vaultError(405, '仅支持 GET', 'method_not_allowed')
    sendJson(res, 200, { ok: true, service: 'ssh-key-vault', version: 1 })
    return
  }
  if (!normalizedPath.startsWith(`${ROUTE_PATH}/`)) {
    throw notFound('接口不存在')
  }
  const subpath = normalizedPath.slice(ROUTE_PATH.length + 1)
  if (subpath === 'state') {
    if (method !== 'GET') throw vaultError(405, '仅支持 GET', 'method_not_allowed')
    const state = await publicState(ctx, store)
    sendJson(res, 200, { ok: true, ...state })
    return
  }
  if (subpath === 'keys/download') {
    if (method !== 'POST') throw vaultError(405, '仅支持 POST', 'method_not_allowed')
    if (!isJsonContentType(req)) {
      throw vaultError(415, '请求 Content-Type 必须是 application/json', 'unsupported_media_type')
    }
    const body = await readJsonBody(req)
    await downloadKeyRoute(ctx, store, body, res)
    return
  }
  const handlers = {
    'keys/upload': uploadRoute,
    'keys/rename': renameRoute,
    'keys/delete': deleteKeyRoute,
    'hosts/save': saveHostRoute,
    'hosts/delete': deleteHostRoute,
    'access/set': setAccessRoute,
  }
  const handler = handlers[subpath]
  if (!handler) throw notFound('接口不存在')
  if (method !== 'POST') throw vaultError(405, '仅支持 POST', 'method_not_allowed')
  if (!isJsonContentType(req)) {
    throw vaultError(415, '请求 Content-Type 必须是 application/json', 'unsupported_media_type')
  }
  const body = await readJsonBody(req)
  sendJson(res, 200, await handler(ctx, store, body))
}

/** Route one /ssh-key-vault request; always ends the response. */
export async function dispatch(ctx, store, req, res) {
  try {
    await route(ctx, store, req, res)
  } catch (error) {
    const known = error?.name === 'VaultError' && Number.isInteger(error.status)
    const status = known ? error.status : 500
    if (status >= 500) {
      ctx.logger?.warn?.(`[ssh-key-vault] ${String(req.method ?? '?')} failed (${known ? error.code : 'internal'})`)
    }
    const payload = { ok: false }
    if (known) {
      payload.error = error.message
      if (error.code) payload.code = error.code
    } else {
      payload.error = '服务器内部错误'
      payload.code = 'internal_error'
    }
    sendJson(res, status, payload)
  }
}

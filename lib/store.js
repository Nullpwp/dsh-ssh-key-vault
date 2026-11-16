import crypto from 'node:crypto'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { isPlainObject, vaultError } from './errors.js'

export const VAULT_VERSION = 2
export const LEGACY_VAULT_VERSION = 1
export const VAULT_FILENAME = 'vault.json'

/** Fresh empty vault, using null-prototype maps so arbitrary ids are safe keys. */
export function emptyVault() {
  return {
    version: VAULT_VERSION,
    keys: Object.create(null),
    hosts: Object.create(null),
    access: Object.create(null),
  }
}

/** Resolve the default storage root under DSH_HOME. */
export function defaultRootDir(env = process.env) {
  const home = env.DSH_HOME?.trim() || path.join(os.homedir(), '.dsh')
  return path.join(home, 'ssh-key-vault')
}

function corruptError() {
  return vaultError(
    500,
    '密钥库数据文件已损坏或格式不受支持。为保护现有数据，插件不会重置该文件；请先备份并手动修复或恢复备份。',
    'vault_corrupt',
  )
}

function requireString(value, field) {
  if (typeof value !== 'string' || !value) throw corruptError()
  return value
}

/**
 * Create the vault file store.
 * @param {{ rootDir?: string, vaultFile?: string }} [options]
 */
export function createStore(options = {}) {
  const rootDir = path.resolve(options.rootDir || defaultRootDir())
  const vaultFile = path.resolve(options.vaultFile || path.join(rootDir, VAULT_FILENAME))
  const keysDir = path.join(rootDir, 'keys')
  let queue = Promise.resolve()

  async function ensureDirs() {
    await fs.mkdir(rootDir, { recursive: true, mode: 0o700 })
    await fs.chmod(rootDir, 0o700).catch(() => {})
    await fs.mkdir(keysDir, { recursive: true, mode: 0o700 })
    await fs.chmod(keysDir, 0o700).catch(() => {})
  }

  /** Resolve a stored relative path and keep it strictly inside the keys directory. */
  function resolveKeyPath(relativePath) {
    if (typeof relativePath !== 'string' || !relativePath.trim()) {
      throw corruptError()
    }
    const absolute = path.resolve(rootDir, relativePath)
    if (!absolute.startsWith(`${keysDir}${path.sep}`)) {
      throw corruptError()
    }
    return absolute
  }

  function normalizeStoredVault(raw) {
    if (
      !isPlainObject(raw) ||
      (raw.version !== LEGACY_VAULT_VERSION && raw.version !== VAULT_VERSION) ||
      !isPlainObject(raw.keys) ||
      !isPlainObject(raw.hosts) ||
      !isPlainObject(raw.access)
    ) {
      throw corruptError()
    }
    const legacy = raw.version === LEGACY_VAULT_VERSION
    const vault = emptyVault()
    for (const [id, key] of Object.entries(raw.keys)) {
      if (!isPlainObject(key) || key.id !== id) throw corruptError()
      const relativePath = requireString(key.relativePath, 'relativePath')
      resolveKeyPath(relativePath)
      vault.keys[id] = {
        id,
        name: requireString(key.name, 'name'),
        filename: requireString(key.filename, 'filename'),
        relativePath,
        fingerprint: requireString(key.fingerprint, 'fingerprint'),
        algorithm: requireString(key.algorithm, 'algorithm'),
        bits: Number.isInteger(key.bits) && key.bits > 0 ? key.bits : (() => { throw corruptError() })(),
        comment: typeof key.comment === 'string' ? key.comment : '',
        createdAt: requireString(key.createdAt, 'createdAt'),
        updatedAt: requireString(key.updatedAt, 'updatedAt'),
      }
    }
    for (const [id, host] of Object.entries(raw.hosts)) {
      if (!isPlainObject(host) || host.id !== id) throw corruptError()
      vault.hosts[id] = {
        id,
        label: requireString(host.label, 'label'),
        address: requireString(host.address, 'address'),
        port: Number.isInteger(host.port) && host.port >= 1 && host.port <= 65535 ? host.port : (() => { throw corruptError() })(),
        username: requireString(host.username, 'username'),
        keyId: requireString(host.keyId, 'keyId'),
        note: typeof host.note === 'string' ? host.note : '',
        createdAt: requireString(host.createdAt, 'createdAt'),
        updatedAt: requireString(host.updatedAt, 'updatedAt'),
      }
    }
    for (const [workspaceId, entry] of Object.entries(raw.access)) {
      if (!workspaceId || !isPlainObject(entry)) throw corruptError()
      if (!Array.isArray(entry.hostIds) || entry.hostIds.some((id) => typeof id !== 'string')) {
        throw corruptError()
      }
      const hostIds = new Set(entry.hostIds)
      if (legacy) {
        // v1 stored alongside host grants whatever keys were granted directly.
        // Host-only grants are the v2 model: expand each key to the hosts bound
        // to it at migration time, then discard the key dimension.
        if (!Array.isArray(entry.keyIds) || entry.keyIds.some((id) => typeof id !== 'string')) {
          throw corruptError()
        }
        for (const keyId of entry.keyIds) {
          for (const host of Object.values(vault.hosts)) {
            if (host.keyId === keyId) hostIds.add(host.id)
          }
        }
      } else if (entry.keyIds !== undefined) {
        // v2 must not carry the removed direct-key dimension.
        throw corruptError()
      }
      const existingHostIds = [...hostIds].filter((id) => Boolean(vault.hosts[id]))
      if (existingHostIds.length > 0) {
        vault.access[workspaceId] = { hostIds: existingHostIds }
      }
    }
    return vault
  }

  async function readVault() {
    await ensureDirs()
    let text
    try {
      text = await fs.readFile(vaultFile, 'utf8')
    } catch (error) {
      if (error?.code === 'ENOENT') return emptyVault()
      throw error
    }
    let parsed
    try {
      parsed = JSON.parse(text)
    } catch {
      throw corruptError()
    }
    return normalizeStoredVault(parsed)
  }

  async function writeVault(vault) {
    await ensureDirs()
    const body = `${JSON.stringify(vault, null, 2)}\n`
    const temp = path.join(
      rootDir,
      `.${VAULT_FILENAME}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`,
    )
    let handle
    try {
      handle = await fs.open(temp, 'wx', 0o600)
      await handle.writeFile(body, 'utf8')
      await handle.sync()
      await handle.close()
      handle = undefined
      await fs.rename(temp, vaultFile)
      await fs.chmod(vaultFile, 0o600).catch(() => {})
    } catch (error) {
      if (handle) await handle.close().catch(() => {})
      await fs.rm(temp, { force: true }).catch(() => {})
      throw error
    }
  }

  function enqueue(task) {
    const run = queue.then(task)
    queue = run.then(
      () => undefined,
      () => undefined,
    )
    return run
  }

  /**
   * Read-modify-write under one serialized queue. A failed task does not block later tasks.
   * @template T
   * @param {(vault: object) => Promise<T> | T} mutate
   * @returns {Promise<T>}
   */
  function update(mutate) {
    return enqueue(async () => {
      const vault = await readVault()
      const result = await mutate(vault)
      await writeVault(vault)
      return result
    })
  }

  async function saveKeyFile(relativePath, content) {
    const absolute = resolveKeyPath(relativePath)
    if (path.dirname(absolute) !== keysDir) throw corruptError()
    await ensureDirs()
    const temp = path.join(keysDir, `.key-${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`)
    let handle
    try {
      handle = await fs.open(temp, 'wx', 0o600)
      await handle.writeFile(Buffer.isBuffer(content) ? content : Buffer.from(String(content), 'utf8'))
      await handle.sync()
      await handle.close()
      handle = undefined
      await fs.rename(temp, absolute)
      await fs.chmod(absolute, 0o600).catch(() => {})
    } catch (error) {
      if (handle) await handle.close().catch(() => {})
      await fs.rm(temp, { force: true }).catch(() => {})
      throw error
    }
  }

  async function deleteKeyFile(relativePath) {
    const absolute = resolveKeyPath(relativePath)
    try {
      await fs.unlink(absolute)
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error
    }
  }

  return {
    rootDir,
    vaultFile,
    keysDir,
    ensureDirs,
    readVault,
    writeVault,
    update,
    saveKeyFile,
    deleteKeyFile,
    resolveKeyPath,
  }
}

import { spawn } from 'node:child_process'
import { constants as fsConstants } from 'node:fs'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { MAX_KEY_BYTES } from './model.js'
import { vaultError } from './errors.js'

const MAX_CAPTURE = 64 * 1024
const DEFAULT_TIMEOUT_MS = 10_000
const PUBLIC_LINE = /^(ssh-[a-z0-9-]+|ecdsa-[a-z0-9-]+|sk-[a-z0-9@.-]+)\s+[A-Za-z0-9+/=]+/

function run(command, args, timeoutMs) {
  return new Promise((resolve) => {
    let child
    try {
      child = spawn(command, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        env: { ...process.env, LC_ALL: 'C', LANG: 'C' },
      })
    } catch (error) {
      resolve({ ok: false, code: null, stdout: '', stderr: '', spawnError: error, timedOut: false })
      return
    }
    let stdout = ''
    let stderr = ''
    let settled = false
    const finish = (result) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve(result)
    }
    const timer = setTimeout(() => {
      try {
        child.kill('SIGKILL')
      } catch {
        // The process may already have exited.
      }
      finish({ ok: false, code: null, stdout, stderr, timedOut: true })
    }, timeoutMs)
    child.stdout?.on('data', (chunk) => {
      if (stdout.length < MAX_CAPTURE) stdout += String(chunk)
    })
    child.stderr?.on('data', (chunk) => {
      if (stderr.length < MAX_CAPTURE) stderr += String(chunk)
    })
    child.on('error', (error) => {
      finish({ ok: false, code: null, stdout, stderr, spawnError: error, timedOut: false })
    })
    child.on('close', (code) => {
      finish({ ok: code === 0, code, stdout, stderr, timedOut: false })
    })
  })
}

/**
 * Locate an executable ssh-keygen without involving a shell.
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {Promise<string | null>}
 */
export async function findSshKeygen(env = process.env) {
  const candidates = []
  const explicit = env.SSH_KEYGEN?.trim()
  if (explicit) {
    if (explicit.includes('/') || explicit.includes('\\')) candidates.push(path.resolve(explicit))
    else {
      for (const dir of String(env.PATH ?? '').split(path.delimiter)) {
        if (dir) candidates.push(path.join(dir, explicit))
      }
    }
  }
  for (const dir of String(env.PATH ?? '').split(path.delimiter)) {
    if (dir) candidates.push(path.join(dir, 'ssh-keygen'))
  }
  candidates.push('/usr/bin/ssh-keygen', '/bin/ssh-keygen', '/usr/local/bin/ssh-keygen')
  const seen = new Set()
  for (const candidate of candidates) {
    const absolute = path.resolve(candidate)
    if (seen.has(absolute)) continue
    seen.add(absolute)
    try {
      const stat = await fs.stat(absolute)
      if (!stat.isFile()) continue
      await fs.access(absolute, fsConstants.X_OK)
      return absolute
    } catch {
      // Try the next candidate.
    }
  }
  return null
}

function parseComment(line, filename) {
  const value = String(line ?? '').trim()
  if (!value || value === 'no comment') return ''
  if (value.includes('/') || value === filename) return ''
  return value
}

/**
 * Validate one unencrypted private key and derive its public fingerprint metadata.
 * @param {{ content: string, sshKeygen: string, timeoutMs?: number }} input
 */
export async function validatePrivateKey({ content, sshKeygen, timeoutMs = DEFAULT_TIMEOUT_MS }) {
  if (!sshKeygen) {
    throw vaultError(503, '服务器未安装 ssh-keygen，无法校验私钥', 'ssh_keygen_unavailable')
  }
  if (typeof content !== 'string') {
    throw vaultError(400, '私钥内容必须是文本', 'invalid_key_content')
  }
  if (content.includes('\u0000')) {
    throw vaultError(400, '私钥内容包含无效字符', 'invalid_key_content')
  }
  let normalized = content.replace(/\r\n?/g, '\n')
  if (Buffer.byteLength(normalized, 'utf8') > MAX_KEY_BYTES) {
    throw vaultError(413, `私钥文件不能超过 ${MAX_KEY_BYTES / 1024} KiB`, 'key_too_large')
  }
  if (!normalized.trim()) {
    throw vaultError(400, '私钥内容不能为空', 'invalid_key_content')
  }
  if (
    !/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(normalized) ||
    !/-----END [A-Z0-9 ]*PRIVATE KEY-----/.test(normalized)
  ) {
    throw vaultError(400, '文件不是可识别的 SSH 私钥（缺少 PRIVATE KEY 头尾）', 'invalid_key_content')
  }
  normalized = `${normalized.replace(/\s+$/, '')}\n`

  let tempDir
  try {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'dsh-ssh-key-vault-'))
    const keyPath = path.join(tempDir, 'key')
    await fs.writeFile(keyPath, normalized, { mode: 0o600 })

    const derived = await run(sshKeygen, ['-y', '-P', '', '-f', keyPath], timeoutMs)
    if (derived.spawnError?.code === 'ENOENT') {
      throw vaultError(503, '服务器未安装 ssh-keygen，无法校验私钥', 'ssh_keygen_unavailable')
    }
    if (derived.timedOut) {
      throw vaultError(400, '私钥校验超时，请确认私钥格式正确且没有口令', 'key_check_timeout')
    }
    if (!derived.ok) {
      throw vaultError(
        400,
        '私钥无法通过 ssh-keygen 校验：它可能带有口令，或不是受支持的私钥格式',
        'key_check_failed',
      )
    }
    const publicLine = String(derived.stdout ?? '').split(/\r?\n/).find((line) => PUBLIC_LINE.test(line.trim()))
    if (!publicLine) {
      throw vaultError(400, 'ssh-keygen 未能识别该私钥的算法', 'key_check_failed')
    }
    const derivedComment = parseComment(publicLine.trim().split(/\s+/).slice(2).join(' '), path.basename(keyPath))

    const listed = await run(sshKeygen, ['-l', '-E', 'sha256', '-f', keyPath], timeoutMs)
    if (!listed.ok || listed.timedOut) {
      throw vaultError(400, '无法读取私钥的指纹信息', 'key_fingerprint_failed')
    }
    const line = String(listed.stdout ?? '')
      .split(/\r?\n/)
      .map((item) => item.trim())
      .find(Boolean)
    const match = /^(\d+)\s+(SHA256:[A-Za-z0-9+/]+={0,2})\s+(.*?)\s*\(([A-Za-z0-9-]+)\)$/.exec(line ?? '')
    if (!match) {
      throw vaultError(400, '无法解析 ssh-keygen 返回的指纹信息', 'key_fingerprint_failed')
    }
    const bits = Number(match[1])
    const fingerprint = match[2]
    const listedComment = parseComment(match[3], path.basename(keyPath))
    const algorithm = match[4].toUpperCase()
    if (!Number.isInteger(bits) || bits <= 0 || !fingerprint.startsWith('SHA256:')) {
      throw vaultError(400, 'ssh-keygen 返回的指纹信息无效', 'key_fingerprint_failed')
    }
    const comment = (derivedComment || listedComment)
      .replace(/[\u0000-\u001f\u007f]/g, ' ')
      .trim()
      .slice(0, 200)
    return { content: normalized, bits, fingerprint, algorithm, comment }
  } finally {
    if (tempDir) await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {})
  }
}

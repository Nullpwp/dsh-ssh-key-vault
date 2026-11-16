import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { findSshKeygen, validatePrivateKey } from '../lib/ssh.js'

const keygen = await findSshKeygen()
const skip = keygen ? false : 'ssh-keygen is not available in this environment'
let workDir
let ed25519Content

test.before(async () => {
  if (!keygen) return
  workDir = await fs.mkdtemp(path.join(os.tmpdir(), 'skv-ssh-test-'))
  const target = path.join(workDir, 'id_ed25519')
  execFileSync(keygen, ['-q', '-t', 'ed25519', '-N', '', '-C', 'vault-test@example', '-f', target])
  ed25519Content = await fs.readFile(target, 'utf8')
})

test.after(async () => {
  if (workDir) await fs.rm(workDir, { recursive: true, force: true })
})

test('findSshKeygen resolves an executable path', { skip }, async () => {
  assert.ok(keygen)
  assert.match(keygen, /ssh-keygen$/)
})

test('validates a generated unencrypted ed25519 key and derives fingerprint metadata', { skip }, async () => {
  const result = await validatePrivateKey({ content: ed25519Content, sshKeygen: keygen })
  assert.match(result.fingerprint, /^SHA256:[A-Za-z0-9+/]{43}$/)
  assert.equal(result.algorithm, 'ED25519')
  assert.equal(result.bits, 256)
  assert.equal(result.comment, 'vault-test@example')
  assert.ok(result.content.endsWith('\n'))
  assert.ok(result.content.includes('BEGIN OPENSSH PRIVATE KEY'))
})

test('rejects an encrypted private key', { skip }, async () => {
  const target = path.join(workDir, 'encrypted')
  execFileSync(keygen, ['-q', '-t', 'ed25519', '-N', 'secret-passphrase', '-f', target])
  const content = await fs.readFile(target, 'utf8')
  await assert.rejects(
    validatePrivateKey({ content, sshKeygen: keygen }),
    (error) => error.status === 400 && error.code === 'key_check_failed',
  )
})

test('rejects garbage, public keys, and oversize content without invoking a shell', { skip }, async () => {
  await assert.rejects(
    validatePrivateKey({ content: 'not a key at all', sshKeygen: keygen }),
    (error) => error.status === 400 && error.code === 'invalid_key_content',
  )
  const publicKey = await fs.readFile(path.join(workDir, 'id_ed25519.pub'), 'utf8')
  await assert.rejects(
    validatePrivateKey({ content: publicKey, sshKeygen: keygen }),
    (error) => error.status === 400 && error.code === 'invalid_key_content',
  )
  await assert.rejects(
    validatePrivateKey({ content: '-----BEGIN OPENSSH PRIVATE KEY-----\n', sshKeygen: keygen }),
    (error) => error.status === 400,
  )
  const oversized = `-----BEGIN OPENSSH PRIVATE KEY-----\n${'A'.repeat(64 * 1024)}\n-----END OPENSSH PRIVATE KEY-----\n`
  await assert.rejects(
    validatePrivateKey({ content: oversized, sshKeygen: keygen }),
    (error) => error.status === 413 && error.code === 'key_too_large',
  )
})

test('reports a missing ssh-keygen as service unavailable', async () => {
  await assert.rejects(
    validatePrivateKey({ content: 'anything', sshKeygen: null }),
    (error) => error.status === 503 && error.code === 'ssh_keygen_unavailable',
  )
})

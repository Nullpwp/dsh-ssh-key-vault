import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { Readable } from 'node:stream'
import test from 'node:test'
import { dispatch } from '../lib/http.js'
import { createStore } from '../lib/store.js'
import { findSshKeygen } from '../lib/ssh.js'

const keygen = await findSshKeygen()
const skip = keygen ? false : 'ssh-keygen is not available in this environment'
let keyWorkDir

test.before(async () => {
  if (!keygen) return
  keyWorkDir = await fs.mkdtemp(path.join(os.tmpdir(), 'skv-http-keys-'))
})

test.after(async () => {
  if (keyWorkDir) await fs.rm(keyWorkDir, { recursive: true, force: true })
})

async function generateKey(comment = 'http-test') {
  const stamp = `${Date.now()}-${Math.random().toString(16).slice(2)}`
  const target = path.join(keyWorkDir, `id_ed25519_${stamp}`)
  execFileSync(keygen, ['-q', '-t', 'ed25519', '-N', '', '-C', comment, '-f', target])
  return { content: await fs.readFile(target, 'utf8'), filename: 'id_ed25519' }
}

async function setup(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'skv-http-test-'))
  const store = createStore({ rootDir: path.join(root, 'vault') })
  const workspaces = [
    { id: 'ws-1', title: 'Workspace one', path: '/srv/one' },
    { id: 'ws-2', title: 'Workspace two', path: '/srv/two' },
  ]
  const logs = []
  const ctx = {
    webServer: { getOrigin: () => 'http://127.0.0.1:3080' },
    workspaceRegistry: { list: () => workspaces },
    logger: { warn: (message) => logs.push(String(message)) },
  }
  t.after(async () => {
    await fs.rm(root, { recursive: true, force: true })
  })
  return { store, ctx, logs, workspaces }
}

function makeRes() {
  let finish
  const done = new Promise((resolve) => {
    finish = resolve
  })
  const res = {
    statusCode: 0,
    headers: {},
    writableEnded: false,
    setHeader(name, value) {
      this.headers[String(name).toLowerCase()] = String(value)
    },
    end(body) {
      if (this.writableEnded) return
      this.body = body === undefined ? Buffer.alloc(0) : Buffer.from(body)
      this.writableEnded = true
      finish()
    },
  }
  return { res, done }
}

async function call(ctx, store, options = {}) {
  const method = options.method ?? 'GET'
  const requestPath = options.path ?? '/ssh-key-vault'
  const headers = { ...(options.headers ?? {}) }
  const body = options.body
  const chunks = body === undefined ? [] : [Buffer.isBuffer(body) ? body : Buffer.from(body)]
  if (body !== undefined && headers['content-length'] === undefined && options.omitContentLength !== true) {
    headers['content-length'] = String(chunks[0].length)
  }
  const req = Readable.from(chunks)
  req.method = method
  req.url = requestPath
  req.headers = headers
  const { res, done } = makeRes()
  await dispatch(ctx, store, req, res)
  await done
  let json
  try {
    json = JSON.parse(res.body.toString('utf8'))
  } catch {
    json = undefined
  }
  return { status: res.statusCode, headers: res.headers, body: res.body, json }
}

async function uploadKey(ctx, store, content, name) {
  return call(ctx, store, {
    method: 'POST',
    path: '/ssh-key-vault/keys/upload',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name, filename: 'id_ed25519', content }),
  })
}

test('health and empty state are available', async (t) => {
  const { store, ctx } = await setup(t)
  const health = await call(ctx, store)
  assert.equal(health.status, 200)
  assert.deepEqual(health.json, { ok: true, service: 'ssh-key-vault', version: 1 })
  assert.equal(health.headers['cache-control'], 'no-store')
  assert.equal(health.headers['x-content-type-options'], 'nosniff')

  const state = await call(ctx, store, { path: '/ssh-key-vault/state' })
  assert.equal(state.status, 200)
  assert.equal(state.json.ok, true)
  assert.deepEqual(state.json.keys, [])
  assert.deepEqual(state.json.hosts, [])
  assert.equal(state.json.workspaces.length, 2)
  assert.deepEqual(state.json.access['ws-1'], { hostIds: [] })
  assert.deepEqual(state.json.stats, { keys: 0, hosts: 0, grantedWorkspaces: 0 })
  assert.equal(typeof state.json.capabilities.sshKeygen, 'boolean')
  assert.equal(state.body.toString('utf8').includes('relativePath'), false)
})

test('POST enforces JSON content type, same origin, and known routes', async (t) => {
  const { store, ctx } = await setup(t)
  const wrongType = await call(ctx, store, {
    method: 'POST',
    path: '/ssh-key-vault/keys/delete',
    headers: { 'content-type': 'text/plain' },
    body: '{"id":"x"}',
  })
  assert.equal(wrongType.status, 415)

  const badOrigin = await call(ctx, store, {
    method: 'POST',
    path: '/ssh-key-vault/keys/delete',
    headers: { 'content-type': 'application/json', origin: 'http://evil.example' },
    body: '{"id":"x"}',
  })
  assert.equal(badOrigin.status, 403)

  const goodOrigin = await call(ctx, store, {
    method: 'POST',
    path: '/ssh-key-vault/keys/delete',
    headers: { 'content-type': 'application/json', origin: 'http://127.0.0.1:3080' },
    body: '{"id":"x"}',
  })
  assert.equal(goodOrigin.status, 404)

  const missing = await call(ctx, store, { path: '/ssh-key-vault/nope' })
  assert.equal(missing.status, 404)
  const wrongMethod = await call(ctx, store, {
    method: 'GET',
    path: '/ssh-key-vault/keys/delete',
  })
  assert.equal(wrongMethod.status, 405)
  const postHealth = await call(ctx, store, { method: 'POST' })
  assert.equal(postHealth.status, 405)
})

test('invalid or oversized JSON bodies are rejected', async (t) => {
  const { store, ctx } = await setup(t)
  const broken = await call(ctx, store, {
    method: 'POST',
    path: '/ssh-key-vault/keys/delete',
    headers: { 'content-type': 'application/json' },
    body: '{bad json',
  })
  assert.equal(broken.status, 400)
  assert.equal(broken.json.code, 'invalid_json')

  const array = await call(ctx, store, {
    method: 'POST',
    path: '/ssh-key-vault/keys/delete',
    headers: { 'content-type': 'application/json' },
    body: '[]',
  })
  assert.equal(array.status, 400)

  const oversized = JSON.stringify({ id: 'x', padding: 'a'.repeat(300 * 1024) })
  const withLength = await call(ctx, store, {
    method: 'POST',
    path: '/ssh-key-vault/keys/delete',
    headers: { 'content-type': 'application/json' },
    body: oversized,
  })
  assert.equal(withLength.status, 413)
  assert.equal(withLength.json.code, 'body_too_large')

  const streaming = await call(ctx, store, {
    method: 'POST',
    path: '/ssh-key-vault/keys/delete',
    headers: { 'content-type': 'application/json' },
    body: oversized,
    omitContentLength: true,
  })
  assert.equal(streaming.status, 413)
  assert.equal(streaming.json.code, 'body_too_large')
})

test('upload validates with ssh-keygen, stores private files, and rejects duplicates', { skip }, async (t) => {
  const { store, ctx } = await setup(t)
  const generated = await generateKey('http-upload@example')
  const uploaded = await uploadKey(ctx, store, generated.content, 'Production')
  assert.equal(uploaded.status, 200, uploaded.body.toString())
  assert.equal(uploaded.json.ok, true)
  assert.equal(uploaded.json.key.name, 'Production')
  assert.match(uploaded.json.key.fingerprint, /^SHA256:/)
  assert.equal(uploaded.json.key.algorithm, 'ED25519')
  assert.equal(uploaded.json.key.bits, 256)
  assert.equal(uploaded.json.key.hostCount, 0)
  assert.equal(uploaded.body.toString('utf8').includes('PRIVATE KEY'), false)
  assert.equal(uploaded.body.toString('utf8').includes('relativePath'), false)
  assert.equal((await fs.stat(store.rootDir)).mode & 0o777, 0o700)
  assert.equal((await fs.stat(store.keysDir)).mode & 0o777, 0o700)
  assert.equal((await fs.stat(store.vaultFile)).mode & 0o777, 0o600)
  const vault = await store.readVault()
  const stored = Object.values(vault.keys)[0]
  const keyPath = store.resolveKeyPath(stored.relativePath)
  assert.equal((await fs.stat(keyPath)).mode & 0o777, 0o600)

  const duplicate = await uploadKey(ctx, store, generated.content, 'Another')
  assert.equal(duplicate.status, 409)
  assert.equal(duplicate.json.code, 'duplicate_key')

  const garbage = await uploadKey(ctx, store, 'not a private key')
  assert.equal(garbage.status, 400)
  assert.equal(garbage.json.code, 'invalid_key_content')

  const encryptedPath = path.join(keyWorkDir, 'encrypted')
  execFileSync(keygen, ['-q', '-t', 'ed25519', '-N', 'secret', '-f', encryptedPath])
  const encrypted = await uploadKey(ctx, store, await fs.readFile(encryptedPath, 'utf8'))
  assert.equal(encrypted.status, 400)
  assert.equal(encrypted.json.code, 'key_check_failed')

  const oversized = `-----BEGIN OPENSSH PRIVATE KEY-----\n${'A'.repeat(64 * 1024)}\n-----END OPENSSH PRIVATE KEY-----\n`
  const tooLarge = await uploadKey(ctx, store, oversized)
  assert.equal(tooLarge.status, 413)
  assert.equal(tooLarge.json.code, 'key_too_large')

  const state = await call(ctx, store, { path: '/ssh-key-vault/state' })
  assert.equal(state.json.keys.length, 1)
  assert.equal(state.body.toString('utf8').includes('PRIVATE KEY'), false)
})

test('key download returns the private key once with attachment headers', { skip }, async (t) => {
  const { store, ctx } = await setup(t)
  const generated = await generateKey('download@example')
  const uploaded = await uploadKey(ctx, store, generated.content, 'Download key')
  assert.equal(uploaded.status, 200)
  const keyId = uploaded.json.key.id

  const download = await call(ctx, store, {
    method: 'POST',
    path: '/ssh-key-vault/keys/download',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ id: keyId }),
  })
  assert.equal(download.status, 200)
  assert.equal(download.headers['content-type'], 'application/octet-stream')
  assert.equal(download.headers['content-disposition'], 'attachment; filename="id_ed25519"')
  assert.equal(download.headers['cache-control'], 'no-store')
  assert.equal(download.headers['x-content-type-options'], 'nosniff')
  assert.equal(download.body.toString('utf8'), generated.content)

  const crossOrigin = await call(ctx, store, {
    method: 'POST',
    path: '/ssh-key-vault/keys/download',
    headers: {
      'content-type': 'application/json',
      origin: 'https://evil.example',
    },
    body: JSON.stringify({ id: keyId }),
  })
  assert.equal(crossOrigin.status, 403)
  assert.equal(crossOrigin.json.code, 'origin_forbidden')

  const unknown = await call(ctx, store, {
    method: 'POST',
    path: '/ssh-key-vault/keys/download',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ id: 'key_missing' }),
  })
  assert.equal(unknown.status, 404)
  assert.equal(unknown.json.code, 'not_found')

  const wrongMethod = await call(ctx, store, { path: '/ssh-key-vault/keys/download' })
  assert.equal(wrongMethod.status, 405)

  const wrongType = await call(ctx, store, {
    method: 'POST',
    path: '/ssh-key-vault/keys/download',
    headers: { 'content-type': 'text/plain' },
    body: JSON.stringify({ id: keyId }),
  })
  assert.equal(wrongType.status, 415)

  const keyPath = store.resolveKeyPath((await store.readVault()).keys[keyId].relativePath)
  await fs.rm(keyPath)
  const missingFile = await call(ctx, store, {
    method: 'POST',
    path: '/ssh-key-vault/keys/download',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ id: keyId }),
  })
  assert.equal(missingFile.status, 404)
  assert.equal(missingFile.json.code, 'key_file_missing')
})

test('host profiles, key references, grants, and deletion rules work end to end', { skip }, async (t) => {
  const { store, ctx } = await setup(t)
  const first = await generateKey('first@example')
  const second = await generateKey('second@example')
  const one = await uploadKey(ctx, store, first.content, 'First key')
  const two = await uploadKey(ctx, store, second.content, 'Second key')
  assert.equal(one.status, 200)
  assert.equal(two.status, 200)
  const keyOne = one.json.key.id
  const keyTwo = two.json.key.id

  const saveHost = (body) =>
    call(ctx, store, {
      method: 'POST',
      path: '/ssh-key-vault/hosts/save',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    })

  const hostOne = await saveHost({
    label: 'Host one',
    address: '192.0.2.10',
    port: 22,
    username: 'root',
    keyId: keyOne,
    note: 'primary',
  })
  assert.equal(hostOne.status, 200, hostOne.body.toString())
  assert.equal(hostOne.json.host.address, '192.0.2.10')
  assert.equal(hostOne.json.host.keyId, keyOne)
  const hostOneId = hostOne.json.host.id

  const hostTwo = await saveHost({
    label: 'Host two',
    address: 'web.example.com',
    port: '2222',
    username: 'deploy',
    keyId: keyTwo,
  })
  assert.equal(hostTwo.status, 200)
  const hostTwoId = hostTwo.json.host.id

  const duplicateLabel = await saveHost({
    label: 'host one',
    address: '192.0.2.11',
    port: 22,
    username: 'root',
    keyId: keyOne,
  })
  assert.equal(duplicateLabel.status, 409)

  const badPort = await saveHost({
    label: 'Bad port',
    address: '192.0.2.12',
    port: 70000,
    username: 'root',
    keyId: keyOne,
  })
  assert.equal(badPort.status, 400)

  const blockedDelete = await call(ctx, store, {
    method: 'POST',
    path: '/ssh-key-vault/keys/delete',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ id: keyOne }),
  })
  assert.equal(blockedDelete.status, 409)
  assert.equal(blockedDelete.json.code, 'key_in_use')

  const updated = await saveHost({
    id: hostOneId,
    label: 'Host one updated',
    address: '192.0.2.20',
    port: 2200,
    username: 'admin',
    keyId: keyOne,
    note: 'updated',
  })
  assert.equal(updated.status, 200)
  assert.equal(updated.json.host.label, 'Host one updated')
  assert.equal(updated.json.host.port, 2200)

  const setAccess = (workspaceId, hostIds) =>
    call(ctx, store, {
      method: 'POST',
      path: '/ssh-key-vault/access/set',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ workspaceId, hostIds }),
    })

  const granted = await setAccess('ws-1', [hostTwoId])
  assert.equal(granted.status, 200)
  assert.deepEqual(granted.json.access, { hostIds: [hostTwoId] })
  assert.deepEqual(granted.json.state.access['ws-1'], { hostIds: [hostTwoId] })
  assert.deepEqual(
    granted.json.state.keys.find((key) => key.id === keyTwo).authorizedWorkspaceIds,
    ['ws-1'],
  )
  assert.deepEqual(
    granted.json.state.hosts.find((host) => host.id === hostTwoId).authorizedWorkspaceIds,
    ['ws-1'],
  )

  const regranted = await setAccess('ws-1', [hostOneId])
  assert.equal(regranted.status, 200)
  assert.deepEqual(regranted.json.access, { hostIds: [hostOneId] })
  assert.deepEqual(
    regranted.json.state.keys.find((key) => key.id === keyOne).authorizedWorkspaceIds,
    ['ws-1'],
  )
  assert.deepEqual(
    regranted.json.state.keys.find((key) => key.id === keyTwo).authorizedWorkspaceIds,
    [],
  )

  const revoked = await setAccess('ws-1', [])
  assert.equal(revoked.status, 200)
  assert.deepEqual(revoked.json.access, { hostIds: [] })

  const unknownWorkspace = await setAccess('ws-missing', [])
  assert.equal(unknownWorkspace.status, 400)
  assert.equal(unknownWorkspace.json.code, 'workspace_not_found')

  const unknownHost = await setAccess('ws-1', ['host_missing'])
  assert.equal(unknownHost.status, 400)

  const legacyKeyGrant = await call(ctx, store, {
    method: 'POST',
    path: '/ssh-key-vault/access/set',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ workspaceId: 'ws-1', keyIds: [keyOne], hostIds: [] }),
  })
  assert.equal(legacyKeyGrant.status, 400)
  assert.equal(legacyKeyGrant.json.code, 'invalid_access')

  const state = await call(ctx, store, { path: '/ssh-key-vault/state' })
  assert.equal(state.json.keys.find((key) => key.id === keyOne).hostCount, 1)
  assert.equal(state.json.stats.hosts, 2)

  const keyOnePath = store.resolveKeyPath((await store.readVault()).keys[keyOne].relativePath)
  const deleteHost = await call(ctx, store, {
    method: 'POST',
    path: '/ssh-key-vault/hosts/delete',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ id: hostOneId }),
  })
  assert.equal(deleteHost.status, 200)
  assert.equal(deleteHost.json.deletedKeyId, keyOne)
  assert.equal(deleteHost.json.keyRetained, undefined)
  assert.equal(deleteHost.json.state.keys.some((key) => key.id === keyOne), false)
  await assert.rejects(fs.stat(keyOnePath), (error) => error.code === 'ENOENT')

  const deleteAlreadyGoneKey = await call(ctx, store, {
    method: 'POST',
    path: '/ssh-key-vault/keys/delete',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ id: keyOne }),
  })
  assert.equal(deleteAlreadyGoneKey.status, 404)

  const deleteMissingHost = await call(ctx, store, {
    method: 'POST',
    path: '/ssh-key-vault/hosts/delete',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ id: 'host_missing' }),
  })
  assert.equal(deleteMissingHost.status, 404)
})

test('deleting a host keeps a key shared by another host until the last host is deleted', { skip }, async (t) => {
  const { store, ctx } = await setup(t)
  const generated = await generateKey('shared@example')
  const uploaded = await uploadKey(ctx, store, generated.content, 'Shared key')
  assert.equal(uploaded.status, 200)
  const keyId = uploaded.json.key.id

  const saveHost = (label) =>
    call(ctx, store, {
      method: 'POST',
      path: '/ssh-key-vault/hosts/save',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        label,
        address: '192.0.2.30',
        port: 22,
        username: 'root',
        keyId,
      }),
    })

  const first = await saveHost('First shared host')
  const second = await saveHost('Second shared host')
  assert.equal(first.status, 200)
  assert.equal(second.status, 200)
  const keyPath = store.resolveKeyPath((await store.readVault()).keys[keyId].relativePath)

  const deleteFirst = await call(ctx, store, {
    method: 'POST',
    path: '/ssh-key-vault/hosts/delete',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ id: first.json.host.id }),
  })
  assert.equal(deleteFirst.status, 200)
  assert.equal(deleteFirst.json.keyRetained, true)
  assert.equal(deleteFirst.json.deletedKeyId, undefined)
  assert.equal(deleteFirst.json.state.keys.some((key) => key.id === keyId), true)
  await fs.stat(keyPath)

  const deleteSecond = await call(ctx, store, {
    method: 'POST',
    path: '/ssh-key-vault/hosts/delete',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ id: second.json.host.id }),
  })
  assert.equal(deleteSecond.status, 200)
  assert.equal(deleteSecond.json.deletedKeyId, keyId)
  assert.equal(deleteSecond.json.state.keys.some((key) => key.id === keyId), false)
  await assert.rejects(fs.stat(keyPath), (error) => error.code === 'ENOENT')
})

test('state omits grants for workspaces that no longer exist', async (t) => {
  const { store, ctx } = await setup(t)
  await store.update((vault) => {
    vault.access['ws-deleted'] = { hostIds: ['host_stale'] }
  })
  const state = await call(ctx, store, { path: '/ssh-key-vault/state' })
  assert.equal(state.status, 200)
  assert.equal(Object.hasOwn(state.json.access, 'ws-deleted'), false)
  assert.deepEqual(Object.keys(state.json.access), ['ws-1', 'ws-2'])
})

test('a corrupt vault returns a safe 500 without resetting the file', async (t) => {
  const { store, ctx, logs } = await setup(t)
  await fs.mkdir(store.rootDir, { recursive: true })
  await fs.writeFile(store.vaultFile, '{"broken":', 'utf8')
  const state = await call(ctx, store, { path: '/ssh-key-vault/state' })
  assert.equal(state.status, 500)
  assert.equal(state.json.ok, false)
  assert.equal(state.json.code, 'vault_corrupt')
  assert.equal(state.body.toString('utf8').includes('at '), false)
  assert.equal(await fs.readFile(store.vaultFile, 'utf8'), '{"broken":')
  assert.ok(logs.length >= 1)
  assert.equal(logs.join('\n').includes('{"broken"'), false)
})

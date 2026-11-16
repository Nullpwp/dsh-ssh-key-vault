import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { createStore, emptyVault } from '../lib/store.js'

async function makeStore(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'skv-store-test-'))
  t.after(async () => {
    await fs.rm(root, { recursive: true, force: true })
  })
  return { root, store: createStore({ rootDir: path.join(root, 'vault') }) }
}

function keyRecord(id, relativePath) {
  const stamp = '2026-01-01T00:00:00.000Z'
  return {
    id,
    name: `Key ${id}`,
    filename: 'id_ed25519',
    relativePath,
    fingerprint: `SHA256:${id}`,
    algorithm: 'ED25519',
    bits: 256,
    comment: '',
    createdAt: stamp,
    updatedAt: stamp,
  }
}

test('empty vault is returned before any file exists and dirs are private', async (t) => {
  const { store } = await makeStore(t)
  const vault = await store.readVault()
  assert.deepEqual(vault, emptyVault())
  await assert.rejects(fs.stat(store.vaultFile), (error) => error.code === 'ENOENT')
  assert.equal((await fs.stat(store.rootDir)).mode & 0o777, 0o700)
  assert.equal((await fs.stat(store.keysDir)).mode & 0o777, 0o700)
})

test('update writes atomically with 0600 and serializes concurrent writers', async (t) => {
  const { store } = await makeStore(t)
  await store.update((vault) => {
    vault.keys.key_a = keyRecord('key_a', 'keys/key_a-id_ed25519')
  })
  assert.equal((await fs.stat(store.vaultFile)).mode & 0o777, 0o600)
  const parsed = JSON.parse(await fs.readFile(store.vaultFile, 'utf8'))
  assert.equal(parsed.version, 2)
  assert.ok(parsed.keys.key_a)

  await Promise.all(
    Array.from({ length: 20 }, (_, index) =>
      store.update((vault) => {
        const id = `host_${index}`
        vault.hosts[id] = {
          id,
          label: `Host ${index}`,
          address: '192.0.2.1',
          port: 22,
          username: 'root',
          keyId: 'key_a',
          note: '',
          createdAt: '2026-01-01T00:00:00.000Z',
          updatedAt: '2026-01-01T00:00:00.000Z',
        }
      }),
    ),
  )
  const after = await store.readVault()
  assert.equal(Object.keys(after.hosts).length, 20)
  const leftovers = (await fs.readdir(store.rootDir)).filter((name) => name.includes('.tmp'))
  assert.deepEqual(leftovers, [])
})

test('a failed update does not block later updates', async (t) => {
  const { store } = await makeStore(t)
  await assert.rejects(
    store.update(() => {
      throw new Error('nope')
    }),
    /nope/,
  )
  await store.update((vault) => {
    vault.keys.key_a = keyRecord('key_a', 'keys/key_a-id_ed25519')
  })
  assert.ok((await store.readVault()).keys.key_a)
})

test('corrupt or unsupported vault JSON is preserved, never reset', async (t) => {
  const { store } = await makeStore(t)
  await fs.mkdir(store.rootDir, { recursive: true })
  const broken = '{ this is not json'
  await fs.writeFile(store.vaultFile, broken, 'utf8')
  await assert.rejects(
    store.readVault(),
    (error) => error.status === 500 && error.code === 'vault_corrupt',
  )
  assert.equal(await fs.readFile(store.vaultFile, 'utf8'), broken)

  await fs.writeFile(store.vaultFile, JSON.stringify({ version: 3, keys: {}, hosts: {}, access: {} }))
  await assert.rejects(store.readVault(), (error) => error.code === 'vault_corrupt')
})

test('version 1 grants migrate to host-only grants on read', async (t) => {
  const { store } = await makeStore(t)
  await fs.mkdir(store.rootDir, { recursive: true })
  const stamp = '2026-01-01T00:00:00.000Z'
  const host = (id, keyId) => ({
    id,
    label: 'Host ' + id,
    address: '192.0.2.10',
    port: 22,
    username: 'root',
    keyId,
    note: '',
    createdAt: stamp,
    updatedAt: stamp,
  })
  const legacy = {
    version: 1,
    keys: {
      key_1: keyRecord('key_1', 'keys/key_1-id_ed25519'),
      key_2: keyRecord('key_2', 'keys/key_2-id_ed25519'),
    },
    hosts: {
      host_1: host('host_1', 'key_1'),
      host_2: host('host_2', 'key_2'),
      host_3: host('host_3', 'key_2'),
    },
    access: {
      ws_1: { keyIds: ['key_2'], hostIds: ['host_1'] },
      ws_2: { keyIds: ['key_1'], hostIds: ['host_1'] },
      ws_3: { keyIds: ['key_missing'], hostIds: [] },
    },
  }
  await fs.writeFile(store.vaultFile, JSON.stringify(legacy))

  const vault = await store.readVault()
  assert.equal(vault.version, 2)
  assert.deepEqual(vault.access.ws_1, { hostIds: ['host_1', 'host_2', 'host_3'] })
  assert.deepEqual(vault.access.ws_2, { hostIds: ['host_1'] })
  assert.equal(vault.access.ws_3, undefined)
  assert.equal(JSON.parse(await fs.readFile(store.vaultFile, 'utf8')).version, 1)

  await store.update(() => {})
  assert.equal(JSON.parse(await fs.readFile(store.vaultFile, 'utf8')).version, 2)
})

test('stored path traversal is rejected as corrupt', async (t) => {
  const { store } = await makeStore(t)
  await fs.mkdir(store.rootDir, { recursive: true })
  const vault = emptyVault()
  vault.keys.key_bad = {
    ...keyRecord('key_bad', '../outside'),
  }
  await fs.writeFile(store.vaultFile, JSON.stringify(vault))
  await assert.rejects(store.readVault(), (error) => error.code === 'vault_corrupt')
})

test('key files are private, removable, and confined to the keys directory', async (t) => {
  const { store } = await makeStore(t)
  const relativePath = 'keys/key_a-id_ed25519'
  await store.saveKeyFile(relativePath, 'PRIVATE KEY CONTENT\n')
  const absolute = store.resolveKeyPath(relativePath)
  assert.equal(path.dirname(absolute), store.keysDir)
  assert.equal((await fs.stat(absolute)).mode & 0o777, 0o600)
  assert.equal(await fs.readFile(absolute, 'utf8'), 'PRIVATE KEY CONTENT\n')
  await store.deleteKeyFile(relativePath)
  await assert.rejects(fs.stat(absolute), (error) => error.code === 'ENOENT')
  await store.deleteKeyFile(relativePath)

  assert.throws(() => store.resolveKeyPath('../outside'), (error) => error.code === 'vault_corrupt')
  assert.throws(() => store.resolveKeyPath('/etc/passwd'), (error) => error.code === 'vault_corrupt')
  await assert.rejects(
    store.saveKeyFile('keys/../escape', 'x'),
    (error) => error.code === 'vault_corrupt',
  )
})

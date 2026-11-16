import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { createStore } from '../lib/store.js'
import { createSshTargetsTool } from '../lib/tool.js'

const STAMP = '2026-01-01T00:00:00.000Z'

function keyRecord(id, name, filename) {
  return {
    id,
    name,
    filename,
    relativePath: 'keys/' + id + '-' + filename,
    fingerprint: 'SHA256:' + id,
    algorithm: 'ED25519',
    bits: 256,
    comment: '',
    createdAt: STAMP,
    updatedAt: STAMP,
  }
}

function hostRecord(id, label, keyId, overrides = {}) {
  return {
    id,
    label,
    address: '192.0.2.10',
    port: 22,
    username: 'root',
    keyId,
    note: '',
    createdAt: STAMP,
    updatedAt: STAMP,
    ...overrides,
  }
}

async function createFixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ssh-key-vault-tool-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const store = createStore({ rootDir: root })
  const keys = {
    key_1: keyRecord('key_1', 'Alpha', 'id_ed25519'),
    key_2: keyRecord('key_2', 'Beta', 'id_ecdsa'),
    key_3: keyRecord('key_3', 'Gamma', 'id_rsa'),
  }
  const hosts = {
    host_1: hostRecord('host_1', 'Alpha host', 'key_2'),
    host_2: hostRecord('host_2', 'Beta host', 'key_2', { address: '2001:db8::1', port: 2222 }),
  }
  const access = {
    ws_1: { hostIds: ['host_1', 'host_2'] },
    ws_2: { hostIds: [] },
  }
  await store.writeVault({ version: 2, keys, hosts, access })
  for (const key of Object.values(keys)) {
    await store.saveKeyFile(key.relativePath, 'dummy key material')
  }
  const workspaces = [
    {
      id: 'ws_1',
      title: 'website',
      path: path.join(root, 'website'),
      sessionIds: ['s_1'],
    },
    {
      id: 'ws_2',
      title: 'other',
      path: path.join(root, 'other'),
      sessionIds: [],
    },
  ]
  return { store, workspaces, keysDir: store.keysDir }
}

function makeTool(fixture) {
  return createSshTargetsTool({
    keysDir: fixture.keysDir,
    resolveKeyPath: fixture.store.resolveKeyPath,
    readVault: () => fixture.store.readVault(),
    listWorkspaces: () => fixture.workspaces,
  })
}

test('returns granted hosts and absolute key paths', async (t) => {
  const fixture = await createFixture(t)
  const tool = makeTool(fixture)
  const result = await tool.execute({}, {
    agent: { session: { id: 's_1', header: { cwd: fixture.workspaces[0].path } } },
  })

  assert.equal(result.workspace.id, 'ws_1')
  assert.deepEqual(result.hosts.map((host) => host.id).sort(), ['host_1', 'host_2'])
  assert.equal('keysWithoutHost' in result, false)

  const host2 = result.hosts.find((host) => host.id === 'host_2')
  assert.ok(host2)
  assert.equal(host2.port, 2222)
  assert.equal(host2.key.path, path.join(fixture.keysDir, 'key_2-id_ecdsa'))
  assert.equal(host2.key.exists, true)
  assert.match(host2.ssh, /\[2001:db8::1\] -p 2222$/)

  const rendered = tool.output.render({}, result)
  assert.match(rendered[0].text, /ssh -i /)
})

test('does not expand a grant to other hosts sharing the same key', async (t) => {
  const fixture = await createFixture(t)
  await fixture.store.update((vault) => {
    vault.access.ws_1 = { hostIds: ['host_1'] }
  })
  const result = await makeTool(fixture).execute({ workspace: 'website' }, {})
  assert.deepEqual(result.hosts.map((host) => host.id), ['host_1'])
})

test('selects a workspace by title and by absolute path', async (t) => {
  const fixture = await createFixture(t)
  const tool = makeTool(fixture)

  const byTitle = await tool.execute({ workspace: 'other' }, {})
  assert.equal(byTitle.workspace.id, 'ws_2')
  assert.deepEqual(byTitle.hosts, [])
  assert.match(tool.output.render({}, byTitle)[0].text, /No SSH hosts/)

  const byPath = await tool.execute({ workspace: fixture.workspaces[0].path }, {})
  assert.equal(byPath.workspace.id, 'ws_1')
})

test('falls back to the session cwd when the workspace has no session account', async (t) => {
  const fixture = await createFixture(t)
  const tool = makeTool(fixture)
  const result = await tool.execute({}, {
    agent: {
      session: {
        id: 's_2',
        header: { cwd: path.join(fixture.workspaces[1].path, 'src') },
      },
    },
  })
  assert.equal(result.workspace.id, 'ws_2')
})

test('rejects unknown and ambiguous workspace selectors', async (t) => {
  const fixture = await createFixture(t)
  const tool = makeTool(fixture)

  await assert.rejects(tool.execute({ workspace: 'missing' }, {}), /Unknown workspace/)
  await assert.rejects(tool.execute({}, { agent: { session: { id: 's_x' } } }), /Cannot determine/)

  fixture.workspaces.push({
    id: 'ws_3',
    title: 'other',
    path: path.join(fixture.workspaces[0].path, 'nested'),
    sessionIds: [],
  })
  await assert.rejects(tool.execute({ workspace: 'other' }, {}), /ambiguous/)
})

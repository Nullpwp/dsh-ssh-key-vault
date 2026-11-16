import assert from 'node:assert/strict'
import test from 'node:test'
import {
  applyAccess,
  buildState,
  normalizeAccessInput,
  normalizeAddress,
  normalizeHostInput,
  normalizeKeyName,
  normalizeNote,
  normalizePort,
  normalizeUsername,
  removeHostFromAccess,
  sanitizeFilename,
  uniqueKeyName,
} from '../lib/model.js'

function keyRecord(id, name, overrides = {}) {
  const stamp = '2026-01-01T00:00:00.000Z'
  return {
    id,
    name,
    filename: 'id_ed25519',
    relativePath: `keys/${id}-id_ed25519`,
    fingerprint: `SHA256:${'A'.repeat(43)}=`,
    algorithm: 'ED25519',
    bits: 256,
    comment: '',
    createdAt: stamp,
    updatedAt: stamp,
    ...overrides,
  }
}

function hostRecord(id, label, keyId, overrides = {}) {
  const stamp = '2026-01-01T00:00:00.000Z'
  return {
    id,
    label,
    address: '192.0.2.10',
    port: 22,
    username: 'root',
    keyId,
    note: '',
    createdAt: stamp,
    updatedAt: stamp,
    ...overrides,
  }
}

function vaultFixture() {
  return {
    version: 2,
    keys: {
      key_1: keyRecord('key_1', 'Alpha'),
      key_2: keyRecord('key_2', 'Beta', { fingerprint: 'SHA256:B' }),
      key_3: keyRecord('key_3', 'Gamma', { fingerprint: 'SHA256:C' }),
    },
    hosts: {
      host_1: hostRecord('host_1', 'Host one', 'key_2'),
      host_2: hostRecord('host_2', 'Host two', 'key_1'),
      host_3: hostRecord('host_3', 'Host three', 'key_3'),
    },
    access: {
      'ws-1': { hostIds: ['host_1', 'host_3'] },
      'ws-2': { hostIds: [] },
    },
  }
}

test('sanitizeFilename keeps only safe basename characters and trims length', () => {
  assert.equal(sanitizeFilename('../../etc/passwd'), 'passwd')
  assert.equal(sanitizeFilename('C:\\Users\\me\\id_ed25519'), 'id_ed25519')
  assert.equal(sanitizeFilename('.hidden'), 'hidden')
  assert.equal(sanitizeFilename('id rsa; rm -rf'), 'idrsarm-rf')
  assert.equal(sanitizeFilename(''), 'ssh_private_key')
  assert.equal(sanitizeFilename('.'.repeat(10)), 'ssh_private_key')
  assert.equal(sanitizeFilename('a'.repeat(200)).length, 96)
})

test('normalizeKeyName enforces length, control characters, and case-insensitive uniqueness', () => {
  const keys = { key_1: keyRecord('key_1', 'Production Server') }
  assert.equal(normalizeKeyName('  Staging  ', keys), 'Staging')
  assert.throws(() => normalizeKeyName('production server', keys), (error) => error.status === 409)
  assert.equal(normalizeKeyName('Production Server', keys, 'key_1'), 'Production Server')
  assert.throws(() => normalizeKeyName('', keys), (error) => error.status === 400)
  assert.throws(() => normalizeKeyName('bad\nname', keys), (error) => error.status === 400)
  assert.throws(() => normalizeKeyName('x'.repeat(81), keys), (error) => error.status === 400)
  assert.equal(uniqueKeyName('id_ed25519', { key_1: keyRecord('key_1', 'id_ed25519') }), 'id_ed25519 (2)')
})

test('normalizeAddress accepts IPv4, hostnames, bracketed and bare IPv6', () => {
  for (const value of ['192.0.2.1', 'example.com', 'web-01.internal', 'localhost', '[2001:db8::1]', '2001:db8::1']) {
    assert.equal(normalizeAddress(value), value)
  }
  for (const value of ['', 'bad host', 'http://example.com', '999.1.1.1', 'user@example.com', 'a'.repeat(256)]) {
    assert.throws(() => normalizeAddress(value), (error) => error.status === 400, value)
  }
})

test('normalizePort and normalizeUsername reject invalid host form values', () => {
  assert.equal(normalizePort('22'), 22)
  assert.equal(normalizePort(65535), 65535)
  for (const value of [0, 65536, '22x', '1.5', null, true]) {
    assert.throws(() => normalizePort(value), (error) => error.status === 400)
  }
  assert.equal(normalizeUsername('deploy-bot_1'), 'deploy-bot_1')
  for (const value of ['', 'root user', 'root;id', 'a'.repeat(65)]) {
    assert.throws(() => normalizeUsername(value), (error) => error.status === 400)
  }
})

test('normalizeHostInput validates uniqueness, key reference, and note', () => {
  const vault = vaultFixture()
  const valid = normalizeHostInput(
    {
      label: ' New host ',
      address: '203.0.113.9',
      port: '2222',
      username: 'deploy',
      keyId: 'key_1',
      note: '  staging\nbox  ',
    },
    vault,
  )
  assert.deepEqual(valid, {
    label: 'New host',
    address: '203.0.113.9',
    port: 2222,
    username: 'deploy',
    keyId: 'key_1',
    note: 'staging\nbox',
  })
  assert.throws(
    () => normalizeHostInput({ ...valid, label: 'host one' }, vault),
    (error) => error.status === 409,
  )
  assert.throws(
    () => normalizeHostInput({ ...valid, keyId: 'key_missing' }, vault),
    (error) => error.status === 400,
  )
  assert.throws(
    () => normalizeHostInput({ ...valid }, vault, 'host_missing'),
    (error) => error.status === 404,
  )
  assert.equal(normalizeNote('a'.repeat(500)).length, 500)
  assert.throws(() => normalizeNote('a'.repeat(501)), (error) => error.status === 400)
})

test('buildState filters unknown workspaces and never exposes storage paths', () => {
  const state = buildState(vaultFixture(), [
    { id: 'ws-1', title: 'Workspace one', path: '/srv/one' },
    { id: 'ws-2', title: 'Workspace two', path: '/srv/two' },
    { id: '', title: 'broken', path: '/srv/none' },
  ])
  assert.deepEqual(Object.keys(state.access), ['ws-1', 'ws-2'])
  assert.deepEqual(state.access['ws-1'], { hostIds: ['host_1', 'host_3'] })
  assert.deepEqual(state.access['ws-2'], { hostIds: [] })
  assert.equal(state.stats.keys, 3)
  assert.equal(state.stats.hosts, 3)
  assert.equal(state.stats.grantedWorkspaces, 1)
  assert.deepEqual(state.keys.find((key) => key.id === 'key_1').authorizedWorkspaceIds, [])
  assert.deepEqual(state.keys.find((key) => key.id === 'key_2').authorizedWorkspaceIds, ['ws-1'])
  assert.deepEqual(state.keys.find((key) => key.id === 'key_3').authorizedWorkspaceIds, ['ws-1'])
  assert.deepEqual(state.hosts.find((host) => host.id === 'host_1').authorizedWorkspaceIds, ['ws-1'])
  assert.deepEqual(state.hosts.find((host) => host.id === 'host_2').authorizedWorkspaceIds, [])
  const serialized = JSON.stringify(state)
  assert.equal(serialized.includes('relativePath'), false)
  assert.equal(serialized.includes('PRIVATE KEY'), false)
})

test('normalizeAccessInput accepts host grants and rejects legacy keyIds', () => {
  const vault = vaultFixture()
  const result = normalizeAccessInput(vault, {
    workspaceId: 'ws-1',
    hostIds: ['host_1', 'host_1', 'host_3'],
  })
  assert.deepEqual(result, { workspaceId: 'ws-1', hostIds: ['host_1', 'host_3'] })
  assert.throws(
    () => normalizeAccessInput(vault, { workspaceId: 'ws-1', hostIds: ['host_missing'] }),
    (error) => error.status === 400,
  )
  assert.throws(
    () => normalizeAccessInput(vault, { workspaceId: 'ws-1', hostIds: 'host_1' }),
    (error) => error.status === 400,
  )
  assert.throws(
    () => normalizeAccessInput(vault, { workspaceId: 'ws-1', hostIds: [], keyIds: ['key_1'] }),
    (error) => error.status === 400 && error.code === 'invalid_access',
  )
})

test('applyAccess replaces host grants and removes empty entries', () => {
  const vault = vaultFixture()
  applyAccess(vault, 'ws-1', ['host_2'])
  assert.deepEqual(vault.access['ws-1'], { hostIds: ['host_2'] })
  applyAccess(vault, 'ws-1', [])
  assert.equal(vault.access['ws-1'], undefined)
})

test('removeHostFromAccess prunes grants and empty entries', () => {
  const vault = vaultFixture()
  removeHostFromAccess(vault, 'host_1')
  assert.deepEqual(vault.access['ws-1'], { hostIds: ['host_3'] })
  removeHostFromAccess(vault, 'host_3')
  assert.equal(vault.access['ws-1'], undefined)
})

test('rebinding a host key changes the workspace key without changing the host grant', () => {
  const vault = vaultFixture()
  vault.hosts.host_1.keyId = 'key_1'
  const state = buildState(vault, [{ id: 'ws-1', title: 'Workspace one', path: '/srv/one' }])
  assert.deepEqual(state.access['ws-1'], { hostIds: ['host_1', 'host_3'] })
  assert.deepEqual(state.keys.find((key) => key.id === 'key_1').authorizedWorkspaceIds, ['ws-1'])
  assert.deepEqual(state.keys.find((key) => key.id === 'key_2').authorizedWorkspaceIds, [])
  assert.deepEqual(state.keys.find((key) => key.id === 'key_3').authorizedWorkspaceIds, ['ws-1'])
})

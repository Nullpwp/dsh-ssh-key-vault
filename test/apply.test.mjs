import assert from 'node:assert/strict'
import test from 'node:test'
import { apply } from '../index.js'

test('apply registers the Agent tool when the tools service exists', () => {
  let registered
  const ctx = {
    webServer: { register: () => () => {} },
    workspaceRegistry: { list: () => [] },
    effect: (fn) => fn(),
    inject: (deps, callback) => {
      if (deps.includes('tools')) {
        callback({ tools: { register: (definition) => { registered = definition } } })
      }
    },
  }

  apply(ctx)

  assert.equal(registered.name, 'ssh_targets')
})

import { createStore } from './lib/store.js'
import { dispatch, ROUTE_PATH } from './lib/http.js'
import { registerSshTargets } from './lib/tool.js'

export const name = 'ssh-key-vault'
export const inject = ['webServer', 'workspaceRegistry']

/**
 * Host half of the SSH key vault: same-origin JSON API over the local vault files.
 * The browser half is declared through package.json `dsh.client` and `client.js`.
 */
export function apply(ctx, config = {}) {
  const configured = typeof config?.dataDir === 'string' ? config.dataDir.trim() : ''
  const store = createStore(configured ? { rootDir: configured } : {})
  ctx.effect(
    () =>
      ctx.webServer.register({
        kind: 'prefix',
        path: ROUTE_PATH,
        handler: (req, res) => dispatch(ctx, store, req, res),
      }),
    'ssh-key-vault: HTTP route',
  )

  const surface = {
    keysDir: store.keysDir,
    resolveKeyPath: store.resolveKeyPath,
    readVault: () => store.readVault(),
    listWorkspaces: () => {
      const registry = ctx.workspaceRegistry
      if (!registry || typeof registry.list !== 'function') return []
      const list = registry.list()
      return Array.isArray(list) ? list : []
    },
  }

  // Optional: the Web profile mounts @deepseek-ai/dsh-tools at the Host, which
  // makes this a global tool visible to every agent. ctx.inject keeps the HTTP
  // half working in compositions that do not mount a tools registry.
  ctx.inject(['tools'], (toolCtx) => {
    registerSshTargets(toolCtx, surface)
  })
}

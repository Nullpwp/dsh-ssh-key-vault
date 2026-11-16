/** Errors that carry an HTTP status and a stable machine-readable code. */
export class VaultError extends Error {
  constructor(status, message, code) {
    super(message)
    this.name = 'VaultError'
    this.status = status
    this.code = code
  }
}

/**
 * Build one API error.
 * @param {number} status HTTP status.
 * @param {string} message user-facing message (never contains secret material).
 * @param {string} [code] stable error code.
 */
export function vaultError(status, message, code) {
  return new VaultError(status, message, code)
}

/** True for values that are plain JSON objects (not null, not arrays). */
export function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

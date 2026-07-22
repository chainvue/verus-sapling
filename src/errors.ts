/**
 * Errors for the shielded package.
 *
 * These extend a LOCAL base (`Error`), NOT @chainvue/verus-sdk's `VerusError`:
 * importing anything from the SDK pulls its Node-bundled `dist/bundle.js`
 * (@bitgo/utxo-lib + `crypto`/`buffer`/…) into the browser bundle. To stay
 * browser-safe the base is local, but it mirrors `VerusError`'s shape — a
 * machine-readable `.code` plus `.name` — so callers can branch on those.
 */

/** Base class for all shielded-package errors. */
export class ShieldedError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
    this.name = 'ShieldedError';
  }
}

/** Thrown when the shielded input contract is violated (bad amount, memo, address). */
export class ShieldedInputError extends ShieldedError {
  constructor(message: string) {
    super('ERR_SHIELDED_INPUT', message);
    this.name = 'ShieldedInputError';
  }
}

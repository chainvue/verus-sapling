/**
 * Errors for the shielded package. We extend @chainvue/verus-sdk's `VerusError`
 * so consumers can keep a single typed catch surface across transparent and
 * shielded signing.
 */

import { VerusError } from '@chainvue/verus-sdk';

/** Thrown by any build/sign entry point while the Sapling prover is not wired. */
export class ShieldedNotImplementedError extends VerusError {
  constructor(what: string) {
    super(
      'ERR_SHIELDED_NOT_IMPLEMENTED',
      `${what} is not implemented yet: no SaplingBackend (WASM prover) is wired. ` +
        `This package is a scaffold — see README.md.`,
    );
    this.name = 'ShieldedNotImplementedError';
  }
}

/** Thrown when the shielded input contract is violated (bad amount, memo, address). */
export class ShieldedInputError extends VerusError {
  constructor(message: string) {
    super('ERR_SHIELDED_INPUT', message);
    this.name = 'ShieldedInputError';
  }
}

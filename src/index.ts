/**
 * @chainvue/verus-sapling
 *
 * Offline signing of Verus shielded (Sapling) transactions — t→z, z→z, z→t,
 * with memo. Companion to @chainvue/verus-sdk: builds and signs bytes; the
 * consumer broadcasts. No full node on the signing host (though z→z / z→t
 * require witness/anchor data from a Verus lightwalletd/Electrum backend).
 *
 * STATUS: working. The Sapling prover (Rust → wasm, `crate/`) builds and signs
 * all three flows (t→z, z→z, z→t, with memo), proven accepted on Verus testnet.
 * The wasm builders are exposed via `wasm.ts` (`shieldT2z` / `spendShielded` /
 * `detectNotes`); the lightwalletd-driven typed orchestration lives in
 * `wallet.ts` (`detectNotes` — client-side note detection replacing
 * `z_listunspent` — and `buildShieldedSpend`).
 *
 * The older `shield` / `sendShielded` entry points below front a `SaplingBackend`
 * abstraction that predates the concrete wasm ABI; they throw
 * `ShieldedNotImplementedError` unless a backend is supplied. Prefer the
 * `wallet.ts` orchestration + `wasm.ts` builders, which are the proven path.
 */

import { CONSENSUS_BRANCH_ID, isRAddress } from '@chainvue/verus-sdk';

import type { SaplingBackend, SaplingBuildRequest } from './backend.js';
import { ShieldedInputError, ShieldedNotImplementedError } from './errors.js';
import {
  MEMO_MAX_BYTES,
  type Memo,
  type SendShieldedParams,
  type ShieldParams,
  type ShieldedOutput,
  type SignedShieldedTx,
  type TransparentOutput,
} from './types.js';

export * from './types.js';
export * from './errors.js';
export type { SaplingBackend, SaplingBuildRequest } from './backend.js';

// Pure helpers (dependency-free, browser-safe).
export * from './parse.js';
export { CONSENSUS_BRANCH_ID, parseSats, toSafeNumber } from './money.js';
export { bytesToHex, hexToBytes, reverseBytes } from './hex.js';
export { decodeSaplingAddress, saplingAddressToHex } from './zaddr.js';

// wasm prover loaders + low-level builders (init once, then call).
export {
  initSapling,
  shieldT2z,
  spendShielded,
  detectNotes as detectNotesWasm,
  readNote,
  type SaplingParams,
  type DetectedNoteRaw,
  type ReadNoteResult,
} from './wasm.js';

// Shielded wallet orchestration (transport- and prover-agnostic).
export {
  detectNotes,
  buildShieldedSpend,
  type DetectKey,
  type DetectProver,
  type SpendProver,
  type DetectNotesParams,
  type SpendableNote,
  type BuildShieldedSpendParams,
  type ShieldedRecipient,
  type TransparentRecipient,
} from './wallet.js';

// lightwalletd transport contract + compact types (TYPE-ONLY: no @grpc/grpc-js
// is pulled into the browser bundle from the package root). The concrete Node
// gRPC client is a separate entry: `@chainvue/verus-sapling/lightwalletd`.
export type {
  LightwalletdTransport,
  TreeState,
  CompactOutput,
  CompactTx,
  CompactBlock,
  LightdInfo,
} from './lightwalletd.js';

const TESTNET_SAPLING_PREFIX = 'ztestsapling';
const MAINNET_SAPLING_PREFIX = 'zs';

/** Options common to the build entry points. */
export interface BuildOptions {
  /** Prover implementation. If omitted, the call throws ShieldedNotImplementedError. */
  readonly backend?: SaplingBackend;
}

// ---- validation (money invariant lives here) --------------------------------

function assertSats(label: string, sats: bigint, { allowZero = false } = {}): void {
  if (typeof sats !== 'bigint') {
    throw new ShieldedInputError(`${label} must be a bigint (satoshis), got ${typeof sats}`);
  }
  if (sats < 0n || (!allowZero && sats === 0n)) {
    throw new ShieldedInputError(`${label} must be ${allowZero ? '>= 0' : '> 0'}, got ${sats}`);
  }
}

function assertSaplingAddress(label: string, address: string): void {
  if (
    typeof address !== 'string' ||
    !(address.startsWith(MAINNET_SAPLING_PREFIX) || address.startsWith(TESTNET_SAPLING_PREFIX))
  ) {
    throw new ShieldedInputError(`${label} must be a Sapling (zs / ztestsapling) address, got "${address}"`);
  }
}

function assertTransparentAddress(label: string, address: string): void {
  if (!isRAddress(address)) {
    throw new ShieldedInputError(`${label} must be a transparent R-address, got "${address}"`);
  }
}

function memoByteLength(memo: Memo): number {
  return typeof memo === 'string' ? new TextEncoder().encode(memo).length : memo.length;
}

function assertMemo(memo: Memo | undefined): void {
  if (memo === undefined) return;
  const len = memoByteLength(memo);
  if (len > MEMO_MAX_BYTES) {
    throw new ShieldedInputError(`memo is ${len} bytes; max is ${MEMO_MAX_BYTES}`);
  }
}

function validateShieldedOutputs(outputs: readonly ShieldedOutput[]): void {
  for (const [i, out] of outputs.entries()) {
    assertSaplingAddress(`shieldedOutputs[${i}].address`, out.address);
    assertSats(`shieldedOutputs[${i}].valueSats`, out.valueSats);
    assertMemo(out.memo);
  }
}

function validateTransparentOutputs(outputs: readonly TransparentOutput[]): void {
  for (const [i, out] of outputs.entries()) {
    assertTransparentAddress(`transparentOutputs[${i}].address`, out.address);
    assertSats(`transparentOutputs[${i}].valueSats`, out.valueSats);
  }
}

// ---- public API -------------------------------------------------------------

/**
 * Build and sign a t→z shielding transaction: transparent inputs → shielded
 * output(s) (with memo), transparent change. Requires no note-tree witness.
 */
export async function shield(params: ShieldParams, opts: BuildOptions = {}): Promise<SignedShieldedTx> {
  if (params.inputs.length === 0) throw new ShieldedInputError('inputs must not be empty');
  if (params.transparentKeys.length === 0) throw new ShieldedInputError('transparentKeys must not be empty');
  if (params.shieldedOutputs.length === 0) throw new ShieldedInputError('shieldedOutputs must not be empty');
  validateShieldedOutputs(params.shieldedOutputs);
  assertTransparentAddress('changeAddress', params.changeAddress);
  assertSats('feeSats', params.feeSats, { allowZero: true });

  const request: SaplingBuildRequest = {
    kind: 'shield',
    branchId: params.branchId ?? CONSENSUS_BRANCH_ID,
    expiryHeight: params.expiryHeight,
    feeSats: params.feeSats,
    payload: params,
  };
  return dispatch('shield', request, opts.backend);
}

/**
 * Build and sign a z→z / z→t transaction: spend shielded notes to shielded
 * and/or transparent outputs. Each spent note needs its witness + anchor
 * (obtained from a Verus lightwalletd/Electrum backend).
 */
export async function sendShielded(
  params: SendShieldedParams,
  opts: BuildOptions = {},
): Promise<SignedShieldedTx> {
  if (params.shieldedInputs.length === 0) throw new ShieldedInputError('shieldedInputs must not be empty');
  const shieldedOutputs = params.shieldedOutputs ?? [];
  const transparentOutputs = params.transparentOutputs ?? [];
  if (shieldedOutputs.length === 0 && transparentOutputs.length === 0) {
    throw new ShieldedInputError('at least one shielded or transparent output is required');
  }
  validateShieldedOutputs(shieldedOutputs);
  validateTransparentOutputs(transparentOutputs);
  if (params.changeAddress !== undefined) assertSaplingAddress('changeAddress', params.changeAddress);
  assertSats('feeSats', params.feeSats, { allowZero: true });

  for (const [i, spend] of params.shieldedInputs.entries()) {
    assertSats(`shieldedInputs[${i}].note.valueSats`, spend.note.valueSats);
    if (spend.position < 0n) {
      throw new ShieldedInputError(`shieldedInputs[${i}].position must be >= 0`);
    }
    if (spend.merklePath.length === 0) {
      throw new ShieldedInputError(`shieldedInputs[${i}].merklePath must not be empty (needs the note witness)`);
    }
  }

  const request: SaplingBuildRequest = {
    kind: 'send',
    branchId: params.branchId ?? CONSENSUS_BRANCH_ID,
    expiryHeight: params.expiryHeight,
    feeSats: params.feeSats,
    payload: params,
  };
  return dispatch('sendShielded', request, opts.backend);
}

async function dispatch(
  fn: string,
  request: SaplingBuildRequest,
  backend: SaplingBackend | undefined,
): Promise<SignedShieldedTx> {
  if (!backend) throw new ShieldedNotImplementedError(fn);
  if (!backend.isReady()) {
    throw new ShieldedInputError('SaplingBackend is not ready (proving parameters not loaded)');
  }
  return backend.buildAndSign(request);
}

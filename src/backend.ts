/**
 * The WASM prover boundary.
 *
 * The TypeScript layer owns the input contract, the money invariant, and
 * validation. The zk-SNARK proving, RedJubjub spend-auth + binding signatures,
 * note encryption (memo), and the final Sapling v4 serialization all live
 * behind this interface — implemented by a stock Zcash Sapling Rust prover
 * compiled to WASM, with the Verus consensus branch id injected.
 *
 * Keeping this an interface (rather than importing a concrete WASM module) lets
 * the TS package compile, type-check, and unit-test its validation logic with no
 * WASM present, and lets us swap prover implementations (adapted WebZjs /
 * ChainSafe zcash-wasm / librustzcash→WASM) without touching the public API.
 */

import type { SignedShieldedTx } from './types.js';

/**
 * Fully-marshalled, serializable build request handed to the WASM prover. The
 * exact field encoding is finalized against the chosen prover's ABI during
 * Phase 1 (t→z) and Phase 2 (z→z / z→t); this type is the boundary contract,
 * not the wire format.
 */
export interface SaplingBuildRequest {
  readonly kind: 'shield' | 'send';
  /** Consensus branch id (0x76b809bb for Verus). */
  readonly branchId: number;
  readonly expiryHeight: number;
  readonly feeSats: bigint;
  /** Opaque, prover-specific marshalled inputs/outputs. */
  readonly payload: unknown;
}

/**
 * A Sapling prover implementation. A backend must load its proving parameters
 * (sapling-spend ~47MB + sapling-output ~3.5MB — byte-identical to Zcash's)
 * before `buildAndSign` is called; how it obtains them (bundled vs fetched) is
 * the implementation's concern and a documented Phase-0 decision.
 */
export interface SaplingBackend {
  /** True once proving parameters are loaded and the prover is ready. */
  isReady(): boolean;
  /** Build, prove, sign, and serialize. Returns the broadcastable transaction. */
  buildAndSign(request: SaplingBuildRequest): Promise<SignedShieldedTx>;
}

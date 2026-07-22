/**
 * @chainvue/verus-sapling
 *
 * Offline signing of Verus shielded (Sapling) transactions — t→z, z→z, z→t,
 * with memo — plus client-side note detection and memo reading. Companion to
 * @chainvue/verus-sdk: it builds and signs bytes; the consumer broadcasts. No
 * full node on the signing host (z→z / z→t need witness data from a Verus
 * lightwalletd, reached through a `LightwalletdTransport`).
 *
 * Verus shielded = stock Zcash Sapling (stock circuit, byte-identical MPC
 * params, consensus branch id 0x76b809bb).
 *
 * The API:
 *  - `initSapling` + the wasm builders (`shieldT2z` / `spendShielded` /
 *    `detectNotesWasm` / `readNote`) — the prover boundary (`wasm.ts`).
 *  - the lightwalletd-driven orchestration (`detectNotes`, `buildShieldedSpend`)
 *    over a `LightwalletdTransport` (`wallet.ts`).
 *  - pure helpers: v4/tree parsers, `parseSats`/`toSafeNumber`, hex, `zs` decode.
 *
 * Entry points: the package root is browser-safe and pulls in no `@grpc/grpc-js`.
 * Browser consumers also import `@chainvue/verus-sapling/browser` (gRPC-web
 * client + Web Worker prover); Node consumers import
 * `@chainvue/verus-sapling/lightwalletd` (the gRPC client).
 */

export * from './types.js';
export * from './errors.js';

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

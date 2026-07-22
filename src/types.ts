/**
 * Shared domain vocabulary for the shielded package.
 *
 * Money invariant (inherited from @chainvue/verus-sdk): ALL satoshi amounts are
 * `bigint`, end to end — never `number`. The only checked crossing into a
 * float64 boundary is `toSafeNumber` (see `money.ts`).
 *
 * The concrete request/result shapes live with the functions that use them:
 * `SpendableNote` / `ShieldedRecipient` / `BuildShieldedSpendParams` in
 * `wallet.ts`, `SaplingParams` / `ReadNoteResult` in `wasm.ts`.
 */

/** Sapling payment address, Bech32: `zs`-prefixed (mainnet) / `ztestsapling` (testnet). */
export type SaplingAddress = string;

/** Transparent Verus address (R-address, P2PKH). */
export type TransparentAddress = string;

/**
 * Sapling extended spending key (ZIP-32) as 169-byte hex — the full spend
 * authority. Same trust surface as a transparent WIF: it is present on the
 * signing host; callers must protect it accordingly.
 */
export type SaplingSpendingKey = string;

/**
 * A Sapling memo. A `string` is UTF-8-encoded then zero-padded to 512 bytes; a
 * hex string via a recipient's `memoHex` carries raw bytes verbatim (for
 * structured/binary memos). Max 512 bytes either way.
 */
export type Memo = string;

/** Max memo size in bytes (Zcash/Verus Sapling note-plaintext memo field). */
export const MEMO_MAX_BYTES = 512;

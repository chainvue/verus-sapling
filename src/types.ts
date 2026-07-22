/**
 * Input contract for offline Verus shielded (Sapling) transaction signing.
 *
 * Money invariant (inherited from @chainvue/verus-sdk): ALL satoshi amounts are
 * `bigint`, end to end. Never `number`. The only checked crossing into a
 * float64 boundary is @chainvue/verus-sdk's `toSafeNumber`.
 *
 * Verus shielded is stock Zcash Sapling (confirmed: stock librustzcash circuit,
 * byte-identical MPC params, branch id 0x76b809bb). The only Verus-specific
 * value threaded through the shielded path is the consensus branch id, which is
 * `CONSENSUS_BRANCH_ID` in @chainvue/verus-sdk.
 */

import type { Utxo } from '@chainvue/verus-sdk';

/** Sapling payment address, Bech32, `zs`-prefixed (mainnet) / `ztestsapling` (testnet). */
export type SaplingAddress = string;

/** Transparent Verus address (R-address, P2PKH). */
export type TransparentAddress = string;

/**
 * Sapling extended spending key (ZIP-32), `secret-extended-key-...`.
 * NOTE: this is the full spend authority — same trust surface as a transparent
 * WIF. It is present on the signing host; callers must protect it accordingly.
 */
export type SaplingSpendingKey = string;

/**
 * A Sapling memo. Up to 512 bytes. A `string` is UTF-8 encoded then
 * zero-padded to 512 bytes by the prover; a `Uint8Array` is used verbatim and
 * must be <= 512 bytes. Omitted → the canonical "no memo" (0xF6 ..) encoding.
 */
export type Memo = string | Uint8Array;

/** Max memo size in bytes (Zcash/Verus Sapling note plaintext memo field). */
export const MEMO_MAX_BYTES = 512;

/** A shielded output: pay `valueSats` to a `zs` address, optionally with a memo. */
export interface ShieldedOutput {
  readonly address: SaplingAddress;
  readonly valueSats: bigint;
  readonly memo?: Memo;
}

/** A transparent output: pay `valueSats` to an R-address. */
export interface TransparentOutput {
  readonly address: TransparentAddress;
  readonly valueSats: bigint;
}

/**
 * A spendable Sapling note plus the witness data required to prove membership
 * in the note commitment tree.
 *
 * This is the part that CANNOT be produced offline: `position`, `merklePath`,
 * and `anchor` come from a chain-scanning service (Verus lightwalletd
 * `GetTreeState` / compact blocks, or a full node). The signing host stays
 * node-free but depends on that service to obtain these fields.
 */
export interface ShieldedSpendInput {
  /** Note plaintext / components sufficient for the prover to reconstruct the note. */
  readonly note: SaplingNote;
  /** Full spending authority for this note. */
  readonly spendingKey: SaplingSpendingKey;
  /** 0-based position of the note commitment in the tree. */
  readonly position: bigint;
  /** Authentication path (sibling hashes) from the note commitment to the anchor. */
  readonly merklePath: readonly Uint8Array[];
  /** The note commitment tree root this spend is proven against. Hex or bytes. */
  readonly anchor: string | Uint8Array;
}

/** Minimal Sapling note description. Exact shape finalized against the prover ABI. */
export interface SaplingNote {
  /** Diversified recipient address the note was sent to. */
  readonly address: SaplingAddress;
  readonly valueSats: bigint;
  /** Note random commitment trapdoor / rcm (bytes). */
  readonly rcm: Uint8Array;
}

/** Common fields for every shielded build request. */
interface BaseBuildParams {
  /** Absolute fee in satoshis (bigint). */
  readonly feeSats: bigint;
  /** nExpiryHeight for the Sapling v4 transaction. */
  readonly expiryHeight: number;
  /**
   * Consensus branch id for the ZIP-243 sighash / binding signature.
   * Defaults to @chainvue/verus-sdk's `CONSENSUS_BRANCH_ID` (0x76b809bb).
   */
  readonly branchId?: number;
}

/**
 * t→z (shielding): transparent inputs → shielded output(s), optional
 * transparent change. Needs NO note-commitment-tree witness — the true
 * "sign a private transaction with zero extra backend" case.
 */
export interface ShieldParams extends BaseBuildParams {
  /** Transparent UTXOs to spend (from @chainvue/verus-sdk `Utxo`). */
  readonly inputs: readonly Utxo[];
  /** WIF(s) authorizing the transparent inputs. */
  readonly transparentKeys: readonly string[];
  /** Shielded recipients (memo lives here). */
  readonly shieldedOutputs: readonly ShieldedOutput[];
  /** Transparent change address for any remainder. */
  readonly changeAddress: TransparentAddress;
}

/**
 * z→z and/or z→t: spend shielded notes to shielded and/or transparent outputs.
 * Requires witness + anchor per spent note (see `ShieldedSpendInput`).
 */
export interface SendShieldedParams extends BaseBuildParams {
  readonly shieldedInputs: readonly ShieldedSpendInput[];
  readonly shieldedOutputs?: readonly ShieldedOutput[];
  readonly transparentOutputs?: readonly TransparentOutput[];
  /** Optional shielded change address; else change returns to a spend's address. */
  readonly changeAddress?: SaplingAddress;
}

/** Result of a build+sign: the raw signed transaction, ready to broadcast. */
export interface SignedShieldedTx {
  /** Full signed transaction hex (Sapling v4, shielded bundle populated). */
  readonly hex: string;
  /** Transaction id (little-endian hex), if the backend computes it. */
  readonly txid?: string;
}

/**
 * Shielded wallet orchestration — the typed home for the flows proven end to end
 * on Verus testnet, sourcing ALL chain data from lightwalletd (no full node):
 *
 *  - `detectNotes`       — find the wallet's own notes by trial-decrypting the
 *                          compact blocks of a height range, and drop any already
 *                          spent within that range. Replaces `z_listunspent`.
 *  - `buildShieldedSpend`— assemble and prove a z→z / z→t spend of one detected
 *                          note (fetches the note's creating output, tree state,
 *                          and block cmus, then calls the prover).
 *
 * This module is transport- and prover-agnostic: it depends only on the
 * `LightwalletdTransport` interface and a prover callback. That keeps the money
 * invariant and marshalling here (bigint sats, checked crossings) while letting
 * the caller decide where the wasm runs — directly in Node, or in a Web Worker
 * in the browser (spend proving is ~5–20 s; detection is milliseconds).
 *
 * Proven reference: the fully-lightwalletd-sourced z→z (txid 07e3b38e…f996) and
 * the note-detection cross-check whose predicted nullifier matched that spend's
 * on-chain nullifier byte-for-byte.
 */

import { ShieldedInputError } from './errors.js';
import { bytesToHex, reverseBytes } from './hex.js';
import type { LightwalletdTransport } from './lightwalletd.js';
import { CONSENSUS_BRANCH_ID, toSafeNumber } from './money.js';

/** Enforce the money invariant at the boundary: a `bigint`, and >= 0. */
function assertSats(label: string, sats: bigint): void {
  if (typeof sats !== 'bigint') {
    throw new ShieldedInputError(`${label} must be a bigint (satoshis), got ${typeof sats}`);
  }
  if (sats < 0n) throw new ShieldedInputError(`${label} must be >= 0, got ${sats}`);
}
import { parseSaplingOutput, parseTreeState, type ParsedTreeState } from './parse.js';
import type { DetectedNoteRaw } from './wasm.js';
import { saplingAddressToHex } from './zaddr.js';

const toHex = (b: Uint8Array): string => bytesToHex(b);

/** A viewing/spending key for detection: an extended spending key (169-byte hex)
 *  or a diversifiable full viewing key (128-byte hex, read-only). */
export type DetectKey = { extskHex: string } | { dfvkHex: string };

/** Trial-decrypt the compact outputs (read path). Returns raw detected notes. */
export type DetectProver = (specJson: string) => DetectedNoteRaw[] | Promise<DetectedNoteRaw[]>;

/** Prove + sign a shielded spend. Returns the signed transaction hex. The caller
 *  binds the proving parameters (and may run this in a Web Worker). */
export type SpendProver = (specJson: string) => string | Promise<string>;

export interface DetectNotesParams {
  readonly key: DetectKey;
  /** First block to scan (inclusive). Use the wallet's birthday height. */
  readonly fromHeight: number;
  /** Last block to scan (inclusive). Defaults to the chain tip. */
  readonly toHeight?: number;
}

/** A spendable note the wallet owns, with everything a later spend needs. */
export interface SpendableNote {
  /** Creating transaction id (display/big-endian hex). */
  readonly txid: string;
  readonly outputIndex: number;
  readonly height: number;
  /** 0-based leaf position in the note-commitment tree. */
  readonly position: number;
  readonly valueSats: bigint;
  /** 43-byte Sapling payment address the note pays to (hex). */
  readonly recipientHex: string;
  /** Note nullifier (hex) — its appearance in a block marks the note spent. */
  readonly nullifierHex: string;
}

/**
 * Find the wallet's own notes in `[fromHeight, toHeight]` by trial-decryption,
 * excluding notes whose nullifier is spent within the same range.
 *
 * Sources everything from `transport`: the tree state before the range (for
 * absolute positions) plus every compact block in the range. `prover` is the
 * wasm `detectNotes` (cheap; may run on the main thread).
 *
 * Note: spends are only observed within the scanned range. Scan from the wallet
 * birthday to the tip for a complete unspent set.
 */
export async function detectNotes(
  transport: LightwalletdTransport,
  prover: DetectProver,
  params: DetectNotesParams,
): Promise<SpendableNote[]> {
  const toHeight = params.toHeight ?? (await transport.getLatestHeight());
  if (toHeight < params.fromHeight) return [];

  const treeState = await transport.getTreeState(params.fromHeight - 1);
  const tree = parseTreeState(treeState.tree);

  const outputs: Array<{
    height: number;
    tx_index: number;
    output_index: number;
    cmu: string;
    epk: string;
    ciphertext: string;
  }> = [];
  const spentNullifiers = new Set<string>();
  const txidByKey = new Map<string, string>(); // `${height}:${tx_index}` -> display txid

  for await (const block of transport.getBlockRange(params.fromHeight, toHeight)) {
    const height = Number(block.height);
    for (const tx of block.vtx) {
      const txIndex = Number(tx.index);
      txidByKey.set(`${height}:${txIndex}`, bytesToHex(reverseBytes(tx.hash)));
      for (const s of tx.spends) spentNullifiers.add(toHex(s.nf));
      tx.outputs.forEach((o, outputIndex) => {
        outputs.push({
          height,
          tx_index: txIndex,
          output_index: outputIndex,
          cmu: toHex(o.cmu),
          epk: toHex(o.epk),
          ciphertext: toHex(o.ciphertext),
        });
      });
    }
  }

  const keyField =
    'extskHex' in params.key
      ? { extsk_hex: params.key.extskHex }
      : { dfvk_hex: params.key.dfvkHex };
  const spec = JSON.stringify({ ...keyField, tree, outputs });
  const detected = await prover(spec);

  return detected
    .filter((n) => !spentNullifiers.has(n.nullifier_hex))
    .map((n) => {
      const txid = txidByKey.get(`${n.height}:${n.tx_index}`);
      if (txid === undefined) {
        throw new ShieldedInputError(
          `detected note at ${n.height}:${n.tx_index} has no matching block tx (transport/scan mismatch)`,
        );
      }
      // Compact-output values are server-controlled and unauthenticated. Guard the
      // float64 crossing (JSON number) so an out-of-range value throws instead of
      // silently rounding — the money invariant, at this inbound boundary.
      if (!Number.isSafeInteger(n.value)) {
        throw new ShieldedInputError(`detected note value ${n.value} is not a safe integer`);
      }
      return {
        txid,
        outputIndex: n.output_index,
        height: n.height,
        position: n.position,
        valueSats: BigInt(n.value),
        recipientHex: n.recipient_hex,
        nullifierHex: n.nullifier_hex,
      };
    });
}

/** A shielded (z) recipient of a spend. */
export interface ShieldedRecipient {
  readonly address: string; // zs / ztestsapling
  readonly valueSats: bigint;
  /** UTF-8 text memo (≤ 512 bytes). Ignored if `memoHex` is set. */
  readonly memo?: string;
  /** Raw memo bytes as hex (≤ 512 bytes) — for structured/binary memos (e.g. a
   *  messenger frame). Takes precedence over `memo`. */
  readonly memoHex?: string;
}

/** A transparent recipient of a spend, by raw output script. */
export interface TransparentRecipient {
  readonly scriptHex: string;
  readonly valueSats: bigint;
}

/** Default sanity ceiling on the fee: 0.1 coin. Overridable via `maxFeeSats`. */
const DEFAULT_MAX_FEE_SATS = 10_000_000n;

export interface BuildShieldedSpendParams {
  /** The note to spend, from `detectNotes` (its value + spending key). */
  readonly note: {
    readonly txid: string;
    readonly outputIndex: number;
    readonly extskHex: string;
    /** The note's value in satoshis (from the detected `SpendableNote`). Used to
     *  enforce value conservation before signing. */
    readonly valueSats: bigint;
  };
  readonly shieldedOutputs?: readonly ShieldedRecipient[];
  readonly transparentOutputs?: readonly TransparentRecipient[];
  /** The miner fee in satoshis. **Required and explicit**: the fee is the note
   *  value minus every output, so an unstated fee is silently whatever is left
   *  over — a forgotten change output would donate it to miners. This value must
   *  equal `note.valueSats − Σ outputs`, and is bounded by `maxFeeSats`. */
  readonly feeSats: bigint;
  /** Sanity ceiling on `feeSats` to catch a mis-computed fee (default 0.1 coin). */
  readonly maxFeeSats?: bigint;
  /** nExpiryHeight. Defaults to chain tip + 40. */
  readonly expiryHeight?: number;
  /** Consensus branch id. Defaults to Verus `CONSENSUS_BRANCH_ID` (0x76b809bb). */
  readonly branchId?: number;
}

/**
 * Build + sign a z→z / z→t spend of a single detected note. Fetches the note's
 * creating output (via `getTransaction`), the tree state at its block − 1, and
 * that block's ordered cmus (to place the note), assembles the prover spec, and
 * runs `prover` (wasm `spendShielded`, typically in a Web Worker). Returns the
 * broadcastable transaction hex.
 *
 * Value conservation is enforced HERE, before signing: `note.valueSats` must
 * equal Σ shielded-output + Σ transparent-output + `feeSats`. The daemon only
 * rejects a *negative* fee at broadcast; a positive overshoot (e.g. a forgotten
 * change output) is a valid, eagerly-mined transaction that donates the excess
 * to miners. Requiring an explicit `feeSats` and checking the balance turns that
 * silent loss into a caught error.
 */
export async function buildShieldedSpend(
  transport: LightwalletdTransport,
  prover: SpendProver,
  params: BuildShieldedSpendParams,
): Promise<{ hex: string }> {
  const shieldedOutputs = params.shieldedOutputs ?? [];
  const transparentOutputs = params.transparentOutputs ?? [];
  if (shieldedOutputs.length === 0 && transparentOutputs.length === 0) {
    throw new ShieldedInputError('at least one shielded or transparent output is required');
  }
  shieldedOutputs.forEach((o, i) => assertSats(`shieldedOutputs[${i}].valueSats`, o.valueSats));
  transparentOutputs.forEach((o, i) => assertSats(`transparentOutputs[${i}].valueSats`, o.valueSats));
  assertSats('note.valueSats', params.note.valueSats);
  assertSats('feeSats', params.feeSats);

  // Value conservation + a fee sanity ceiling — see the doc comment above.
  const maxFee = params.maxFeeSats ?? DEFAULT_MAX_FEE_SATS;
  if (params.feeSats > maxFee) {
    throw new ShieldedInputError(
      `feeSats ${params.feeSats} exceeds maxFeeSats ${maxFee} — pass maxFeeSats to override`,
    );
  }
  const outSum =
    shieldedOutputs.reduce((a, o) => a + o.valueSats, 0n) +
    transparentOutputs.reduce((a, o) => a + o.valueSats, 0n);
  if (params.note.valueSats !== outSum + params.feeSats) {
    throw new ShieldedInputError(
      `value conservation failed: note ${params.note.valueSats} != outputs ${outSum} + fee ${params.feeSats}`,
    );
  }

  const tx = await transport.getTransaction(params.note.txid);
  const height = Number(tx.height);
  const out = parseSaplingOutput(tx.data, params.note.outputIndex);

  const treeState = await transport.getTreeState(height - 1);
  const tree: ParsedTreeState = parseTreeState(treeState.tree);

  const blockCmus: string[] = [];
  for await (const block of transport.getBlockRange(height, height)) {
    for (const btx of block.vtx) for (const o of btx.outputs) blockCmus.push(toHex(o.cmu));
  }
  const myCmuIndex = blockCmus.indexOf(out.cmu);
  if (myCmuIndex < 0) {
    throw new ShieldedInputError(`note cmu not found in block ${height} compact outputs`);
  }

  const expiryHeight = params.expiryHeight ?? (await transport.getLatestHeight()) + 40;

  const spec = {
    extsk_hex: params.note.extskHex,
    out,
    tree,
    block_cmus: blockCmus,
    my_cmu_index: myCmuIndex,
    shielded_outputs: shieldedOutputs.map((o) => ({
      recipient_hex: saplingAddressToHex(o.address),
      value: toSafeNumber(o.valueSats),
      ...(o.memoHex !== undefined ? { memo_hex: o.memoHex } : { memo: o.memo ?? '' }),
    })),
    transparent_outputs: transparentOutputs.map((o) => ({
      value: toSafeNumber(o.valueSats),
      script_hex: o.scriptHex,
    })),
    // The Rust builder re-checks conservation against the DECRYPTED note value
    // (authoritative) once the wasm is rebuilt to read this field.
    fee: toSafeNumber(params.feeSats),
    expiry_height: expiryHeight,
    branch_id: params.branchId ?? CONSENSUS_BRANCH_ID,
  };

  const hex = await prover(JSON.stringify(spec));
  return { hex };
}

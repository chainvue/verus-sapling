/**
 * Pure byte parsers for the two pieces of chain data a shielded spend needs from
 * lightwalletd, with no external dependency:
 *
 *  - `parseTreeState`  — the note-commitment tree `finalState` (zcashd/Verus
 *    serialization) → { left, right, parents }, the witness base the prover
 *    reconstructs into a `CommitmentTree`.
 *  - `parseSaplingOutput` — the full 948-byte Sapling output description at a
 *    given index of a raw v4 transaction (cv/cmu/epk/enc/ct/proof), needed to
 *    re-derive and spend a note.
 *
 * These were validated end to end: the parsed outputs and tree fed a wasm
 * `spend_shielded` that produced an on-chain-accepted z→z (txid 07e3b38e…f996).
 * Kept dependency-free and unit-tested so the byte layout is pinned.
 */

import { bytesToHex, hexToBytes } from './hex.js';

/** Minimal sequential byte reader over a `Uint8Array` (little-endian ints). */
class ByteReader {
  private off = 0;
  constructor(private readonly buf: Uint8Array) {}

  private view(): DataView {
    return new DataView(this.buf.buffer, this.buf.byteOffset, this.buf.byteLength);
  }

  u8(): number {
    if (this.off >= this.buf.length) throw new RangeError('ByteReader: read past end');
    return this.buf[this.off++]!;
  }

  slice(n: number): Uint8Array {
    if (this.off + n > this.buf.length) throw new RangeError('ByteReader: slice past end');
    const s = this.buf.subarray(this.off, this.off + n);
    this.off += n;
    return s;
  }

  skip(n: number): void {
    if (this.off + n > this.buf.length) throw new RangeError('ByteReader: skip past end');
    this.off += n;
  }

  /** Bitcoin/Zcash CompactSize varint. */
  varint(): number {
    const b = this.u8();
    if (b < 0xfd) return b;
    if (b === 0xfd) {
      const v = this.view().getUint16(this.off, true);
      this.off += 2;
      return v;
    }
    if (b === 0xfe) {
      const v = this.view().getUint32(this.off, true);
      this.off += 4;
      return v;
    }
    const v = this.view().getBigUint64(this.off, true);
    this.off += 8;
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError('varint exceeds MAX_SAFE_INTEGER');
    return Number(v);
  }
}

const toHex = (b: Uint8Array): string => bytesToHex(b);

/** The note-commitment tree state, parts as raw-wire hex (nulls for empty slots). */
export interface ParsedTreeState {
  left: string | null;
  right: string | null;
  parents: (string | null)[];
}

/**
 * Parse a zcashd/Verus commitment-tree `finalState` (hex) — as returned by
 * `z_gettreestate` / lightwalletd `GetTreeState` — into { left, right, parents }.
 * Layout: `EmptyOrValue<Node> left; EmptyOrValue<Node> right;
 * vector<EmptyOrValue<Node>> parents`, each `EmptyOrValue` = 1 tag byte then
 * (if 1) 32 bytes.
 */
export function parseTreeState(finalStateHex: string): ParsedTreeState {
  const r = new ByteReader(hexToBytes(finalStateHex));
  const opt = (): string | null => (r.u8() === 1 ? toHex(r.slice(32)) : null);
  const left = opt();
  const right = opt();
  const n = r.varint();
  const parents: (string | null)[] = [];
  for (let i = 0; i < n; i++) parents.push(opt());
  return { left, right, parents };
}

/** A full Sapling output description, fields as raw-wire hex. */
export interface SaplingOutputBytes {
  cv: string; // 32
  cmu: string; // 32
  epk: string; // 32
  enc: string; // 580
  ct: string; // 80
  proof: string; // 192
}

/**
 * Extract the Sapling output description at `index` from a raw Sapling **v4**
 * transaction. Walks the transparent inputs/outputs and shielded spends to reach
 * `vShieldedOutput`, then returns the 948-byte description split into fields.
 * Throws if the tx has fewer than `index + 1` shielded outputs.
 */
export function parseSaplingOutput(rawTx: Uint8Array, index: number): SaplingOutputBytes {
  const r = new ByteReader(rawTx);
  r.skip(8); // header (4) + versionGroupId (4)

  const nIn = r.varint();
  for (let i = 0; i < nIn; i++) {
    r.skip(36); // prevout: txid(32) + vout(4)
    const scriptLen = r.varint();
    r.skip(scriptLen);
    r.skip(4); // sequence
  }

  const nOut = r.varint();
  for (let i = 0; i < nOut; i++) {
    r.skip(8); // value
    const scriptLen = r.varint();
    r.skip(scriptLen);
  }

  r.skip(4 + 4 + 8); // lockTime + expiryHeight + valueBalance(i64)

  const nSpend = r.varint();
  r.skip(nSpend * 384); // each SpendDescription is 384 bytes in a full tx

  const nShieldedOut = r.varint();
  if (index >= nShieldedOut) {
    throw new RangeError(`shielded output index ${index} out of range (have ${nShieldedOut})`);
  }
  let found: Uint8Array | undefined;
  for (let i = 0; i < nShieldedOut; i++) {
    const d = r.slice(948);
    if (i === index) found = d;
  }
  const d = found!;
  return {
    cv: toHex(d.subarray(0, 32)),
    cmu: toHex(d.subarray(32, 64)),
    epk: toHex(d.subarray(64, 96)),
    enc: toHex(d.subarray(96, 676)),
    ct: toHex(d.subarray(676, 756)),
    proof: toHex(d.subarray(756, 948)),
  };
}

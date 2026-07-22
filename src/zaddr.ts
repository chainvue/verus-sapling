/**
 * Decode a Verus Sapling bech32 address to its raw 43-byte payment-address
 * payload — the form the Rust/wasm prover expects.
 *
 * HRP note (verified against a live daemon, not the stock-zcash source): real
 * Verus uses the `zs` prefix on BOTH mainnet and vrsctest — there is no
 * HRP-level network distinction, so the payload alone determines the recipient.
 * We also tolerate stock-zcash `ztestsapling` for compatibility, but Verus
 * itself never emits it. The bech32 checksum is the only guard against a
 * mistyped address; `bech32Decode` verifies it.
 *
 * Minimal bech32 (BIP-173) decoder, no dependency (keeps the tiny-dep ethos).
 * Sapling addresses use bech32 (not bech32m) and carry an 88-symbol data part
 * that converts to 43 bytes (11-byte diversifier + 32-byte pk_d).
 */

import { bytesToHex } from './hex.js';

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

const BECH32_GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

/** BIP-173 polymod over 5-bit values (bit ops stay within 30 bits, safe in JS). */
function bech32Polymod(values: number[]): number {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= BECH32_GENERATOR[i]!;
  }
  return chk >>> 0;
}

function hrpExpand(hrp: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5);
  out.push(0);
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
  return out;
}

function bech32Decode(addr: string): { hrp: string; data: number[] } {
  const s = addr.trim().toLowerCase();
  const sep = s.lastIndexOf('1');
  if (sep < 1) throw new Error('invalid bech32: no separator');
  const hrp = s.slice(0, sep);
  const data: number[] = [];
  for (const ch of s.slice(sep + 1)) {
    const v = CHARSET.indexOf(ch);
    if (v === -1) throw new Error(`invalid bech32 char: ${ch}`);
    data.push(v);
  }
  if (data.length < 6) throw new Error('bech32 data too short');
  // Verify the 6-symbol checksum (Sapling uses bech32, constant 1 — not bech32m)
  // BEFORE stripping it. Skipping this would let a single mistyped character
  // decode to a valid-looking but WRONG 43-byte payload — on mainnet, funds
  // encrypted to an unspendable key.
  if (bech32Polymod([...hrpExpand(hrp), ...data]) !== 1) {
    throw new Error('invalid bech32 checksum');
  }
  return { hrp, data: data.slice(0, -6) };
}

function convertBits(data: number[], from: number, to: number, pad: boolean): number[] {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  const maxv = (1 << to) - 1;
  for (const value of data) {
    acc = (acc << from) | value;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & maxv);
    }
  }
  if (pad && bits > 0) out.push((acc << (to - bits)) & maxv);
  return out;
}

/** Decode a `zs`/`ztestsapling` address to its 43-byte payload. */
export function decodeSaplingAddress(addr: string): Uint8Array {
  const { hrp, data } = bech32Decode(addr);
  if (hrp !== 'zs' && hrp !== 'ztestsapling') {
    throw new Error(`not a Sapling address (hrp=${hrp})`);
  }
  const bytes = convertBits(data, 5, 8, false);
  if (bytes.length !== 43) {
    throw new Error(`expected 43-byte payload, got ${bytes.length}`);
  }
  return Uint8Array.from(bytes);
}

/** Hex of the 43-byte payload (convenience for JSON specs). */
export function saplingAddressToHex(addr: string): string {
  return bytesToHex(decodeSaplingAddress(addr));
}

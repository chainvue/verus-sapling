/**
 * Decode a Verus Sapling (`zs` / `ztestsapling`) bech32 address to its raw
 * 43-byte payment-address payload — the form the Rust/wasm prover expects.
 *
 * Minimal bech32 (BIP-173) decoder, no dependency (keeps the tiny-dep ethos).
 * Sapling addresses use bech32 (not bech32m) and carry an 88-symbol data part
 * that converts to 43 bytes (11-byte diversifier + 32-byte pk_d).
 */

import { bytesToHex } from './hex.js';

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

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
  return { hrp, data: data.slice(0, -6) }; // drop 6-symbol checksum
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

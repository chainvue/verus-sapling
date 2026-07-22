/**
 * Buffer-free hex ↔ bytes helpers, so the core (parsers, orchestration, address
 * decode) runs unchanged in the browser as well as Node. Node's `Buffer` is not
 * available in a browser/extension context; these use only `Uint8Array`.
 */

const HEX = '0123456789abcdef';

/** Lowercase hex of a byte array. */
export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += HEX[b >> 4]! + HEX[b & 0x0f]!;
  return out;
}

/** Parse a hex string (even length) to bytes. Throws on odd length / non-hex. */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error(`hex: odd length ${hex.length}`);
  // Strict: reject any non-hex char up front. `Number.parseInt` otherwise accepts
  // "+1"/" 1" and stops at the first bad char in a pair ("1z" -> 1), silently
  // producing wrong bytes.
  if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error('hex: invalid character');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

/** Reverse byte order (e.g. txid display ↔ internal). */
export function reverseBytes(bytes: Uint8Array): Uint8Array {
  return Uint8Array.from(bytes).reverse();
}

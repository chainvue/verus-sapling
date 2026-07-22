import { describe, expect, it } from 'vitest';

import { bytesToHex, hexToBytes, reverseBytes } from '../src/hex.js';

describe('hex', () => {
  it('bytesToHex ↔ hexToBytes round-trip', () => {
    const bytes = Uint8Array.from([0x00, 0xff, 0x10, 0xab, 0x7f, 0x80]);
    expect(bytesToHex(bytes)).toBe('00ff10ab7f80');
    expect(hexToBytes('00ff10ab7f80')).toEqual(bytes);
  });

  it('bytesToHex is lowercase and zero-padded per byte', () => {
    expect(bytesToHex(Uint8Array.from([1, 2, 3]))).toBe('010203');
    expect(bytesToHex(new Uint8Array(0))).toBe('');
  });

  it('hexToBytes rejects odd length and non-hex', () => {
    expect(() => hexToBytes('abc')).toThrow(/odd length/);
    expect(() => hexToBytes('zz')).toThrow(/invalid character/);
  });

  it('hexToBytes strictly rejects sign/space/partial pairs', () => {
    // Number.parseInt would accept these and produce wrong bytes.
    expect(() => hexToBytes('+1')).toThrow(/invalid character/);
    expect(() => hexToBytes(' 1')).toThrow(/invalid character/);
    expect(() => hexToBytes('1z')).toThrow(/invalid character/);
  });

  it('reverseBytes reverses without mutating the input', () => {
    const input = Uint8Array.from([1, 2, 3, 4]);
    expect(reverseBytes(input)).toEqual(Uint8Array.from([4, 3, 2, 1]));
    expect(input).toEqual(Uint8Array.from([1, 2, 3, 4])); // unchanged
  });

  it('round-trips a 32-byte txid display↔internal reversal', () => {
    const display = 'a'.repeat(2) + 'b'.repeat(62);
    const internal = bytesToHex(reverseBytes(hexToBytes(display)));
    expect(bytesToHex(reverseBytes(hexToBytes(internal)))).toBe(display);
  });
});

import { describe, expect, it } from 'vitest';

import { decodeSaplingAddress, saplingAddressToHex } from '../src/zaddr.js';

// A real Verus vrsctest Sapling address (validated on-chain as `type: sapling`).
// Verus uses the `zs` HRP on both mainnet and testnet, so this is also a valid
// checksum vector for the mainnet decode path.
const VALID = 'zs1tcvsfvpm8dx5wldd3c5zvvw3r4w663g9cujxvtrw7nhjmrdvll5mc6aju2yhm6e0v7c5uqyf2s4';

describe('decodeSaplingAddress', () => {
  it('decodes a real zs address to the 43-byte payload', () => {
    const payload = decodeSaplingAddress(VALID);
    expect(payload).toHaveLength(43); // 11-byte diversifier + 32-byte pk_d
    expect(saplingAddressToHex(VALID)).toHaveLength(86);
  });

  it('rejects a single mistyped character (checksum guard)', () => {
    // Flip the last data symbol; the bech32 checksum must catch it rather than
    // silently decoding to a wrong-but-valid-length payload (mainnet: lost funds).
    const mutated = VALID.slice(0, -1) + (VALID.endsWith('m') ? 'p' : 'm');
    expect(() => decodeSaplingAddress(mutated)).toThrow(/checksum/);
  });

  it('rejects a truncated address', () => {
    expect(() => decodeSaplingAddress(VALID.slice(0, VALID.length - 4))).toThrow();
  });

  it('rejects a non-Sapling HRP', () => {
    // Valid bech32 for hrp "bc" (a BIP-173 test vector) — right encoding, wrong prefix.
    expect(() => decodeSaplingAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')).toThrow(
      /Sapling/,
    );
  });

  it('rejects an invalid bech32 character', () => {
    expect(() => decodeSaplingAddress('zs1bbb')).toThrow();
  });

  it('is case-insensitive on all-uppercase input', () => {
    expect(decodeSaplingAddress(VALID.toUpperCase())).toEqual(decodeSaplingAddress(VALID));
  });

  it('rejects mixed-case input (BIP-173)', () => {
    const mixed = VALID.slice(0, 20) + VALID.slice(20).toUpperCase();
    expect(() => decodeSaplingAddress(mixed)).toThrow(/mixed case/);
  });
});

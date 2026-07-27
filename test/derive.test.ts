import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

import { deriveSaplingAccount, mnemonicToSeed, COIN_TYPE_VRSCTEST } from '../src/derive.js';
import { bytesToHex } from '../src/hex.js';
import { initSapling } from '../src/wasm.js';
import { decodeSaplingAddress, encodeSaplingAddress, saplingAddressToHex } from '../src/zaddr.js';

// The ZIP-32 derivation is exercised at two levels: in Rust
// (`crate/src/derive.rs`, `cargo test`) and end-to-end through the wasm below.
// The rest covers the pure-TS halves that flank it — the BIP-39 seed the crate
// consumes, and the bech32 encoding of the address it returns.

const VALID_ZS = 'zs1tcvsfvpm8dx5wldd3c5zvvw3r4w663g9cujxvtrw7nhjmrdvll5mc6aju2yhm6e0v7c5uqyf2s4';

describe('mnemonicToSeed', () => {
  // Official BIP-39 English test vectors (trezor/python-mnemonic vectors.json).
  // Verus Mobile reaches the identical function through kotlin-bip39
  // (`MnemonicCode.toSeed()`), so matching these is what makes the derived
  // z-address match the wallet's.
  const VECTORS = [
    {
      mnemonic:
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      passphrase: 'TREZOR',
      seed: 'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04',
    },
  ] as const;

  it('matches the official BIP-39 vector', async () => {
    const v = VECTORS[0]!;
    expect(bytesToHex(await mnemonicToSeed(v.mnemonic, v.passphrase))).toBe(v.seed);
  });

  it('defaults to an empty passphrase, as Verus Mobile does', async () => {
    const withEmpty = await mnemonicToSeed(VECTORS[0]!.mnemonic);
    const explicit = await mnemonicToSeed(VECTORS[0]!.mnemonic, '');
    expect(bytesToHex(withEmpty)).toBe(bytesToHex(explicit));
    // A passphrase is a different wallet entirely.
    expect(bytesToHex(withEmpty)).not.toBe(bytesToHex(await mnemonicToSeed(VECTORS[0]!.mnemonic, 'TREZOR')));
  });

  it('produces 64 bytes', async () => {
    expect(await mnemonicToSeed('one two three')).toHaveLength(64);
  });

  it('rejects an empty mnemonic', async () => {
    await expect(mnemonicToSeed('')).rejects.toThrow(/empty/);
    await expect(mnemonicToSeed('   ')).rejects.toThrow(/empty/);
  });
});

describe('encodeSaplingAddress', () => {
  it('round-trips a real address through decode → encode', () => {
    expect(encodeSaplingAddress(decodeSaplingAddress(VALID_ZS))).toBe(VALID_ZS);
  });

  it('produces an address the decoder accepts', () => {
    const payload = Uint8Array.from({ length: 43 }, (_, i) => (i * 7) & 0xff);
    const addr = encodeSaplingAddress(payload);
    expect(addr.startsWith('zs1')).toBe(true);
    expect(saplingAddressToHex(addr)).toBe(bytesToHex(payload));
  });

  it('defaults to the zs HRP on both Verus networks', () => {
    const payload = decodeSaplingAddress(VALID_ZS);
    expect(encodeSaplingAddress(payload).startsWith('zs1')).toBe(true);
    // The stock-zcash HRP stays available for interop, and stays decodable.
    const testHrp = encodeSaplingAddress(payload, 'ztestsapling');
    expect(testHrp.startsWith('ztestsapling1')).toBe(true);
    expect(saplingAddressToHex(testHrp)).toBe(bytesToHex(payload));
  });

  it('rejects a payload that is not 43 bytes', () => {
    expect(() => encodeSaplingAddress(new Uint8Array(42))).toThrow(/43-byte/);
  });
});

describe('deriveSaplingAccount (through the wasm)', () => {
  // Derivation needs no proving parameters, so unlike the prover smoke test this
  // one runs in CI. It locks the whole path — mnemonic → BIP-39 seed → ZIP-32
  // → bech32 — against a fixed vector.
  const MNEMONIC =
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  // m/32'/133'/0' for that mnemonic. Cross-checked against the native Rust path
  // (`cargo run --example derive_address`), and the SAME path a live Verus
  // Mobile VRSCTEST wallet was confirmed to use on 2026-07-28.
  const EXPECTED = 'zs188wzupg00tqs3y5reyjc758c6vhl8qm2kg4k43mcp533ytrdkwpy8xjdk3zqtek0ng0cv7f0nta';

  it('derives the default VRSC account from a mnemonic', async () => {
    await initSapling(await readFile(new URL('../crate/pkg/verus_sapling_prover_bg.wasm', import.meta.url)));
    const account = await deriveSaplingAccount({ mnemonic: MNEMONIC });

    expect(account.address).toBe(EXPECTED);
    expect(account.extskHex).toHaveLength(169 * 2);
    expect(account.dfvkHex).toHaveLength(128 * 2);
    expect(saplingAddressToHex(account.address)).toBe(account.addressHex);
  });

  it('accepts a pre-computed seed and agrees with the mnemonic path', async () => {
    await initSapling(await readFile(new URL('../crate/pkg/verus_sapling_prover_bg.wasm', import.meta.url)));
    const seedHex = bytesToHex(await mnemonicToSeed(MNEMONIC));
    expect((await deriveSaplingAccount({ seedHex })).address).toBe(EXPECTED);
  });

  it('derives a different key for the stock-zcash testnet coin type', async () => {
    await initSapling(await readFile(new URL('../crate/pkg/verus_sapling_prover_bg.wasm', import.meta.url)));
    const testnet = await deriveSaplingAccount({ mnemonic: MNEMONIC, coinType: COIN_TYPE_VRSCTEST });
    // Verus Mobile does NOT use this path — see the note in derive.ts.
    expect(testnet.address).not.toBe(EXPECTED);
  });

  it('requires exactly one of mnemonic or seedHex', async () => {
    await expect(deriveSaplingAccount({})).rejects.toThrow(/exactly one/);
    await expect(
      deriveSaplingAccount({ mnemonic: MNEMONIC, seedHex: '00'.repeat(64) }),
    ).rejects.toThrow(/exactly one/);
  });
});

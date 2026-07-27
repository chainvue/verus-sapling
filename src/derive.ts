/**
 * Shielded key derivation from a recovery phrase — BIP-39 → ZIP-32 Sapling.
 *
 * A Verus Mobile wallet derives BOTH of its keys from one phrase, by two
 * completely unrelated schedules:
 *
 *   transparent (R-address)  sha256(utf8(phrase)) + Agama/Iguana clamp.
 *                            No BIP-39, no BIP-32, one key per phrase.
 *                            Lives in `@chainvue/verus-sdk` (`keys.seedToWif`).
 *   shielded    (z-address)  BIP-39 → 64-byte seed → ZIP-32 `m/32'/coin'/account'`.
 *                            This module.
 *
 * Consequences worth knowing before you wire this into a wallet:
 *
 *  - The phrase must be a REAL BIP-39 mnemonic for a z-address to exist. Verus
 *    Mobile gates its shielded account on `validateMnemonic()` + ≥12 words; an
 *    arbitrary passphrase yields a transparent-only wallet. The transparent
 *    side, by contrast, accepts any string at all.
 *  - `coinType` is 133 for a Verus Mobile wallet on BOTH networks — including
 *    VRSCTEST. That is not a typo: the app's `parseDlightSeed` calls
 *    `Tools.deriveSaplingSpendingKey(seed)` with NO network argument, so the
 *    Kotlin bridge falls back to `networks.getOrDefault(network,
 *    ZcashNetwork.Mainnet)` and a testnet wallet ends up holding a mainnet-path
 *    key. Confirmed 2026-07-28 against a live VRSCTEST wallet: only
 *    `m/32'/133'/0'` reproduced the address the app displays. The stock-zcash
 *    testnet coin type (1) is exported for other tooling, but derives a key no
 *    Verus Mobile wallet holds.
 *  - The address has no network split either — Verus emits `zs` on both.
 *  - This derives keys; it does not validate the BIP-39 checksum (that needs the
 *    2048-word list, which this package deliberately does not carry). A typo'd
 *    phrase derives a valid but empty wallet — compare the address against your
 *    wallet before relying on it.
 */

import { ShieldedInputError } from './errors.js';
import { bytesToHex, hexToBytes } from './hex.js';
import { deriveAccountWasm } from './wasm.js';
import { encodeSaplingAddress } from './zaddr.js';

/**
 * ZIP-32 coin type for Verus (stock Zcash mainnet value; the Verus librustzcash
 * fork leaves it unmodified). This is what Verus Mobile uses on **both**
 * networks — see the note above — so it is the right default for VRSCTEST too.
 */
export const COIN_TYPE_VRSC = 133;
/**
 * Stock-zcash testnet coin type. Exported for interoperating with tooling that
 * follows the network split; a Verus Mobile wallet does NOT hold a key at this
 * path, not even on VRSCTEST.
 */
export const COIN_TYPE_VRSCTEST = 1;

/**
 * BIP-39 mnemonic → 64-byte seed: PBKDF2-HMAC-SHA512, 2048 iterations, salt
 * `"mnemonic" + passphrase`, both NFKD-normalized. Exactly what Verus Mobile's
 * `SeedPhrase.toByteArray()` (kotlin-bip39 `MnemonicCode.toSeed()`) computes.
 *
 * WebCrypto, so it works unchanged in Node and the browser.
 */
export async function mnemonicToSeed(mnemonic: string, passphrase = ''): Promise<Uint8Array> {
  if (typeof mnemonic !== 'string' || mnemonic.trim().length === 0) {
    throw new ShieldedInputError('mnemonic is empty');
  }
  const enc = new TextEncoder();
  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    enc.encode(mnemonic.normalize('NFKD')),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  const bits = await globalThis.crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: enc.encode(`mnemonic${passphrase.normalize('NFKD')}`),
      iterations: 2048,
      hash: 'SHA-512',
    },
    key,
    512,
  );
  return new Uint8Array(bits);
}

/** A derived Sapling account. */
export interface SaplingAccount {
  /** `zs…` payment address — compare this against your wallet. */
  address: string;
  /** Raw 43-byte payment address, hex (what the JSON specs take). */
  addressHex: string;
  /** ZIP-32 extended spending key, hex — `extskHex` everywhere else here. CAN SPEND. */
  extskHex: string;
  /** Diversifiable full viewing key, hex — enough to scan, cannot spend. */
  dfvkHex: string;
  /** Diversifier index the default address was found at. */
  diversifierIndexHex: string;
}

export interface DeriveSaplingAccountParams {
  /** BIP-39 recovery phrase. Mutually exclusive with `seedHex`. */
  mnemonic?: string;
  /** Optional BIP-39 passphrase ("25th word"). Verus Mobile does not use one. */
  passphrase?: string;
  /** A 64-byte BIP-39 seed, hex, if you did the mnemonic step yourself. */
  seedHex?: string;
  /**
   * Defaults to 133 — what Verus Mobile derives with on BOTH VRSC and VRSCTEST.
   * Pass 1 only for stock-zcash tooling that honours the testnet split.
   */
  coinType?: number;
  /** Defaults to 0 — the account Verus Mobile uses (`Account.DEFAULT`). */
  account?: number;
}

/**
 * Derive `m/32'/coinType'/account'` and its default payment address.
 *
 * Requires the wasm module: call `initSapling()` first. Cheap — no proving
 * parameters, no Groth16, safe on the main thread.
 */
export async function deriveSaplingAccount(
  params: DeriveSaplingAccountParams,
): Promise<SaplingAccount> {
  const { mnemonic, seedHex, passphrase = '', coinType = COIN_TYPE_VRSC, account = 0 } = params;

  // Narrowed by the branches themselves rather than by a non-null assertion:
  // exactly one input is allowed, and each branch reads the one it checked.
  let seed: Uint8Array;
  if (mnemonic != null && seedHex == null) {
    seed = await mnemonicToSeed(mnemonic, passphrase);
  } else if (seedHex != null && mnemonic == null) {
    seed = hexToBytes(seedHex);
  } else {
    throw new ShieldedInputError('pass exactly one of mnemonic or seedHex');
  }
  const derived = deriveAccountWasm(
    JSON.stringify({ seed_hex: bytesToHex(seed), coin_type: coinType, account }),
  );

  return {
    address: encodeSaplingAddress(hexToBytes(derived.address_hex)),
    addressHex: derived.address_hex,
    extskHex: derived.extsk_hex,
    dfvkHex: derived.dfvk_hex,
    diversifierIndexHex: derived.diversifier_index_hex,
  };
}

//! ZIP-32 Sapling account derivation from a BIP-39 seed.
//!
//! Verus Mobile derives BOTH of a wallet's keys from one recovery phrase, but by
//! two completely unrelated schedules:
//!
//!   * transparent (R-address): `sha256(utf8(phrase))` + the Agama/Iguana clamp,
//!     no BIP-39, no BIP-32, one key per phrase. That path lives in
//!     `@chainvue/verus-sdk` (`keys.seedToWif`).
//!   * shielded (z-address): the real BIP-39 -> ZIP-32 path implemented here.
//!     The phrase must be a VALID BIP-39 mnemonic; the JS side turns it into the
//!     64-byte seed (PBKDF2-HMAC-SHA512) that this function consumes.
//!
//! Path: `m/32'/coin_type'/account'`, all hardened — the composition
//! `zcash_keys::keys::sapling::spending_key` uses, verified against VerusCoin's
//! own librustzcash fork. Verus Mobile reaches the same code through the ECC
//! Zcash Android SDK (`DerivationTool.deriveSaplingSpendingKey(seed, network,
//! Account.DEFAULT)`), so account 0 is what the app shows.
//!
//! `coin_type` is **133 for a Verus Mobile wallet on both networks**, VRSCTEST
//! included. The Kotlin bridge does map VRSC -> Mainnet / VRSCTEST -> Testnet
//! (and VerusCoin's librustzcash fork keeps the stock 133/1 constants), but the
//! app never reaches that mapping for key derivation: `parseDlightSeed` calls
//! `Tools.deriveSaplingSpendingKey(seed)` with NO network argument, so
//! `networks.getOrDefault(network, ZcashNetwork.Mainnet)` falls back to mainnet
//! and a testnet wallet holds a mainnet-path key. Confirmed 2026-07-28 against a
//! live VRSCTEST wallet: of the five candidate paths tried, only
//! `m/32'/133'/0'` reproduced the z-address the app displays.
//!
//! The address has no network split either — Verus emits the `zs` HRP on both
//! (see `src/zaddr.ts`).

use sapling_crypto::zip32::ExtendedSpendingKey;
use zip32::ChildIndex;

/// Coin type for Verus (stock Zcash mainnet value, unmodified in the Verus
/// fork). Verus Mobile derives with this on VRSCTEST as well — see above.
pub const COIN_TYPE_MAINNET: u32 = 133;
/// Stock-zcash testnet coin type. No Verus Mobile wallet holds a key here; kept
/// for interop with tooling that follows the network split.
pub const COIN_TYPE_TESTNET: u32 = 1;

/// One derived Sapling account: the spending key, its diversifiable full
/// viewing key, and the default payment address.
pub struct DerivedAccount {
    /// ZIP-32 extended spending key, 169 bytes — the form `extsk_hex` takes
    /// everywhere else in this crate.
    pub extsk: [u8; 169],
    /// Diversifiable full viewing key, 128 bytes — enough to SCAN but not spend.
    pub dfvk: [u8; 128],
    /// Raw 43-byte payment address (11-byte diversifier || 32-byte pk_d). The TS
    /// layer bech32-encodes this into a `zs…` address.
    pub address: [u8; 43],
    /// The diversifier index the default address was found at (usually 0, but
    /// not guaranteed — roughly half of indices yield no valid diversifier).
    pub diversifier_index: [u8; 11],
}

/// Derive `m/32'/coin_type'/account'` from a BIP-39 seed.
///
/// Errors rather than panics on a short seed or an out-of-range index —
/// `zcash_keys`' equivalent panics on the seed length, which is not acceptable
/// at a library boundary that takes caller input.
pub fn derive_account(seed: &[u8], coin_type: u32, account: u32) -> Result<DerivedAccount, String> {
    // ZIP-32 requires >= 32 bytes; BIP-39 supplies 64. A shorter seed is a
    // caller bug (truncated hex, wrong field) and must not silently derive a
    // weaker key.
    if seed.len() < 32 {
        return Err(format!("ZIP-32 seed must be at least 32 bytes, got {}", seed.len()));
    }
    if seed.len() > 252 {
        return Err(format!("ZIP-32 seed must be at most 252 bytes, got {}", seed.len()));
    }
    // Every element of the path is hardened, so the index must fit below 2^31.
    const HARDENED_LIMIT: u32 = 1 << 31;
    if coin_type >= HARDENED_LIMIT {
        return Err(format!("coin_type {coin_type} exceeds the hardened index range"));
    }
    if account >= HARDENED_LIMIT {
        return Err(format!("account {account} exceeds the hardened index range"));
    }

    let extsk = ExtendedSpendingKey::from_path(
        &ExtendedSpendingKey::master(seed),
        &[
            ChildIndex::hardened(32),
            ChildIndex::hardened(coin_type),
            ChildIndex::hardened(account),
        ],
    );
    let dfvk = extsk.to_diversifiable_full_viewing_key();
    let (index, address) = dfvk.default_address();

    Ok(DerivedAccount {
        extsk: extsk.to_bytes(),
        dfvk: dfvk.to_bytes(),
        address: address.to_bytes(),
        diversifier_index: *index.as_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The derived spending key must round-trip into the form the rest of this
    /// crate consumes (`extsk_hex` -> dfvk), and the dfvk must agree with the
    /// one derivation returned directly.
    #[test]
    fn extsk_round_trips_into_the_scanning_key() {
        let seed = [7u8; 64];
        let acct = derive_account(&seed, COIN_TYPE_MAINNET, 0).expect("derive");
        let dfvk = crate::scan::dfvk_from_extsk(&acct.extsk).expect("dfvk from extsk");
        assert_eq!(dfvk.to_bytes(), acct.dfvk);
        assert_eq!(dfvk.default_address().1.to_bytes(), acct.address);
    }

    /// Path elements must actually be applied: a different coin type or account
    /// is a different wallet. Guards against a silently-dropped path segment.
    #[test]
    fn coin_type_and_account_change_the_key() {
        let seed = [7u8; 64];
        let vrsc = derive_account(&seed, COIN_TYPE_MAINNET, 0).unwrap();
        let vrsctest = derive_account(&seed, COIN_TYPE_TESTNET, 0).unwrap();
        let account1 = derive_account(&seed, COIN_TYPE_MAINNET, 1).unwrap();
        assert_ne!(vrsc.address, vrsctest.address);
        assert_ne!(vrsc.address, account1.address);
        assert_ne!(vrsc.extsk, account1.extsk);
    }

    #[test]
    fn rejects_a_short_seed_instead_of_panicking() {
        assert!(derive_account(&[0u8; 31], COIN_TYPE_MAINNET, 0).is_err());
        assert!(derive_account(&[0u8; 32], COIN_TYPE_MAINNET, 0).is_ok());
    }

    /// Regression lock over the whole seed -> address pipeline, using the ZIP-32
    /// test-vector seed [0,1,…,31].
    ///
    /// Honest about what this proves: the value was generated by THIS code, so
    /// it catches an accidental change to the path or the encoding — it does not
    /// independently prove Zcash-correctness. That comes from two other places:
    /// `sapling-crypto`'s own ZIP-32 test vectors cover the primitives, and the
    /// end-to-end proof is a real Verus Mobile wallet deriving the same
    /// z-address from the same phrase.
    #[test]
    fn derivation_is_pinned_end_to_end() {
        let seed: Vec<u8> = (0u8..32).collect();
        let acct = derive_account(&seed, COIN_TYPE_MAINNET, 0).unwrap();
        assert_eq!(
            hex::encode(acct.address),
            "d8ef8293d26de832e7193f296ba1922d90f122c6135bc231eebd91efdb03b1a8606771cd4fd6480574d43e",
            "seed -> m/32'/133'/0' -> default address changed",
        );
    }
}

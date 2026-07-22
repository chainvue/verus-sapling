//! Verus shielded (Sapling) proving core — native-first, wasm32 target added later.
//!
//! Verus shielded is stock Zcash Sapling (stock circuit, byte-identical MPC
//! params, branch id 0x76b809bb). This crate uses `sapling-crypto` for the zk
//! proving + RedJubjub signatures + note encryption, and (in a following
//! tranche) a hand-written Sapling v4 transaction serializer + ZIP-243 sighash
//! that injects the Verus branch id. The golden vectors in
//! `../test/vectors/` are the byte-layout targets.
//!
//! MILESTONE STATUS: this file implements and is intended to compile the t->z
//! Sapling *bundle* proving pipeline (Builder -> proofs -> binding signature).
//! It does NOT yet compute the real ZIP-243 sighash or serialize the full v4
//! transaction (transparent inputs/outputs + shielded bundle) — those are the
//! next, clearly-scoped pieces. Passing a real sighash is required before the
//! binding signature is chain-valid; `prove_shield` accepts it as a parameter.

pub mod golden;
pub mod json_api;
pub mod scan;
pub mod tx;
pub mod z2z;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

use std::fs::File;
use std::io::BufReader;

use rand::rngs::OsRng;
use sapling_crypto::builder::{Builder, BundleType};
use sapling_crypto::bundle::{Authorized, Bundle};
use sapling_crypto::circuit::{OutputParameters, SpendParameters};
use sapling_crypto::keys::OutgoingViewingKey;
use sapling_crypto::note_encryption::Zip212Enforcement;
use sapling_crypto::value::NoteValue;
use sapling_crypto::{Anchor, PaymentAddress};

/// Max Sapling memo size (note-plaintext memo field).
pub const MEMO_SIZE: usize = 512;

/// A shielded output for a t->z build: raw 43-byte Sapling payment address
/// (the TS layer decodes the `zs` bech32 into these bytes), value in zatoshi,
/// and a 512-byte memo (already UTF-8-encoded + zero-padded by the caller).
pub struct ShieldOutput {
    pub recipient: [u8; 43],
    pub value: u64,
    pub memo: [u8; MEMO_SIZE],
}

/// The proven, binding-signed Sapling bundle for a t->z transaction, decomposed
/// into the fields the (forthcoming) v4 serializer will lay out.
pub struct ProvenShield {
    /// Net value moved out of the shielded pool. For t->z this is negative
    /// (value enters the pool); matches the golden vector's `valueBalance`.
    pub value_balance: i64,
    /// Each serialized Sapling OutputDescription (v4 order):
    /// cv(32) || cmu(32) || ephemeralKey(32) || encCiphertext(580) || outCiphertext(80) || zkproof(192).
    pub shielded_outputs: Vec<Vec<u8>>,
    /// 64-byte Sapling binding signature.
    pub binding_sig: [u8; 64],
}

/// Loads the standard Zcash Sapling Groth16 parameters (byte-identical for
/// Verus). Paths point at `sapling-spend.params` / `sapling-output.params`.
pub fn load_params(
    spend_path: &str,
    output_path: &str,
) -> Result<(SpendParameters, OutputParameters), String> {
    let sp = SpendParameters::read(BufReader::new(open(spend_path)?), false)
        .map_err(|e| format!("read spend params: {e}"))?;
    let op = OutputParameters::read(BufReader::new(open(output_path)?), false)
        .map_err(|e| format!("read output params: {e}"))?;
    Ok((sp, op))
}

fn open(path: &str) -> Result<File, String> {
    File::open(path).map_err(|e| format!("open {path}: {e}"))
}

/// Loads the Sapling params from in-memory bytes (for wasm / callers that fetch
/// the params rather than reading a file).
pub fn load_params_from_bytes(
    spend: &[u8],
    output: &[u8],
) -> Result<(SpendParameters, OutputParameters), String> {
    let sp = SpendParameters::read(spend, false).map_err(|e| format!("read spend params: {e}"))?;
    let op =
        OutputParameters::read(output, false).map_err(|e| format!("read output params: {e}"))?;
    Ok((sp, op))
}

/// Build and prove a t->z Sapling bundle: no shielded spends, one or more
/// shielded outputs. `sighash` is the ZIP-243 transaction sighash (Verus branch
/// id 0x76b809bb) over the full v4 transaction; it authorizes the binding
/// signature. Until the serializer exists, callers pass a placeholder to
/// exercise proving — the resulting binding signature is only chain-valid once
/// `sighash` is the real transaction sighash.
///
/// `zip212` selects the note-plaintext encoding. For Verus this is always
/// `Off`: Verus consensus is frozen at Sapling (branch id 0x76b809bb) on both
/// mainnet and testnet — Canopy, which gates ZIP-212 enforcement, is not even
/// defined in Verus's network-upgrade enum. See `json_api.rs` for the evidence.
pub fn prove_shield(
    outputs: &[ShieldOutput],
    spend_params: &SpendParameters,
    output_params: &OutputParameters,
    sighash: [u8; 32],
    zip212: Zip212Enforcement,
) -> Result<ProvenShield, String> {
    if outputs.is_empty() {
        return Err("t->z build requires at least one shielded output".into());
    }
    let mut rng = OsRng;

    // No shielded spends in t->z, so the anchor is the empty tree.
    let mut builder = Builder::new(zip212, BundleType::DEFAULT, Anchor::empty_tree());

    for out in outputs {
        let to = PaymentAddress::from_bytes(&out.recipient)
            .ok_or_else(|| "invalid Sapling payment address bytes".to_string())?;
        // ovk = None: the sender keeps no outgoing-viewing linkability for a
        // shield. (A wallet that wants to detect its own sends would pass Some.)
        let ovk: Option<OutgoingViewingKey> = None;
        builder
            .add_output(ovk, to, NoteValue::from_raw(out.value), out.memo)
            .map_err(|e| format!("add_output: {e:?}"))?;
    }

    // build() assembles the (unproven, unsigned) bundle; no spending keys.
    let (bundle, _meta) = builder
        .build::<SpendParameters, OutputParameters, _, i64>(&[], &mut rng)
        .map_err(|e| format!("build: {e:?}"))?
        .ok_or_else(|| "builder produced no bundle".to_string())?;

    // Generate the Groth16 output proofs, then apply the binding signature.
    // No spend-auth keys (no shielded spends).
    let authorized: Bundle<Authorized, i64> = bundle
        .create_proofs(spend_params, output_params, &mut rng, ())
        .apply_signatures(&mut rng, sighash, &[])
        .map_err(|e| format!("apply_signatures: {e:?}"))?;

    Ok(ProvenShield {
        value_balance: *authorized.value_balance(),
        shielded_outputs: authorized
            .shielded_outputs()
            .iter()
            .map(tx::serialize_output_v4_desc)
            .collect(),
        binding_sig: {
            let mut b = [0u8; 64];
            b.copy_from_slice(&<[u8; 64]>::from(authorized.authorization().binding_sig));
            b
        },
    })
}

/// Build a complete, daemon-signable t->z Sapling v4 transaction.
///
/// Proves the shielded bundle, computes the ZIP-243 shielded sighash (Verus
/// `branch_id`) over the real transaction, applies the binding signature, and
/// serializes the v4 transaction with EMPTY transparent scriptSigs. The Verus
/// daemon fills the scriptSigs via `signrawtransaction`, so no private key is
/// handled here. Returns the transaction hex.
///
/// `transparent_inputs`/`transparent_outputs` describe the transparent side
/// (change output(s)); the fee is implied by
/// `sum(inputs) + valueBalance == sum(outputs) + fee`. Value conservation and
/// final validity are enforced by the daemon at `sendrawtransaction`.
#[allow(clippy::too_many_arguments)]
pub fn build_t2z_unsigned_tx(
    transparent_inputs: &[tx::TxIn],
    transparent_outputs: &[tx::TxOut],
    shielded_outputs: &[ShieldOutput],
    lock_time: u32,
    expiry_height: u32,
    branch_id: u32,
    spend_params: &SpendParameters,
    output_params: &OutputParameters,
    zip212: Zip212Enforcement,
) -> Result<String, String> {
    if shielded_outputs.is_empty() {
        return Err("t->z build requires at least one shielded output".into());
    }
    let mut rng = OsRng;

    let mut builder = Builder::new(zip212, BundleType::DEFAULT, Anchor::empty_tree());
    for out in shielded_outputs {
        let to = PaymentAddress::from_bytes(&out.recipient)
            .ok_or_else(|| "invalid Sapling payment address bytes".to_string())?;
        builder
            .add_output(None, to, NoteValue::from_raw(out.value), out.memo)
            .map_err(|e| format!("add_output: {e:?}"))?;
    }

    let (bundle, _meta) = builder
        .build::<SpendParameters, OutputParameters, _, i64>(&[], &mut rng)
        .map_err(|e| format!("build: {e:?}"))?
        .ok_or_else(|| "builder produced no bundle".to_string())?;

    // Prove first: the output descriptions are fixed after proving and feed the
    // sighash. No shielded spends in t->z.
    let proven = bundle.create_proofs(spend_params, output_params, &mut rng, ());
    let value_balance = *proven.value_balance();
    let shielded_out_descs: Vec<Vec<u8>> =
        proven.shielded_outputs().iter().map(tx::serialize_output_v4_desc).collect();
    let shielded_spend_descs: Vec<Vec<u8>> = Vec::new();

    // ZIP-243 sighash over the real transaction (Verus branch id).
    let sighash = tx::shielded_sighash(
        branch_id,
        transparent_inputs,
        transparent_outputs,
        lock_time,
        expiry_height,
        value_balance,
        &shielded_spend_descs,
        &shielded_out_descs,
    );

    // Apply the binding signature over that sighash (no spend-auth keys for t->z).
    let authorized: Bundle<Authorized, i64> = proven
        .apply_signatures(&mut rng, sighash, &[])
        .map_err(|e| format!("apply_signatures: {e:?}"))?;
    let mut binding_sig = [0u8; 64];
    binding_sig.copy_from_slice(&<[u8; 64]>::from(authorized.authorization().binding_sig));

    let raw = tx::serialize_v4(
        transparent_inputs,
        transparent_outputs,
        lock_time,
        expiry_height,
        value_balance,
        &shielded_spend_descs,
        &shielded_out_descs,
        &binding_sig,
    );
    Ok(hex::encode(raw))
}


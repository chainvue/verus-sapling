//! Live z->z builder: spend a shielded note into a new shielded note (+memo).
//!
//! Reuses the same ZIP-243 sighash + v4 serializer as t->z (validated against
//! golden vectors). z->z has NO transparent inputs, so the result is complete
//! after our binding + spend-auth signatures — `sendrawtransaction` directly.
//!
//! The caller supplies (from the daemon): the note's spending key, the creating
//! output's ciphertext (to decrypt the note), and the commitment-tree data
//! (tree state before the note's block + the ordered cmus in that block) to
//! build the witness. No full node on the signing host; a chain scanner
//! (lightwalletd / the daemon here) supplies witness inputs.

use rand::rngs::OsRng;
use sapling_crypto::builder::{Builder, BundleType};
use sapling_crypto::bundle::{Authorized, Bundle, GrothProofBytes, OutputDescription};
use sapling_crypto::circuit::{OutputParameters, SpendParameters};
use sapling_crypto::note::ExtractedNoteCommitment;
use sapling_crypto::note_encryption::{try_sapling_note_decryption, Zip212Enforcement};
use sapling_crypto::value::{NoteValue, ValueCommitment};
use sapling_crypto::zip32::ExtendedSpendingKey;
use sapling_crypto::{Anchor, CommitmentTree, IncrementalWitness, Node, PaymentAddress};
use zcash_note_encryption::EphemeralKeyBytes;

use crate::tx::{serialize_output_v4_desc, shielded_sighash, TxIn, TxOut};

/// The note to spend, plus its witness inputs (all raw wire bytes).
pub struct SpendInput {
    /// 169-byte ExtendedSpendingKey encoding (from `z_exportkey <zaddr> true`).
    pub extsk_bytes: Vec<u8>,
    /// Creating output's fields (raw wire order).
    pub out_cv: [u8; 32],
    pub out_cmu: [u8; 32],
    pub out_epk: [u8; 32],
    pub out_enc: Vec<u8>,   // 580
    pub out_ct: Vec<u8>,    // 80
    pub out_proof: Vec<u8>, // 192
    /// Commitment tree just BEFORE the note's block (from z_gettreestate(H-1)).
    pub tree_left: Option<[u8; 32]>,
    pub tree_right: Option<[u8; 32]>,
    pub tree_parents: Vec<Option<[u8; 32]>>,
    /// All sapling output cmus in the note's block H, in order (raw wire order).
    pub block_cmus: Vec<[u8; 32]>,
    /// Index into `block_cmus` of THIS note's cmu.
    pub my_cmu_index: usize,
}

pub struct Z2zOutput {
    pub recipient: [u8; 43],
    pub value: u64,
    pub memo: [u8; 512],
}

/// Convenience wrapper for a pure z->z: one shielded output, no transparent.
pub fn build_z2z_tx(
    spend: &SpendInput,
    output: &Z2zOutput,
    expiry_height: u32,
    branch_id: u32,
    zip212: Zip212Enforcement,
    spend_params: &SpendParameters,
    output_params: &OutputParameters,
) -> Result<String, String> {
    build_zspend_tx(
        spend,
        core::slice::from_ref(output),
        &[],
        expiry_height,
        branch_id,
        zip212,
        spend_params,
        output_params,
    )
}

fn node(bytes: [u8; 32]) -> Result<Node, String> {
    Option::<Node>::from(Node::from_bytes(bytes)).ok_or_else(|| "bad tree node bytes".into())
}

/// Build a Sapling v4 tx that spends one shielded note into any mix of shielded
/// outputs and transparent outputs (z->z, z->t, or both). No transparent inputs,
/// so the result is complete after signing — `sendrawtransaction` directly.
///
/// Value conservation (enforced by the daemon): note value = sum(shielded output
/// values) + sum(transparent output values) + fee. valueBalance is computed by
/// the Sapling builder as note_value - sum(shielded output values), which must
/// equal sum(transparent output values) + fee.
#[allow(clippy::too_many_arguments)]
pub fn build_zspend_tx(
    spend: &SpendInput,
    shielded_outputs: &[Z2zOutput],
    transparent_outputs: &[TxOut],
    expiry_height: u32,
    branch_id: u32,
    zip212: Zip212Enforcement,
    spend_params: &SpendParameters,
    output_params: &OutputParameters,
) -> Result<String, String> {
    let mut rng = OsRng;

    // --- keys ---
    let extsk = ExtendedSpendingKey::from_bytes(&spend.extsk_bytes)
        .map_err(|e| format!("extsk decode: {e:?}"))?;
    let dfvk = extsk.to_diversifiable_full_viewing_key();
    let fvk = dfvk.fvk().clone();
    let ivk = dfvk.fvk().vk.ivk();
    let ovk = extsk.expsk.ovk;
    let ask = extsk.expsk.ask.clone();

    // --- decrypt the note we're spending ---
    let cv = Option::from(ValueCommitment::from_bytes_not_small_order(&spend.out_cv))
        .ok_or("bad out_cv")?;
    let cmu =
        Option::from(ExtractedNoteCommitment::from_bytes(&spend.out_cmu)).ok_or("bad out_cmu")?;
    let mut enc = [0u8; 580];
    enc.copy_from_slice(&spend.out_enc);
    let mut oct = [0u8; 80];
    oct.copy_from_slice(&spend.out_ct);
    let mut proof = [0u8; 192];
    proof.copy_from_slice(&spend.out_proof);
    let od: OutputDescription<GrothProofBytes> = OutputDescription::from_parts(
        cv,
        cmu,
        EphemeralKeyBytes(spend.out_epk),
        enc,
        oct,
        proof,
    );
    let prepared_ivk = sapling_crypto::keys::PreparedIncomingViewingKey::new(&ivk);
    let (note, _addr, _memo) = try_sapling_note_decryption(&prepared_ivk, &od, zip212)
        .ok_or("note decryption failed (wrong key / zip212 setting)")?;

    // --- build the witness for the note ---
    let left = spend.tree_left.map(node).transpose()?;
    let right = spend.tree_right.map(node).transpose()?;
    let parents = spend
        .tree_parents
        .iter()
        .map(|p| p.map(node).transpose())
        .collect::<Result<Vec<Option<Node>>, String>>()?;
    let mut tree = CommitmentTree::from_parts(left, right, parents)
        .map_err(|_| "tree parents too deep".to_string())?;

    // Append cmus up to and including ours; snapshot the witness; advance it
    // with the remaining cmus in the block.
    for cmu_bytes in spend.block_cmus.iter().take(spend.my_cmu_index + 1) {
        tree.append(node(*cmu_bytes)?).map_err(|_| "tree append".to_string())?;
    }
    let mut witness: IncrementalWitness =
        IncrementalWitness::from_tree(tree).ok_or("witness from_tree")?;
    for cmu_bytes in spend.block_cmus.iter().skip(spend.my_cmu_index + 1) {
        witness
            .append(node(*cmu_bytes)?)
            .map_err(|_| "witness append".to_string())?;
    }
    let anchor = Anchor::from(witness.root());
    let merkle_path = witness.path().ok_or("witness path")?;

    // --- build + prove ---
    let mut builder = Builder::new(zip212, BundleType::DEFAULT, anchor);
    builder
        .add_spend(fvk, note, merkle_path)
        .map_err(|e| format!("add_spend: {e:?}"))?;
    for out in shielded_outputs {
        let recipient = PaymentAddress::from_bytes(&out.recipient).ok_or("bad recipient")?;
        builder
            .add_output(Some(ovk), recipient, NoteValue::from_raw(out.value), out.memo)
            .map_err(|e| format!("add_output: {e:?}"))?;
    }

    let (bundle, _meta) = builder
        .build::<SpendParameters, OutputParameters, _, i64>(core::slice::from_ref(&extsk), &mut rng)
        .map_err(|e| format!("build: {e:?}"))?
        .ok_or("empty bundle")?;
    let proven = bundle.create_proofs(spend_params, output_params, &mut rng, ());
    let value_balance = *proven.value_balance();

    // spend descriptions for the sighash: cv||anchor||nullifier||rk||zkproof (no auth sig)
    let spend_sighash_descs: Vec<Vec<u8>> = proven
        .shielded_spends()
        .iter()
        .map(|s| {
            let mut v = Vec::with_capacity(320);
            v.extend_from_slice(&s.cv().to_bytes());
            v.extend_from_slice(&s.anchor().to_bytes());
            v.extend_from_slice(&s.nullifier().0);
            v.extend_from_slice(&<[u8; 32]>::from(*s.rk()));
            v.extend_from_slice(s.zkproof());
            v
        })
        .collect();
    let out_descs: Vec<Vec<u8>> =
        proven.shielded_outputs().iter().map(serialize_output_v4_desc).collect();

    let no_in: Vec<TxIn> = Vec::new();
    let sighash = shielded_sighash(
        branch_id,
        &no_in,
        transparent_outputs,
        0,
        expiry_height,
        value_balance,
        &spend_sighash_descs,
        &out_descs,
    );

    let authorized: Bundle<Authorized, i64> = proven
        .apply_signatures(&mut rng, sighash, core::slice::from_ref(&ask))
        .map_err(|e| format!("apply_signatures: {e:?}"))?;
    let mut binding_sig = [0u8; 64];
    binding_sig.copy_from_slice(&<[u8; 64]>::from(authorized.authorization().binding_sig));

    // full spend descriptions (with spend-auth sig) for serialization
    let spend_full_descs: Vec<Vec<u8>> = authorized
        .shielded_spends()
        .iter()
        .map(|s| {
            let mut v = Vec::with_capacity(384);
            v.extend_from_slice(&s.cv().to_bytes());
            v.extend_from_slice(&s.anchor().to_bytes());
            v.extend_from_slice(&s.nullifier().0);
            v.extend_from_slice(&<[u8; 32]>::from(*s.rk()));
            v.extend_from_slice(s.zkproof());
            v.extend_from_slice(&<[u8; 64]>::from(*s.spend_auth_sig()));
            v
        })
        .collect();
    let out_full: Vec<Vec<u8>> =
        authorized.shielded_outputs().iter().map(serialize_output_v4_desc).collect();

    let raw = crate::tx::serialize_v4(
        &no_in,
        transparent_outputs,
        0,
        expiry_height,
        value_balance,
        &spend_full_descs,
        &out_full,
        &binding_sig,
    );
    Ok(hex::encode(raw))
}

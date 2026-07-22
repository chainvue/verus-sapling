//! Validate our ZIP-243 sighash + field handling against a golden (daemon-made)
//! Sapling tx of ANY flow (t->z, z->z, z->t). Reconstructs the tx from its
//! decoded JSON (via `verus_sapling_prover::golden`), computes our sighash, and
//! checks every spend-auth signature, output proof, and the binding signature
//! against it via SaplingVerificationContext. If final_check == true, our
//! sighash matches the daemon's for that flow.
//!
//! Run: cargo run --example verify_golden --release -- <decoded_tx.json>
//!
//! Unlike the `golden_sighash` regression test (which is param-free and asserts
//! the sighash bytes), this example needs the Sapling proving params to run the
//! full zk/signature verification.

use bellman::groth16::Proof;
use bls12_381::Bls12;
use group::GroupEncoding;
use sapling_crypto::note::ExtractedNoteCommitment;
use sapling_crypto::value::ValueCommitment;
use sapling_crypto::SaplingVerificationContext;
use serde_json::Value;
use std::io::Read;
use verus_sapling_prover::golden::GoldenTx;

const VERUS_SAPLING_BRANCH_ID: u32 = 0x76b8_09bb;

fn main() {
    let path = std::env::args().nth(1).expect("json path arg");
    let mut s = String::new();
    std::fs::File::open(&path).unwrap().read_to_string(&mut s).unwrap();
    let d: Value = serde_json::from_str(&s).unwrap();
    let tx = GoldenTx::from_decoded_json(&d).expect("decode golden tx");

    let sighash = tx.sighash(VERUS_SAPLING_BRANCH_ID);
    println!(
        "flow: vin={} vout={} spends={} outputs={} valueBalance={}",
        tx.inputs.len(),
        tx.outputs.len(),
        tx.spends.len(),
        tx.outs.len(),
        tx.value_balance
    );
    println!("our sighash: {}", hex::encode(sighash));

    let home = std::env::var("HOME").unwrap_or_default();
    let (sp, op) = verus_sapling_prover::load_params(
        &format!("{home}/Library/Application Support/ZcashParams/sapling-spend.params"),
        &format!("{home}/Library/Application Support/ZcashParams/sapling-output.params"),
    )
    .expect("load params");
    let spvk = sp.prepared_verifying_key();
    let opvk = op.prepared_verifying_key();

    let mut ctx = SaplingVerificationContext::new();

    for s in &tx.spends {
        let cv = ValueCommitment::from_bytes_not_small_order(&s.cv).unwrap();
        let anchor = bls12_381::Scalar::from_bytes(&s.anchor).unwrap();
        let rk = redjubjub::VerificationKey::try_from(s.rk).expect("rk");
        let auth_sig = redjubjub::Signature::from(s.auth_sig);
        let proof = Proof::<Bls12>::read(&s.proof[..]).expect("spend proof");
        let ok = ctx.check_spend(&cv, anchor, &s.nullifier, rk, &sighash, auth_sig, proof, &spvk);
        println!("check_spend (proof + auth-sig under OUR sighash): {ok}");
    }

    for o in &tx.outs {
        let cv = ValueCommitment::from_bytes_not_small_order(&o.cv).unwrap();
        let cmu = ExtractedNoteCommitment::from_bytes(&o.cmu).unwrap();
        let epk = jubjub::ExtendedPoint::from_bytes(&o.epk).expect("epk");
        let proof = Proof::<Bls12>::read(&o.proof[..]).expect("output proof");
        let ok = ctx.check_output(&cv, cmu, epk, proof, &opvk);
        println!("check_output (proof valid): {ok}");
    }

    let binding_sig = redjubjub::Signature::<redjubjub::Binding>::from(tx.binding_sig);
    let final_ok = ctx.final_check(tx.value_balance, &sighash, binding_sig);
    println!("final_check (binding sig under OUR sighash): {final_ok}");
    println!(
        "=> {}",
        if final_ok {
            "OUR SIGHASH IS CORRECT for this flow."
        } else {
            "SIGHASH MISMATCH."
        }
    );
}

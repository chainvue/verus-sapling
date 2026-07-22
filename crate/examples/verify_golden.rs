//! Validate our ZIP-243 sighash + field handling against a golden (daemon-made)
//! Sapling tx of ANY flow (t->z, z->z, z->t). Reconstructs the tx from its
//! decoded JSON, computes our sighash, and checks every spend-auth signature,
//! output proof, and the binding signature against it via
//! SaplingVerificationContext. If final_check == true, our sighash matches the
//! daemon's for that flow.
//!
//! Run: cargo run --example verify_golden --release -- <decoded_tx.json>
//!
//! decoderawtransaction displays 32-byte fields (cv/cmu/ephemeralKey and
//! spend cv/anchor/nullifier/rk) byte-REVERSED; ciphertexts/proofs/sigs are raw.

use bellman::groth16::Proof;
use bls12_381::Bls12;
use group::GroupEncoding;
use sapling_crypto::note::ExtractedNoteCommitment;
use sapling_crypto::value::ValueCommitment;
use sapling_crypto::SaplingVerificationContext;
use serde_json::Value;
use std::io::Read;
use verus_sapling_prover::tx::{shielded_sighash, TxIn, TxOut};

const VERUS_SAPLING_BRANCH_ID: u32 = 0x76b8_09bb;

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}
fn h32(s: &str) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(&h(s));
    a
}
fn rev32(mut a: [u8; 32]) -> [u8; 32] {
    a.reverse();
    a
}
fn h64(s: &str) -> [u8; 64] {
    let mut a = [0u8; 64];
    a.copy_from_slice(&h(s));
    a
}

fn main() {
    let path = std::env::args().nth(1).expect("json path arg");
    let mut s = String::new();
    std::fs::File::open(&path).unwrap().read_to_string(&mut s).unwrap();
    let d: Value = serde_json::from_str(&s).unwrap();

    // --- transparent inputs/outputs (may be empty) ---
    let inputs: Vec<TxIn> = d["vin"].as_array().map_or(vec![], |a| {
        a.iter()
            .map(|i| {
                let mut txid = h(i["txid"].as_str().unwrap());
                txid.reverse();
                let mut txid_internal = [0u8; 32];
                txid_internal.copy_from_slice(&txid);
                TxIn {
                    txid_internal,
                    vout: i["vout"].as_u64().unwrap() as u32,
                    sequence: i["sequence"].as_u64().unwrap() as u32,
                }
            })
            .collect()
    });
    let outputs: Vec<TxOut> = d["vout"].as_array().map_or(vec![], |a| {
        a.iter()
            .map(|o| TxOut {
                value: (o["value"].as_f64().unwrap() * 1e8).round() as u64,
                script_pubkey: h(o["scriptPubKey"]["hex"].as_str().unwrap()),
            })
            .collect()
    });
    let lock_time = d["locktime"].as_u64().unwrap_or(0) as u32;
    let expiry = d["expiryheight"].as_u64().unwrap() as u32;
    let value_balance = (d["valueBalance"].as_f64().unwrap() * 1e8).round() as i64;

    // --- shielded spends ---
    struct Spend {
        cv: [u8; 32],
        anchor: [u8; 32],
        nullifier: [u8; 32],
        rk: [u8; 32],
        proof: Vec<u8>,
        auth_sig: [u8; 64],
        sighash_desc: Vec<u8>, // cv||anchor||nullifier||rk||proof (no auth sig)
    }
    let spends: Vec<Spend> = d["vShieldedSpend"].as_array().map_or(vec![], |a| {
        a.iter()
            .map(|s| {
                let cv = rev32(h32(s["cv"].as_str().unwrap()));
                let anchor = rev32(h32(s["anchor"].as_str().unwrap()));
                let nullifier = rev32(h32(s["nullifier"].as_str().unwrap()));
                let rk = rev32(h32(s["rk"].as_str().unwrap()));
                let proof = h(s["proof"].as_str().unwrap());
                let auth_sig = h64(s["spendAuthSig"].as_str().unwrap());
                let mut sighash_desc = Vec::new();
                sighash_desc.extend_from_slice(&cv);
                sighash_desc.extend_from_slice(&anchor);
                sighash_desc.extend_from_slice(&nullifier);
                sighash_desc.extend_from_slice(&rk);
                sighash_desc.extend_from_slice(&proof);
                Spend { cv, anchor, nullifier, rk, proof, auth_sig, sighash_desc }
            })
            .collect()
    });

    // --- shielded outputs ---
    struct Out {
        cv: [u8; 32],
        cmu: [u8; 32],
        epk: [u8; 32],
        proof: Vec<u8>,
        desc: Vec<u8>,
    }
    let outs: Vec<Out> = d["vShieldedOutput"].as_array().map_or(vec![], |a| {
        a.iter()
            .map(|o| {
                let cv = rev32(h32(o["cv"].as_str().unwrap()));
                let cmu = rev32(h32(o["cmu"].as_str().unwrap()));
                let epk = rev32(h32(o["ephemeralKey"].as_str().unwrap()));
                let enc = h(o["encCiphertext"].as_str().unwrap());
                let oc = h(o["outCiphertext"].as_str().unwrap());
                let proof = h(o["proof"].as_str().unwrap());
                let mut desc = Vec::new();
                for part in [&cv[..], &cmu[..], &epk[..], &enc, &oc, &proof] {
                    desc.extend_from_slice(part);
                }
                Out { cv, cmu, epk, proof, desc }
            })
            .collect()
    });

    let spend_descs: Vec<Vec<u8>> = spends.iter().map(|s| s.sighash_desc.clone()).collect();
    let out_descs: Vec<Vec<u8>> = outs.iter().map(|o| o.desc.clone()).collect();

    let sighash = shielded_sighash(
        VERUS_SAPLING_BRANCH_ID,
        &inputs,
        &outputs,
        lock_time,
        expiry,
        value_balance,
        &spend_descs,
        &out_descs,
    );
    println!(
        "flow: vin={} vout={} spends={} outputs={} valueBalance={}",
        inputs.len(),
        outputs.len(),
        spends.len(),
        outs.len(),
        value_balance
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

    for s in &spends {
        let cv = ValueCommitment::from_bytes_not_small_order(&s.cv).unwrap();
        let anchor = bls12_381::Scalar::from_bytes(&s.anchor).unwrap();
        let rk = redjubjub::VerificationKey::try_from(s.rk).expect("rk");
        let auth_sig = redjubjub::Signature::from(s.auth_sig);
        let proof = Proof::<Bls12>::read(&s.proof[..]).expect("spend proof");
        let ok = ctx.check_spend(&cv, anchor, &s.nullifier, rk, &sighash, auth_sig, proof, &spvk);
        println!("check_spend (proof + auth-sig under OUR sighash): {ok}");
    }

    for o in &outs {
        let cv = ValueCommitment::from_bytes_not_small_order(&o.cv).unwrap();
        let cmu = ExtractedNoteCommitment::from_bytes(&o.cmu).unwrap();
        let epk = jubjub::ExtendedPoint::from_bytes(&o.epk).expect("epk");
        let proof = Proof::<Bls12>::read(&o.proof[..]).expect("output proof");
        let ok = ctx.check_output(&cv, cmu, epk, proof, &opvk);
        println!("check_output (proof valid): {ok}");
    }

    let binding_sig = redjubjub::Signature::<redjubjub::Binding>::from(h64(d["bindingSig"].as_str().unwrap()));
    let final_ok = ctx.final_check(value_balance, &sighash, binding_sig);
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

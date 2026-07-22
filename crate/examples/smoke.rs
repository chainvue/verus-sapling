//! Native smoke test: load the real Sapling params and prove a t->z bundle.
//!
//! Run: cargo run --example smoke --release -- <spend.params> <output.params>
//! (defaults to the standard macOS ZcashParams location).
//!
//! This proves the crypto pipeline end-to-end natively. The sighash here is a
//! placeholder, so the binding signature is NOT chain-valid — that arrives with
//! the ZIP-243 sighash + v4 serializer tranche. What this validates: real
//! Groth16 output proving, note encryption (memo), value balance, and binding
//! signature all run against the actual params.

use sapling_crypto::note_encryption::Zip212Enforcement;
use sapling_crypto::zip32::ExtendedSpendingKey;
use verus_sapling_prover::{load_params, prove_shield, ShieldOutput, MEMO_SIZE};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let home = std::env::var("HOME").unwrap_or_default();
    let spend = args.get(1).cloned().unwrap_or_else(|| {
        format!("{home}/Library/Application Support/ZcashParams/sapling-spend.params")
    });
    let output = args.get(2).cloned().unwrap_or_else(|| {
        format!("{home}/Library/Application Support/ZcashParams/sapling-output.params")
    });

    eprintln!("loading params...\n  {spend}\n  {output}");
    let (sp, op) = load_params(&spend, &output).expect("load params");

    // Derive a valid Sapling payment address to shield into.
    let extsk = ExtendedSpendingKey::master(&[7u8; 32]);
    let (_idx, addr) = extsk.to_diversifiable_full_viewing_key().default_address();
    let recipient = addr.to_bytes();

    // Memo "Hello-t2z" (matches the golden vector's memo), zero-padded to 512.
    let mut memo = [0u8; MEMO_SIZE];
    let m = b"Hello-t2z";
    memo[..m.len()].copy_from_slice(m);

    let outputs = vec![ShieldOutput {
        recipient,
        value: 100_000_000, // 1.0 VRSCTEST in zatoshi
        memo,
    }];

    eprintln!("proving (real Groth16 output proof)...");
    let placeholder_sighash = [0u8; 32];
    let proven = prove_shield(&outputs, &sp, &op, placeholder_sighash, Zip212Enforcement::Off)
        .expect("prove_shield");

    println!("== t->z bundle proved natively ==");
    println!("value_balance      : {}", proven.value_balance);
    println!("shielded_outputs   : {}", proven.shielded_outputs.len());
    println!(
        "output desc bytes  : {} (expect 948 = 32+32+32+580+80+192)",
        proven.shielded_outputs[0].len()
    );
    println!("binding_sig        : {}", hex::encode(proven.binding_sig));
    assert_eq!(proven.value_balance, -100_000_000, "t->z valueBalance sign");
    assert_eq!(proven.shielded_outputs[0].len(), 948, "output desc size");
    println!("OK");
}

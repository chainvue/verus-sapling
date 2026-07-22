//! Regression net for the ZIP-243 sighash + v4 serializer — the code path that
//! once carried a branch-id decimal typo (0x76b809bb = 1991772603). For each
//! flow (t->z, z->z, z->t) we recompute our sighash from the daemon-made golden
//! vector and assert it equals a baked-in constant.
//!
//! These constants are NOT arbitrary: each was produced by `verify_golden`,
//! whose `final_check` cryptographically confirmed the daemon's binding
//! signature verifies under that exact sighash. So a mismatch here means the
//! serializer/sighash drifted away from a byte layout the Verus daemon accepts.
//! This test needs no proving params, so it runs in plain `cargo test`.

use serde_json::Value;
use verus_sapling_prover::golden::GoldenTx;

const VERUS_SAPLING_BRANCH_ID: u32 = 0x76b8_09bb;

fn sighash_for(vector: &str) -> String {
    let path = format!("{}/../test/vectors/{vector}.json", env!("CARGO_MANIFEST_DIR"));
    let s = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let d: Value = serde_json::from_str(&s).expect("parse vector json");
    let tx = GoldenTx::from_decoded_json(&d).expect("decode golden tx");
    hex::encode(tx.sighash(VERUS_SAPLING_BRANCH_ID))
}

#[test]
fn t2z_sighash_matches_daemon() {
    assert_eq!(
        sighash_for("t2z"),
        "080034d33ac637cf354a218818f799c74ab8c3900a39f48b5d4bfbdb7cde7f3c"
    );
}

#[test]
fn z2z_sighash_matches_daemon() {
    assert_eq!(
        sighash_for("z2z"),
        "52843b719955d380c8d08e56a59526d533a14397e79b615f829a374aafd472d0"
    );
}

#[test]
fn z2t_sighash_matches_daemon() {
    assert_eq!(
        sighash_for("z2t"),
        "82dabe7bf06f7d064ccb8791b14376018ae87a7a8f7eaa90bd65fcb49c864cc7"
    );
}

/// The branch id is load-bearing in the sighash personalization; a wrong one
/// must NOT reproduce the daemon's sighash. Guards against silently reverting
/// the id or its decimal form.
#[test]
fn wrong_branch_id_changes_sighash() {
    let path = format!("{}/../test/vectors/t2z.json", env!("CARGO_MANIFEST_DIR"));
    let d: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let tx = GoldenTx::from_decoded_json(&d).unwrap();
    assert_ne!(
        hex::encode(tx.sighash(VERUS_SAPLING_BRANCH_ID)),
        hex::encode(tx.sighash(0x76b8_09bc)) // off by one
    );
}

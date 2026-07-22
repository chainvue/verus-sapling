//! Build a z->z / z->t Sapling v4 tx from a JSON spec on stdin; print tx hex.
//! Thin wrapper over `json_api::build_zspend_from_json` (shared with the wasm build).

use std::io::Read;
use verus_sapling_prover::json_api::build_zspend_from_json;

fn main() {
    let mut spec = String::new();
    std::io::stdin().read_to_string(&mut spec).expect("read stdin");
    let home = std::env::var("HOME").unwrap_or_default();
    let (sp, op) = verus_sapling_prover::load_params(
        &format!("{home}/Library/Application Support/ZcashParams/sapling-spend.params"),
        &format!("{home}/Library/Application Support/ZcashParams/sapling-output.params"),
    )
    .expect("load params");
    println!("{}", build_zspend_from_json(&spec, &sp, &op).expect("build zspend"));
}

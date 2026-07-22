//! Native note-detection runner: read a detect spec (JSON) on argv[1], trial-
//! decrypt, print the detected notes as JSON. No params, no proving.
//!
//!   cargo run --release --example detect -- detect_spec.json
use std::fs;
use verus_sapling_prover::json_api::detect_notes_from_json;

fn main() {
    let path = std::env::args().nth(1).expect("usage: detect <spec.json>");
    let spec = fs::read_to_string(&path).expect("read spec");
    match detect_notes_from_json(&spec) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("detect error: {e}");
            std::process::exit(1);
        }
    }
}

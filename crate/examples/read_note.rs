//! Fully decrypt an incoming Sapling output (value + recipient + memo) from a
//! JSON spec on argv[1]. No params, no proving.
//!
//!   cargo run --release --example read_note -- read_spec.json
use std::fs;
use verus_sapling_prover::json_api::read_note_from_json;

fn main() {
    let path = std::env::args().nth(1).expect("usage: read_note <spec.json>");
    let spec = fs::read_to_string(&path).expect("read spec");
    match read_note_from_json(&spec) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("read error: {e}");
            std::process::exit(1);
        }
    }
}

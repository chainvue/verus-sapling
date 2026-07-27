//! Native ZIP-32 derivation runner: read a derivation spec (JSON) on STDIN,
//! print the derived account as JSON. No params, no proving.
//!
//!   echo '{"seed_hex":"…","coin_type":133,"account":0}' \
//!     | cargo run --release --example derive_address
//!
//! STDIN, not argv or a file, on purpose: the seed is key material, and this
//! keeps it out of the process table, the shell history, and the disk.
use std::io::Read;
use verus_sapling_prover::json_api::derive_account_from_json;

fn main() {
    let mut spec = String::new();
    std::io::stdin().read_to_string(&mut spec).expect("read spec from stdin");
    match derive_account_from_json(&spec) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("derive error: {e}");
            std::process::exit(1);
        }
    }
}

//! wasm-bindgen boundary for browsers / JS runtimes.
//!
//! The JS side loads the two Sapling params files (byte-identical to Zcash's)
//! and passes them plus a JSON request; these return the signed transaction hex.
//! Single-threaded proving (no `multicore` on wasm). Proving is CPU-heavy —
//! call from a Web Worker.

use wasm_bindgen::prelude::*;

use crate::json_api::{
    build_t2z_from_json, build_zspend_from_json, detect_notes_from_json, read_note_from_json,
};
use crate::load_params_from_bytes;

/// Build + sign a t->z shielding transaction. `spec_json` is the t->z request
/// (see `json_api::build_t2z_from_json`). Returns the transaction hex; the caller
/// still has the daemon fill the transparent scriptSig (signrawtransaction).
#[wasm_bindgen]
pub fn shield_t2z(
    spec_json: &str,
    spend_params: &[u8],
    output_params: &[u8],
) -> Result<String, JsError> {
    let (sp, op) = load_params_from_bytes(spend_params, output_params).map_err(js)?;
    build_t2z_from_json(spec_json, &sp, &op).map_err(js)
}

/// Build + sign a z->z / z->t transaction that spends a shielded note. Complete
/// after this (no transparent inputs) — broadcast directly.
#[wasm_bindgen]
pub fn spend_shielded(
    spec_json: &str,
    spend_params: &[u8],
    output_params: &[u8],
) -> Result<String, JsError> {
    let (sp, op) = load_params_from_bytes(spend_params, output_params).map_err(js)?;
    build_zspend_from_json(spec_json, &sp, &op).map_err(js)
}

/// Detect the wallet's own notes by trial-decrypting compact outputs (read path
/// — no params, no proving). `spec_json` is the note-detection request (see
/// `json_api::detect_notes_from_json`). Returns a JSON array of detected notes.
/// Cheap (milliseconds); safe to call on the main thread.
#[wasm_bindgen]
pub fn detect_notes(spec_json: &str) -> Result<String, JsError> {
    detect_notes_from_json(spec_json).map_err(js)
}

/// Fully decrypt one incoming output (value + recipient + memo) with the
/// wallet's viewing key. `spec_json` is the read request (see
/// `json_api::read_note_from_json`). Returns a JSON object, or the string
/// "null" if the output is not for this key. Cheap (no params, no proving).
#[wasm_bindgen]
pub fn read_note(spec_json: &str) -> Result<String, JsError> {
    read_note_from_json(spec_json).map_err(js)
}

fn js(e: String) -> JsError {
    JsError::new(&e)
}

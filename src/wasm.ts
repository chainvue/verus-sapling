/**
 * TypeScript loader for the Sapling proving wasm module.
 *
 * The wasm (built from `crate/` via `wasm-pack build --target web`, output in
 * `crate/pkg/`) exposes two builders. The caller supplies the two Sapling params
 * files (byte-identical to Zcash's `sapling-spend.params` / `sapling-output.params`,
 * ~50MB total) and a JSON request; the builders return the signed transaction hex.
 *
 * Proving is CPU-heavy (~5s single-threaded per tx) — run it off the main thread
 * (a Web Worker in the browser). This module is the concrete `SaplingBackend`.
 *
 * STATUS: verified end-to-end — a t->z built through this wasm in Node was
 * accepted by the Verus testnet daemon (txid d142edf8…a0ef).
 */

// The generated glue is ESM (wasm-pack, crate/pkg). In a bundler/browser, import
// the pkg directly.
import initWasm, {
  shield_t2z,
  spend_shielded,
  detect_notes,
  read_note,
} from '../crate/pkg/verus_sapling_prover.js';

let ready: Promise<void> | undefined;

/**
 * Initialize the wasm module. Pass the `.wasm` bytes/URL/Response; in Node,
 * read `crate/pkg/verus_sapling_prover_bg.wasm` and pass the bytes.
 */
export function initSapling(wasm: BufferSource | URL | Response | Promise<Response>): Promise<void> {
  if (!ready) ready = initWasm({ module_or_path: wasm }).then(() => undefined);
  return ready;
}

/** Params, loaded by the caller (fetch / fs). */
export interface SaplingParams {
  spend: Uint8Array; // sapling-spend.params
  output: Uint8Array; // sapling-output.params
}

/**
 * Build + sign a t->z shielding tx from a JSON spec (see the Rust
 * `json_api::build_t2z_from_json` shape). Returns tx hex; the consumer still has
 * the daemon fill the transparent scriptSig via `signrawtransaction`.
 * Call `initSapling` first.
 */
export function shieldT2z(specJson: string, params: SaplingParams): string {
  return shield_t2z(specJson, params.spend, params.output);
}

/**
 * Build + sign a z->z / z->t tx that spends a shielded note (JSON spec per
 * `json_api::build_zspend_from_json`). Complete after this (no transparent
 * inputs) — broadcast directly. Call `initSapling` first.
 */
export function spendShielded(specJson: string, params: SaplingParams): string {
  return spend_shielded(specJson, params.spend, params.output);
}

/** A note detected by trial-decryption (see `detectNotes`). All 32-byte fields hex. */
export interface DetectedNoteRaw {
  height: number;
  tx_index: number;
  output_index: number;
  /** 0-based leaf position in the note-commitment tree. */
  position: number;
  /** Note value in zatoshi (safe: below 2^53 for VRSC supply). */
  value: number;
  /** 43-byte Sapling payment address the note pays to (one of the wallet's). */
  recipient_hex: string;
  /** Note nullifier — appears in a future spend's vShieldedSpend. */
  nullifier_hex: string;
}

/**
 * Trial-decrypt compact Sapling outputs to find the wallet's own notes (read
 * path — no params, no proving; runs in milliseconds). `specJson` is the
 * note-detection request (see the Rust `json_api::detect_notes_from_json`).
 * Does NOT require `initSapling` params, but the wasm module must be
 * initialized. Safe on the main thread.
 */
export function detectNotes(specJson: string): DetectedNoteRaw[] {
  return JSON.parse(detect_notes(specJson)) as DetectedNoteRaw[];
}

/** A fully-decrypted incoming note (see `readNote`). */
export interface ReadNoteResult {
  /** Note value in zatoshi. */
  value: number;
  /** 43-byte Sapling payment address the note pays to (hex). */
  recipient_hex: string;
  /** Full 512-byte memo as hex. */
  memo_hex: string;
  /** Memo decoded as UTF-8 text (trimmed at the first 0x00/0xf6 pad byte). */
  memo_text: string;
}

/**
 * Fully decrypt one incoming output — value + recipient + memo — with the
 * wallet's viewing key. `specJson` is the read request (see the Rust
 * `json_api::read_note_from_json`): `{ extsk_hex | dfvk_hex, out:{cv,cmu,epk,enc,ct,proof} }`.
 * Returns `null` if the output is not for this key. Cheap (no params, no proving).
 */
export function readNote(specJson: string): ReadNoteResult | null {
  return JSON.parse(read_note(specJson)) as ReadNoteResult | null;
}

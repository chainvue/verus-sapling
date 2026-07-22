/* tslint:disable */
/* eslint-disable */

/**
 * Detect the wallet's own notes by trial-decrypting compact outputs (read path
 * — no params, no proving). `spec_json` is the note-detection request (see
 * `json_api::detect_notes_from_json`). Returns a JSON array of detected notes.
 * Cheap (milliseconds); safe to call on the main thread.
 */
export function detect_notes(spec_json: string): string;

/**
 * Fully decrypt one incoming output (value + recipient + memo) with the
 * wallet's viewing key. `spec_json` is the read request (see
 * `json_api::read_note_from_json`). Returns a JSON object, or the string
 * "null" if the output is not for this key. Cheap (no params, no proving).
 */
export function read_note(spec_json: string): string;

/**
 * Build + sign a t->z shielding transaction. `spec_json` is the t->z request
 * (see `json_api::build_t2z_from_json`). Returns the transaction hex; the caller
 * still has the daemon fill the transparent scriptSig (signrawtransaction).
 */
export function shield_t2z(spec_json: string, spend_params: Uint8Array, output_params: Uint8Array): string;

/**
 * Build + sign a z->z / z->t transaction that spends a shielded note. Complete
 * after this (no transparent inputs) — broadcast directly.
 */
export function spend_shielded(spec_json: string, spend_params: Uint8Array, output_params: Uint8Array): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly detect_notes: (a: number, b: number) => [number, number, number, number];
    readonly read_note: (a: number, b: number) => [number, number, number, number];
    readonly shield_t2z: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly spend_shielded: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;

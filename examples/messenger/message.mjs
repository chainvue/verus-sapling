/**
 * Memo framing for a shielded messenger. Two layers:
 *   - transport frame: a 12-byte header + chunking, so a message > 500 bytes
 *     spans multiple 512-byte memos (same msgId).
 *   - payload: JSON `{ v, from?, ts, text }` after reassembly.
 *
 * The frame starts with 0xFF — ZIP-302 reserves that leading byte for
 * "arbitrary bytes", so spec-following wallets won't try to render the binary
 * as a text memo.
 *
 * Frame (512 bytes):
 *   [0]      0xFF            ZIP-302 arbitrary-bytes marker
 *   [1..3)   "VM"            app magic
 *   [3]      version (1)
 *   [4..8)   msgId (4)       groups the chunks of one message
 *   [8]      chunkIndex
 *   [9]      chunkCount
 *   [10..12) bodyLen (u16 BE)
 *   [12..]   body            (<= 500 bytes), then zero padding
 */
import { bytesToHex, hexToBytes } from '../../dist/hex.js';

const MARKER = 0xff;
const MAGIC = [0x56, 0x4d]; // "VM"
const VERSION = 1;
const MEMO = 512;
const HEADER = 12;
const MAX_BODY = MEMO - HEADER; // 500

/** Encode a message → one or more 512-byte memos (hex). */
export function encodeMessage(msg) {
  const body = new TextEncoder().encode(JSON.stringify({ v: VERSION, ...msg }));
  const count = Math.max(1, Math.ceil(body.length / MAX_BODY));
  if (count > 255) throw new Error('message too long (> 255 chunks)');
  const msgId = crypto.getRandomValues(new Uint8Array(4));
  const memos = [];
  for (let i = 0; i < count; i++) {
    const chunk = body.subarray(i * MAX_BODY, i * MAX_BODY + MAX_BODY);
    const m = new Uint8Array(MEMO);
    m[0] = MARKER;
    m[1] = MAGIC[0];
    m[2] = MAGIC[1];
    m[3] = VERSION;
    m.set(msgId, 4);
    m[8] = i;
    m[9] = count;
    m[10] = (chunk.length >> 8) & 0xff;
    m[11] = chunk.length & 0xff;
    m.set(chunk, HEADER);
    memos.push(bytesToHex(m));
  }
  return memos;
}

/** Decode one memo (hex) → a chunk, or null if it isn't one of our frames. */
export function decodeMemo(memoHex) {
  const m = hexToBytes(memoHex);
  if (m.length < HEADER || m[0] !== MARKER || m[1] !== MAGIC[0] || m[2] !== MAGIC[1]) return null;
  const len = (m[10] << 8) | m[11];
  return {
    msgId: bytesToHex(m.subarray(4, 8)),
    index: m[8],
    count: m[9],
    body: m.subarray(HEADER, HEADER + len),
  };
}

/** Collects chunks; returns the full message when all chunks of a msgId arrive. */
export class Reassembler {
  #parts = new Map();
  #done = new Set();

  add(chunk) {
    if (this.#done.has(chunk.msgId)) return null;
    let map = this.#parts.get(chunk.msgId);
    if (!map) this.#parts.set(chunk.msgId, (map = new Map()));
    map.set(chunk.index, chunk.body);
    if (map.size !== chunk.count) return null;
    const ordered = [];
    for (let i = 0; i < chunk.count; i++) {
      const p = map.get(i);
      if (!p) return null; // missing a chunk
      ordered.push(p);
    }
    this.#done.add(chunk.msgId);
    this.#parts.delete(chunk.msgId);
    const total = new Uint8Array(ordered.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of ordered) {
      total.set(p, o);
      o += p.length;
    }
    return JSON.parse(new TextDecoder().decode(total));
  }
}

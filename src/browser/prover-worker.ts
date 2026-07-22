/**
 * Web Worker entry for Sapling proving. The spend prove is ~20 s single-threaded
 * — running it on the main thread would freeze the extension UI, so it lives
 * here. Detection is cheap but is offered too, so a caller can keep ALL wasm off
 * the main thread if it wants.
 *
 * Protocol (postMessage):
 *   → { type:'init', wasmBytes, spendParams, outputParams }   ⇒ { type:'ready' }
 *   → { type:'spend',  id, spec }   ⇒ { type:'result', id, value }  | { type:'error', id, message }
 *   → { type:'detect', id, spec }   ⇒ { type:'result', id, value }  | { type:'error', id, message }
 *
 * Bundle this as a module worker:
 *   new Worker(new URL('./prover-worker.js', import.meta.url), { type: 'module' })
 *
 * The params (~50 MB) are transferred in once at init and held for every prove,
 * so they cross the worker boundary only once.
 */

import { detectNotes, initSapling, readNote, spendShielded, type SaplingParams } from '../wasm.js';

// Minimal worker-global shape — avoids pulling in the `webworker` lib (which
// conflicts with `dom`'s `self`) while staying type-safe about what we use.
const ctx = globalThis as unknown as {
  postMessage: (message: unknown) => void;
  addEventListener: (type: 'message', listener: (e: { data: unknown }) => void) => void;
};

type InitMsg = { type: 'init'; wasmBytes: ArrayBuffer; spendParams: Uint8Array; outputParams: Uint8Array };
type SpendMsg = { type: 'spend'; id: number; spec: string };
type DetectMsg = { type: 'detect'; id: number; spec: string };
type ReadMsg = { type: 'read'; id: number; spec: string };
type InMsg = InitMsg | SpendMsg | DetectMsg | ReadMsg;

let params: SaplingParams | undefined;

ctx.addEventListener('message', (e) => {
  const msg = e.data as InMsg;
  void handle(msg);
});

async function handle(msg: InMsg): Promise<void> {
  try {
    if (msg.type === 'init') {
      await initSapling(msg.wasmBytes);
      params = { spend: msg.spendParams, output: msg.outputParams };
      ctx.postMessage({ type: 'ready' });
      return;
    }
    if (msg.type === 'spend') {
      if (!params) throw new Error('worker not initialized (send { type: "init" } first)');
      const hex = spendShielded(msg.spec, params);
      ctx.postMessage({ type: 'result', id: msg.id, value: hex });
      return;
    }
    if (msg.type === 'detect') {
      const notes = detectNotes(msg.spec);
      ctx.postMessage({ type: 'result', id: msg.id, value: notes });
      return;
    }
    if (msg.type === 'read') {
      const note = readNote(msg.spec);
      ctx.postMessage({ type: 'result', id: msg.id, value: note });
      return;
    }
  } catch (err) {
    const id = 'id' in msg ? msg.id : -1;
    ctx.postMessage({ type: 'error', id, message: err instanceof Error ? err.message : String(err) });
  }
}

/**
 * Main-thread handle to the proving Web Worker. Wraps the postMessage protocol
 * of `./prover-worker` into promise-returning `SpendProver` / `DetectProver`
 * callbacks that plug straight into `../wallet`'s `detectNotes` /
 * `buildShieldedSpend`.
 *
 * The caller constructs the `Worker` (its URL is bundler-specific) and passes
 * the wasm bytes + the two Sapling params; this initializes the worker once and
 * hands back the callbacks. Keeps the ~20 s spend prove off the UI thread.
 *
 *   const worker = new Worker(new URL('./prover-worker.js', import.meta.url), { type: 'module' });
 *   const prover = await createWorkerProver(worker, { wasmBytes, spendParams, outputParams });
 *   const { hex } = await buildShieldedSpend(client, prover.spend, { ... });
 */

import type { DetectProver, SpendProver } from '../wallet.js';
import type { DetectedNoteRaw, ReadNoteResult } from '../wasm.js';

/** Fully decrypt one incoming output (value + recipient + memo) in the worker. */
export type ReadProver = (specJson: string) => Promise<ReadNoteResult | null>;

export interface WorkerProverInit {
  /** The `.wasm` bytes (fetch `crate/pkg/verus_sapling_prover_bg.wasm`). */
  readonly wasmBytes: ArrayBuffer;
  /** sapling-spend.params bytes. */
  readonly spendParams: Uint8Array;
  /** sapling-output.params bytes. */
  readonly outputParams: Uint8Array;
}

export interface WorkerProver {
  /** Prove + sign a shielded spend in the worker (~20 s). */
  readonly spend: SpendProver;
  /** Trial-decrypt notes in the worker (cheap; use only to keep wasm off-thread). */
  readonly detect: DetectProver;
  /** Fully decrypt one incoming output → value + recipient + memo (cheap). */
  readonly read: ReadProver;
  /** Terminate the worker. */
  readonly terminate: () => void;
}

type OutMsg =
  | { type: 'ready' }
  | { type: 'result'; id: number; value: unknown }
  | { type: 'error'; id: number; message: string };

/** Initialize the worker (loads wasm + params once) and return the prover callbacks. */
export function createWorkerProver(worker: Worker, init: WorkerProverInit): Promise<WorkerProver> {
  const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  let nextId = 1;
  let readyResolve: (() => void) | undefined;
  const ready = new Promise<void>((r) => (readyResolve = r));

  worker.addEventListener('message', (e: MessageEvent) => {
    const msg = e.data as OutMsg;
    if (msg.type === 'ready') {
      readyResolve?.();
      return;
    }
    const entry = pending.get(msg.id);
    if (!entry) return;
    pending.delete(msg.id);
    if (msg.type === 'error') entry.reject(new Error(msg.message));
    else entry.resolve(msg.value);
  });

  const call = (type: 'spend' | 'detect' | 'read', spec: string): Promise<unknown> => {
    const id = nextId++;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      worker.postMessage({ type, id, spec });
    });
  };

  // Transfer the big params buffers into the worker (no copy).
  worker.postMessage(
    { type: 'init', wasmBytes: init.wasmBytes, spendParams: init.spendParams, outputParams: init.outputParams },
    [init.wasmBytes, init.spendParams.buffer, init.outputParams.buffer],
  );

  return ready.then(() => ({
    spend: (spec: string) => call('spend', spec) as Promise<string>,
    detect: (spec: string) => call('detect', spec) as Promise<DetectedNoteRaw[]>,
    read: (spec: string) => call('read', spec) as Promise<ReadNoteResult | null>,
    terminate: () => worker.terminate(),
  }));
}

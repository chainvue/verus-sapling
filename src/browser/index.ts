/**
 * Browser entry for `@chainvue/verus-sapling` — everything needed to run the
 * shielded wallet in a browser extension, with NO Node dependency
 * (no `@grpc/grpc-js`, no `Buffer`):
 *
 *  - `LightwalletdWebClient` — `LightwalletdTransport` over gRPC-web (`fetch`),
 *    pointed at a gRPC-web proxy in front of lightwalletd.
 *  - `createWorkerProver` — runs the ~20 s Sapling spend prove in a Web Worker.
 *
 * Combine with `detectNotes` / `buildShieldedSpend` from the package root:
 *
 *   import { detectNotes, buildShieldedSpend } from '@chainvue/verus-sapling';
 *   import { LightwalletdWebClient, createWorkerProver } from '@chainvue/verus-sapling/browser';
 *
 *   const client = new LightwalletdWebClient('http://localhost:8080');
 *   const worker = new Worker(new URL('./prover-worker.js', import.meta.url), { type: 'module' });
 *   const prover = await createWorkerProver(worker, { wasmBytes, spendParams, outputParams });
 *   const notes = await detectNotes(client, prover.detect, { key: { extskHex }, fromHeight });
 *   const { hex } = await buildShieldedSpend(client, prover.spend, { note, shieldedOutputs });
 *   await client.sendTransaction(hex);
 */

export { LightwalletdWebClient, blockTxid } from './lightwalletd-web.js';
export {
  createWorkerProver,
  type WorkerProver,
  type WorkerProverInit,
} from './worker-prover.js';

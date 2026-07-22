/**
 * Web Worker entry — just loads the package's prover worker, which registers the
 * message handler on import. Bundled by esbuild into `worker.js` and spawned from
 * the popup via `new Worker(chrome.runtime.getURL('worker.js'), { type: 'module' })`.
 */
import '../../dist/browser/prover-worker.js';

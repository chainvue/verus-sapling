/**
 * Build the demo extension: bundle popup.ts + worker.ts (esbuild), and emit the
 * wasm (via the file loader, stable name) + manifest + html into ./build.
 * Prereq: the package is built (`npm run build`) — popup imports from dist/.
 *
 *   node examples/extension/build.mjs      (or: npm run build:ext)
 *   then load examples/extension/build/ as an unpacked MV3 extension.
 */
import * as esbuild from 'esbuild';
import { cpSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const dir = dirname(fileURLToPath(import.meta.url));
const out = join(dir, 'build');
mkdirSync(out, { recursive: true });

await esbuild.build({
  entryPoints: [join(dir, 'popup.ts'), join(dir, 'worker.ts')],
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: 'es2022',
  outdir: out,
  // The wasm-pack glue references the .wasm via `new URL(..., import.meta.url)`;
  // the file loader copies it out under its real name (we load it at runtime via
  // chrome.runtime.getURL). '[name]' keeps the name stable (no content hash).
  loader: { '.wasm': 'file' },
  assetNames: '[name]',
  logLevel: 'info',
});

cpSync(join(dir, 'manifest.json'), join(out, 'manifest.json'));
cpSync(join(dir, 'popup.html'), join(out, 'popup.html'));
// The wasm is loaded at runtime via chrome.runtime.getURL (we pass its bytes to
// the worker), so copy it in under its fixed name.
cpSync(
  join(dir, '..', '..', 'crate', 'pkg', 'verus_sapling_prover_bg.wasm'),
  join(out, 'verus_sapling_prover_bg.wasm'),
);
console.log('\nextension built →', out);
console.log('load it: chrome://extensions → Developer mode → Load unpacked → select that folder');

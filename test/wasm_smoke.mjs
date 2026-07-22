// Build a shielded tx THROUGH the wasm module (proves the wasm path works).
// Usage: node wasm_smoke.mjs <spec.json> <shield_t2z|spend_shielded>
import { readFileSync } from "node:fs";
import init, {
  shield_t2z,
  spend_shielded,
} from "../crate/pkg/verus_sapling_prover.js";

const [, , specPath, fn = "shield_t2z"] = process.argv;
const wasmBytes = readFileSync(
  new URL("../crate/pkg/verus_sapling_prover_bg.wasm", import.meta.url),
);
await init(wasmBytes);

const home = process.env.HOME;
const base = `${home}/Library/Application Support/ZcashParams`;
const spend = new Uint8Array(readFileSync(`${base}/sapling-spend.params`));
const output = new Uint8Array(readFileSync(`${base}/sapling-output.params`));
const spec = readFileSync(specPath, "utf8");

const build = fn === "spend_shielded" ? spend_shielded : shield_t2z;
const t0 = Date.now();
const hex = build(spec, spend, output);
process.stderr.write(`proved in wasm in ${Date.now() - t0}ms\n`);
console.log(hex);

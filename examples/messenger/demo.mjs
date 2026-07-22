/**
 * End-to-end shielded messenger demo: send a chat message (as a 0-value note +
 * framed memo) to an address, then scan the chain and read it back — all with
 * the SDK's own detection + decryption, via lightwalletd. No full node.
 *
 *   node demo.mjs <extsk-file> <my-zs-address> <fromHeight> ["message text"]
 *
 * Uses one spendable note of <my-zs-address> to pay the fee; the message goes to
 * the same address (send-to-self), change returns to it. Needs the lightwalletd
 * gRPC-web proxy at http://localhost:8080 and the wasm built (crate/pkg).
 */
import { readFileSync } from 'node:fs';
import { encodeMessage, decodeMemo, Reassembler } from './message.mjs';

const PKG = '/Users/robertlech/Developer/verus-sapling';
const WASM = PKG + '/crate/pkg';
const URL = 'http://localhost:8080';
const FEE = 10000n; // 0.0001 VRSC

const extskHex = readFileSync(process.argv[2], 'utf8').trim();
const myAddr = process.argv[3];
const fromHeight = Number(process.argv[4]);
const text = process.argv[5] ?? 'gm from a shielded memo 👋 — chunked, encrypted, on-chain.';

const { LightwalletdWebClient } = await import('file://' + PKG + '/dist/browser/index.js');
const { detectNotes, buildShieldedSpend } = await import('file://' + PKG + '/dist/wallet.js');
const { parseSaplingOutput } = await import('file://' + PKG + '/dist/parse.js');
const wasm = await import('file://' + WASM + '/verus_sapling_prover.js');
await wasm.default({ module_or_path: new Uint8Array(readFileSync(WASM + '/verus_sapling_prover_bg.wasm')) });
const spendParams = new Uint8Array(readFileSync(process.env.HOME + '/Library/Application Support/ZcashParams/sapling-spend.params'));
const outputParams = new Uint8Array(readFileSync(process.env.HOME + '/Library/Application Support/ZcashParams/sapling-output.params'));

const client = new LightwalletdWebClient(URL);
const detectProver = (spec) => JSON.parse(wasm.detect_notes(spec));
const spendProver = (spec) => wasm.spend_shielded(spec, spendParams, outputParams);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// read the memo (hex) of a detected note, via lightwalletd + wasm read_note
async function readMemoHex(note) {
  const tx = await client.getTransaction(note.txid);
  const out = parseSaplingOutput(tx.data, note.outputIndex);
  const res = JSON.parse(wasm.read_note(JSON.stringify({ extsk_hex: extskHex, out })));
  return res?.memo_hex ?? null;
}

// ---- 1. SEND ----
const notes = await detectNotes(client, detectProver, { key: { extskHex }, fromHeight });
const funding = notes.find((n) => n.valueSats > FEE);
if (!funding) throw new Error(`no spendable note > fee at ${myAddr} from ${fromHeight} (fund it first)`);
console.log(`funding note: ${(Number(funding.valueSats) / 1e8).toFixed(8)} VRSC (${funding.txid.slice(0, 12)}…)`);

const memos = encodeMessage({ from: myAddr, ts: Math.floor(Date.now() / 1000), text });
const change = funding.valueSats - FEE;
console.log(`message: "${text}"\nframed into ${memos.length} chunk(s); change ${(Number(change) / 1e8).toFixed(8)} VRSC`);

const { hex } = await buildShieldedSpend(client, spendProver, {
  note: { txid: funding.txid, outputIndex: funding.outputIndex, extskHex },
  shieldedOutputs: [
    ...memos.map((memoHex) => ({ address: myAddr, valueSats: 0n, memoHex })), // 0-value message notes
    { address: myAddr, valueSats: change }, // change back to self
  ],
});
const send = await client.sendTransaction(hex);
if (send.errorCode !== 0) throw new Error(`send failed: ${send.errorCode} ${send.errorMessage}`);
console.log(`sent (${hex.length / 2} B tx); waiting for it to mine…\n`);

// ---- 2. INBOX: scan → decrypt → reassemble ----
const bag = new Reassembler();
const scanFrom = fromHeight;
for (let i = 0; i < 16; i++) {
  await sleep(15000);
  const inbox = await detectNotes(client, detectProver, { key: { extskHex }, fromHeight: scanFrom });
  for (const n of inbox) {
    const memoHex = await readMemoHex(n);
    if (!memoHex) continue;
    const chunk = decodeMemo(memoHex);
    if (!chunk) continue; // not a VM message (e.g. change / text memo)
    const msg = bag.add(chunk);
    if (msg) {
      console.log('📩 INBOX — decoded a chat message:');
      console.log(`   from: ${msg.from?.slice(0, 16)}…`);
      console.log(`   ts:   ${new Date(msg.ts * 1000).toISOString()}`);
      console.log(`   text: "${msg.text}"`);
      console.log(`   (note ${n.txid.slice(0, 12)}…:${n.outputIndex}, block ${n.height}, value ${Number(n.valueSats) / 1e8})`);
      client.close();
      process.exit(0);
    }
  }
  console.log(`  … not mined yet (poll ${i + 1})`);
}
console.log('timed out waiting for the message to mine');
client.close();
process.exit(1);

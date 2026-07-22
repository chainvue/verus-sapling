/**
 * Popup UI + orchestration for the minimal shielded demo. Runs on the main
 * thread; all wasm (detection + the ~20 s spend prove) runs in the Web Worker.
 *
 * Flow: load prover (fetch wasm + params → worker) → detect notes over
 * lightwalletd (gRPC-web) → build + broadcast a private spend. The spending key
 * never leaves the popup; only the signed tx bytes go to the network.
 *
 * Imports the BUILT package (dist/*) so esbuild has plain JS to bundle.
 */

// Import the granular SDK-free modules (NOT dist/index.js, which re-exports
// errors.ts → @chainvue/verus-sdk's Node-bundled artifact) so the browser bundle
// stays free of Node builtins.
import { buildShieldedSpend, detectNotes, type SpendableNote } from '../../dist/wallet.js';
import { parseSaplingOutput } from '../../dist/parse.js';
import { LightwalletdWebClient, createWorkerProver, type WorkerProver } from '../../dist/browser/index.js';
import { bytesToHex, hexToBytes, reverseBytes } from '../../dist/hex.js';
import { parseSats } from '../../dist/money.js';
// @ts-expect-error — plain-JS example module (no .d.ts); esbuild bundles it.
import { decodeMemo, Reassembler } from '../messenger/message.mjs';

declare const chrome: { runtime: { getURL(p: string): string }; storage?: { local: { get(k: string[], cb: (v: Record<string, string>) => void): void; set(v: Record<string, string>): void } } };

const $ = (id: string) => document.getElementById(id) as HTMLInputElement;
const statusEl = document.getElementById('status')!;
const logEl = document.getElementById('log')!;
const notesEl = document.getElementById('notes')!;

const log = (m: string) => {
  logEl.textContent += m + '\n';
  logEl.scrollTop = logEl.scrollHeight;
};
const setStatus = (m: string) => (statusEl.textContent = m);

let client: LightwalletdWebClient | undefined;
let prover: WorkerProver | undefined;
let selected: SpendableNote | undefined;

async function loadProver(): Promise<void> {
  $('initBtn').disabled = true;
  const paramsBase = $('paramsUrl').value.replace(/\/$/, '');
  try {
    setStatus('fetching wasm + params…');
    const [wasmBytes, spendParams, outputParams] = await Promise.all([
      fetch(chrome.runtime.getURL('verus_sapling_prover_bg.wasm')).then((r) => r.arrayBuffer()),
      fetch(`${paramsBase}/sapling-spend.params`).then((r) => r.arrayBuffer()).then((b) => new Uint8Array(b)),
      fetch(`${paramsBase}/sapling-output.params`).then((r) => r.arrayBuffer()).then((b) => new Uint8Array(b)),
    ]);
    log(`params loaded (spend ${spendParams.length}B, output ${outputParams.length}B)`);
    setStatus('initializing prover worker…');
    const worker = new Worker(chrome.runtime.getURL('worker.js'), { type: 'module' });
    prover = await createWorkerProver(worker, { wasmBytes, spendParams, outputParams });
    client = new LightwalletdWebClient($('lwdUrl').value.trim());
    const tip = await client.getLatestHeight();
    setStatus(`ready — tip ${tip}`);
    log(`prover ready; lightwalletd tip ${tip}`);
    $('detectBtn').disabled = false;
    $('inboxBtn').disabled = false;
  } catch (e) {
    setStatus('init failed');
    log('ERROR: ' + (e instanceof Error ? e.message : String(e)));
    $('initBtn').disabled = false;
  }
}

async function detect(): Promise<void> {
  if (!client || !prover) return;
  $('detectBtn').disabled = true;
  notesEl.textContent = '';
  const extskHex = $('extsk').value.trim();
  const fromHeight = Number($('fromHeight').value);
  // Spending key → session storage (in-memory, never written to disk, cleared
  // when the browser closes). Only non-secret settings go to local (disk).
  chrome.storage?.session?.set({ extsk: extskHex });
  chrome.storage?.local.set({ lwdUrl: $('lwdUrl').value, fromHeight: String(fromHeight) });
  try {
    setStatus('scanning compact blocks…');
    const notes = await detectNotes(client, prover.detect, { key: { extskHex }, fromHeight });
    setStatus(`found ${notes.length} spendable note(s)`);
    log(`detectNotes: ${notes.length} note(s) from height ${fromHeight}`);
    renderNotes(notes);
  } catch (e) {
    setStatus('detect failed');
    log('ERROR: ' + (e instanceof Error ? e.message : String(e)));
  } finally {
    $('detectBtn').disabled = false;
  }
}

async function readInbox(): Promise<void> {
  if (!client || !prover) return;
  $('inboxBtn').disabled = true;
  const inboxEl = document.getElementById('inbox')!;
  inboxEl.textContent = '';
  const extskHex = $('extsk').value.trim();
  const fromHeight = Number($('fromHeight').value);
  try {
    setStatus('scanning inbox…');
    const notes = await detectNotes(client, prover.detect, { key: { extskHex }, fromHeight });
    const bag = new Reassembler();
    let shown = 0;
    for (const n of notes) {
      const tx = await client.getTransaction(n.txid);
      const out = parseSaplingOutput(tx.data, n.outputIndex);
      const res = await prover.read(JSON.stringify({ extsk_hex: extskHex, out }));
      if (!res) continue;
      const chunk = decodeMemo(res.memo_hex);
      if (chunk) {
        const msg = bag.add(chunk);
        if (msg) { renderMessage(inboxEl, '📩', msg.text, msg.from, n); shown++; }
      } else if (res.memo_text.trim()) {
        renderMessage(inboxEl, '📝', res.memo_text, undefined, n);
        shown++;
      }
    }
    setStatus(`inbox: ${shown} message(s)`);
    if (shown === 0) inboxEl.textContent = 'no messages in this height range';
  } catch (e) {
    setStatus('inbox failed');
    log('ERROR: ' + (e instanceof Error ? e.message : String(e)));
  } finally {
    $('inboxBtn').disabled = false;
  }
}

/** Render one message safely (textContent — never innerHTML for untrusted memos). */
function renderMessage(el: HTMLElement, icon: string, text: string, from: string | undefined, n: SpendableNote): void {
  const div = document.createElement('div');
  div.className = 'note';
  const head = document.createElement('div');
  head.textContent = `${icon} ${text}`;
  const meta = document.createElement('div');
  meta.className = 'muted';
  meta.style.fontSize = '10px';
  meta.textContent = `${from ? 'from ' + from.slice(0, 16) + '… · ' : ''}block ${n.height} · ${(Number(n.valueSats) / 1e8).toFixed(4)} VRSC`;
  div.append(head, meta);
  el.appendChild(div);
}

function renderNotes(notes: SpendableNote[]): void {
  notesEl.textContent = '';
  for (const n of notes) {
    const div = document.createElement('div');
    div.className = 'note';
    div.textContent = `${(Number(n.valueSats) / 1e8).toFixed(8)} VRSC · ${n.txid.slice(0, 12)}…:${n.outputIndex} · pos ${n.position}`;
    div.onclick = () => {
      selected = n;
      for (const c of notesEl.children) c.classList.remove('sel');
      div.classList.add('sel');
      $('sendBtn').disabled = false;
      setStatus(`selected note ${(Number(n.valueSats) / 1e8).toFixed(8)} VRSC`);
      previewChange();
    };
    notesEl.appendChild(div);
  }
}

/** change = note − amount − fee; must be >= 0. */
function computeChange(): { sendSats: bigint; changeSats: bigint; feeSats: bigint } {
  const noteSats = selected!.valueSats;
  const sendSats = parseSats($('amount').value.trim());
  const feeSats = parseSats($('fee').value.trim());
  const changeSats = noteSats - sendSats - feeSats;
  return { sendSats, changeSats, feeSats };
}

/** Live preview of the change amount as the user types. */
function previewChange(): void {
  if (!selected) return;
  try {
    const { changeSats } = computeChange();
    const el = document.getElementById('changePreview')!;
    el.textContent =
      changeSats < 0n
        ? '⚠ amount + fee exceeds the note value'
        : changeSats === 0n
          ? 'no change (sending the whole note minus fee)'
          : `change back to you: ${(Number(changeSats) / 1e8).toFixed(8)} VRSC`;
  } catch {
    /* ignore partial input */
  }
}

async function send(): Promise<void> {
  if (!client || !prover || !selected) return;
  $('sendBtn').disabled = true;
  try {
    const memo = $('memo').value;
    const { sendSats, changeSats, feeSats } = computeChange();
    if (changeSats < 0n) throw new Error('amount + fee exceeds the note value');

    const shieldedOutputs = [{ address: $('recipient').value.trim(), valueSats: sendSats, memo }];
    if (changeSats > 0n) {
      const changeAddr = $('changeAddr').value.trim();
      if (!changeAddr) throw new Error('this note has leftover value — set a change address (or send amount = note − fee)');
      shieldedOutputs.push({ address: changeAddr, valueSats: changeSats, memo: '' });
      log(`change: ${(Number(changeSats) / 1e8).toFixed(8)} VRSC → ${changeAddr.slice(0, 12)}…`);
    }

    setStatus('proving (~20 s, off the UI thread)…');
    log(`buildShieldedSpend: spending ${selected.txid.slice(0, 12)}…:${selected.outputIndex}`);
    const t0 = performance.now();
    const { hex } = await buildShieldedSpend(client, prover.spend, {
      note: {
        txid: selected.txid,
        outputIndex: selected.outputIndex,
        extskHex: $('extsk').value.trim(),
        valueSats: selected.valueSats,
      },
      feeSats,
      shieldedOutputs,
    });
    log(`proved in ${((performance.now() - t0) / 1000).toFixed(1)} s; tx ${hex.length / 2} bytes`);
    setStatus('broadcasting…');
    const res = await client.sendTransaction(hex);
    if (res.errorCode !== 0) throw new Error(`send rejected: ${res.errorCode} ${res.errorMessage}`);
    const txid = await txidFromHex(hex);
    setStatus('✅ broadcast');
    log(`SENT — txid ${txid}`);
  } catch (e) {
    setStatus('send failed');
    log('ERROR: ' + (e instanceof Error ? e.message : String(e)));
    $('sendBtn').disabled = false;
  }
}

/** Compute a txid (double-SHA256, reversed) from raw tx hex, for display. */
async function txidFromHex(hex: string): Promise<string> {
  const bytes = hexToBytes(hex);
  const h1 = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  const h2 = new Uint8Array(await crypto.subtle.digest('SHA-256', h1));
  return bytesToHex(reverseBytes(h2));
}

// Restore config. Spending key comes from session storage (in-memory, this
// browser session only); non-secret settings come from local (disk).
chrome.storage?.session?.get(['extsk'], (v) => {
  if (v.extsk) $('extsk').value = v.extsk;
});
chrome.storage?.local.get(['lwdUrl', 'fromHeight'], (v) => {
  if (v.lwdUrl) $('lwdUrl').value = v.lwdUrl;
  if (v.fromHeight) $('fromHeight').value = v.fromHeight;
});
$('initBtn').onclick = loadProver;
$('detectBtn').onclick = detect;
$('inboxBtn').onclick = readInbox;
$('sendBtn').onclick = send;
$('amount').oninput = previewChange;
$('fee').oninput = previewChange;
setStatus('click “Load prover + params” to begin');

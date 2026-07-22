# Security

`@chainvue/verus-sapling` builds and signs shielded Verus transactions. Signing
requires the **Sapling extended spending key** to be present on the signing host
— the same trust surface as a transparent WIF in `@chainvue/verus-sdk`, or any
"hot" signer. This document states what the library does and does not protect,
so integrators can reason about the residual risk.

## Trust model

- The spending key lives in the signing process's memory while a transaction is
  built. **If that host is compromised, the key can be stolen** — this is
  inherent to any software signer and is not something a library can prevent.
- The library is **offline by design**: it builds and signs bytes; a separate
  transport broadcasts them. Chain data (compact blocks, tree state) comes from
  a lightwalletd instance the consumer chooses.

## What the library guarantees

Verified in the codebase (see `src/wallet.ts`, `src/wasm.ts`, the `crate`):

- **The key never crosses the network.** The spending/viewing key is placed only
  in the local JSON `spec` passed to the wasm prover. No `LightwalletdTransport`
  method (`getTreeState`, `getBlockRange`, `getTransaction`, `sendTransaction`,
  `getLatestHeight`) ever receives it.
- **The key is never logged.** No code path prints key material.
- **Errors do not echo the key.** No error message includes the key. The single
  exception is a *malformed* hex key, where the underlying hex error may reveal
  one character and its position — never the whole key.
- **The signed transaction contains no key material** — only proofs, signatures,
  and note ciphertexts.
- **Value conservation is enforced before signing.** `buildShieldedSpend`
  requires an explicit `feeSats` and refuses to sign unless
  `note.valueSats == Σ outputs + feeSats` (with a `maxFeeSats` ceiling). The Rust
  builder re-checks this against the *decrypted* note value. A forgotten change
  output can no longer silently donate the remainder to miners.

## What the library does NOT guarantee

- **wasm memory is not zeroized.** The key persists in the wasm module's linear
  memory until the module/worker is torn down; a memory dump of the process
  could recover it. This is inherent to wasm-based proving.
- **Host / supply-chain / page compromise.** Malicious dependencies, XSS in a
  consuming web page, or a compromised OS can exfiltrate the key. Standard
  hot-signer caveats apply.
- **Params authenticity** — the browser Worker verifies the proving parameters'
  SHA-256 (`verifyCanonicalParams`); a Node caller loading params itself should
  call it too. Non-canonical params are refused.
- **Network privacy.** Fetching a note's transaction and broadcasting through the
  same lightwalletd links your notes to your IP — a standard light-client
  caveat. Use the TLS default (or Tor/a trusted relay) and consider separating
  the fetch and broadcast paths for stronger unlinkability.
- **Sender-side recovery of shielded sends.** `t→z` outputs are built with no
  outgoing viewing key (`ovk = None`), so the *sender* cannot later detect its
  own shield outputs. Wallet implementers who want that should thread an `ovk`.

## Guidance for integrators

- **Scan with a viewing key, not the spending key.** Note detection needs only a
  Diversifiable Full Viewing Key. The API supports this:
  `detectNotes(..., { key: { dfvkHex } })`. Derive the DFVK once, use it for all
  scanning, and load the full spending key **only** when actually signing a
  spend. This minimizes how long the spending key is in memory.
- **Never persist the spending key to disk.** The example extension keeps it in
  `chrome.storage.session` (in-memory, session-scoped) — never
  `chrome.storage.local`.
- **Run the prover in an isolated context** (a Web Worker), as the examples do.
- **Treat the signing host as security-critical:** pin dependencies, apply a
  strict CSP, and keep untrusted code out of the page that holds the key.

## Reporting a vulnerability

Report suspected security issues **privately** to the maintainer — do not open a
public issue. Once the repository is public, use GitHub's private security
advisory ("Report a vulnerability") flow.

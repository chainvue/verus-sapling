# @chainvue/verus-sapling

<p>
  <a href="https://github.com/chainvue/verus-sapling/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/chainvue/verus-sapling/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://www.npmjs.com/package/@chainvue/verus-sapling"><img alt="npm" src="https://img.shields.io/npm/v/@chainvue/verus-sapling?color=cb3837&logo=npm"></a>
  <img alt="node" src="https://img.shields.io/node/v/@chainvue/verus-sapling">
  <img alt="types" src="https://img.shields.io/badge/types-included-3178c6?logo=typescript&logoColor=white">
  <a href="./LICENSE"><img alt="license" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
  <img alt="offline" src="https://img.shields.io/badge/network-none%20in%20signer-success">
</p>

> **Offline signing of Verus _shielded_ (Sapling) transactions** — `t→z`, `z→z`,
> `z→t`, with encrypted memos. It builds and signs bytes; your consumer
> broadcasts. **No full node on the signing host.**

Companion to [`@chainvue/verus-sdk`](https://www.npmjs.com/package/@chainvue/verus-sdk)
(transparent transactions). Where the SDK stays pure-TS and tiny, this package
adds the one thing shielded signing genuinely needs — a Sapling zk-prover —
compiled to WASM and kept opt-in.

- 🔐 **All three shielded flows:** shield (`t→z`), private send (`z→z`), deshield (`z→t`), each with a ZIP-302 memo.
- 🧾 **Real zk-proving in WASM** (`sapling-crypto` → Groth16/BLS12-381), RedJubjub spend-auth & binding signatures, note encryption.
- 🛰️ **Client-side note detection** — trial-decrypts compact blocks; no `z_listunspent`, no wallet daemon.
- 🌐 **Browser-ready** — a gRPC-web transport and Web Worker prover ship; a runnable MV3 extension broadcasts a private `z→z` from Chrome.
- 💰 **`bigint` satoshis end-to-end** — one checked crossing into float64, never a silent `number`.
- ✅ **Daemon-verified** — the byte-layout bar is acceptance by a real Verus daemon, not self-consistent tests.

> [!WARNING]
> Proven on **testnet**. Before mainnet or real funds, read
> [`SECURITY.md`](SECURITY.md) — the full spending key is present on the signing
> host (the same trust surface as a transparent WIF).

## Contents

- [Install](#install) · [Quick start](#quick-start) · [How it works](#how-it-works)
- [Proving parameters](#proving-parameters) · [Backend](#backend-the-one-unavoidable-dependency)
- [Security](#security) · [Examples](#examples) · [Project layout](#project-layout) · [Contributing](#contributing)

## Install

```bash
npm install @chainvue/verus-sapling
```

The compiled WASM prover is shipped in the package (`crate/pkg/`). You supply the
two Sapling [proving parameters](#proving-parameters) (~50 MB, fetched once) at
runtime.

## Quick start

Load the prover, then use the lightwalletd-driven orchestration. Chain data comes
through a `LightwalletdTransport`; the concrete Node gRPC client lives on the
`./lightwalletd` subpath (the package root pulls in **no** gRPC).

```ts
import { detectNotes, buildShieldedSpend, initSapling } from '@chainvue/verus-sapling';
import { LightwalletdClient } from '@chainvue/verus-sapling/lightwalletd';

await initSapling(wasmBytes);                       // load the wasm module once
const client = new LightwalletdClient('lightwalletd:9077');

// 1. Find the wallet's own notes — no z_listunspent, no full node.
const notes = await detectNotes(client, detectProver, {
  key: { dfvkHex },              // a viewing key is enough to scan (recommended)
  fromHeight: walletBirthday,    // toHeight defaults to the chain tip
});

// 2. Spend one detected note (z→z / z→t) with a memo.
const { hex } = await buildShieldedSpend(client, spendProver, {
  note: { txid: notes[0].txid, outputIndex: notes[0].outputIndex, extskHex },
  shieldedOutputs: [{ address, valueSats, memo }],   // valueSats is a bigint
});
await client.sendTransaction(hex);
```

`detectProver` / `spendProver` are thin callbacks you wire to the WASM builders
(`detectNotes` on the main thread; `spendShielded` in a Web Worker for the ~20 s
prove — see [`examples/extension`](examples/extension)). Memos are `string`,
≤ 512 bytes. For `t→z` shielding, call the `shieldT2z` builder directly.

> **Scan with a viewing key, spend with the spending key.** `detectNotes` needs
> only a Diversifiable Full Viewing Key (`dfvkHex`); load the full spending key
> (`extskHex`) only to sign a spend. See [`SECURITY.md`](SECURITY.md).

## How it works

The Rust crate (`crate/`) is compiled to WASM and owns the parts that must be
byte-exact: the **ZIP-243 sighash**, the **v4 transaction serializer**, Sapling
**proving**, the signatures, and note encryption. The TypeScript layer (`src/`)
stays thin: input validation, the `bigint` money invariant, the lightwalletd
transport, and address/key marshalling.

### Verus = stock Zcash Sapling

Confirmed against Verus source and a live mainnet node: Verus shielded is
**stock Zcash Sapling** — unmodified `zcash/librustzcash` circuit, byte-identical
MPC parameters, stock consensus branch id `0x76b809bb`, version group id
`0x892f2085`, tx v4. Consensus is frozen at Sapling on **both** mainnet and
testnet (Canopy — which would gate ZIP-212 — is not in Verus's upgrade set), so
ZIP-212 enforcement is `Off`. The only Verus-specific value in the entire path is
that branch id, injected into the sighash. Even the lightwalletd wire protocol is
stock — `VerusCoin/lightwalletd`'s protos are byte-identical to Zcash's.

### Backend: the one unavoidable dependency

- **`t→z` (shielding)** needs **no** commitment-tree witness — only the
  transparent UTXOs you already fetch. The true "sign privately with zero extra
  backend" case.
- **`z→z` / `z→t`** spend shielded notes, which need each note's Merkle **witness
  + anchor** and **note detection**. Those come from a chain-scanning service —
  a stock **Verus lightwalletd** (standard gRPC `GetBlockRange` / `GetTreeState`).
  The signing host still runs no full node, but this service is required.
  Browsers additionally need a gRPC-web proxy in front of it.

## Proving parameters

The prover needs two parameter files — the **canonical Zcash Sapling MPC
parameters**, byte-identical for Verus. They are **not** bundled (≈50 MB would
bloat every install); fetch them once and pass their bytes to `initSapling` and
the prover.

| file | size | SHA-256 |
| --- | --- | --- |
| `sapling-spend.params` | ~47 MB | `8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13` |
| `sapling-output.params` | ~3.5 MB | `2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4` |

**Always verify the SHA-256.** Get them from any Zcash full node
(`zcutil/fetch-params.sh`), a local Verus install, or your own host — then cache
them (IndexedDB / Cache API in the browser, the filesystem in Node). Non-canonical
params produce proofs the daemon rejects.

## Security

This library signs money and the spending key is present on the signing host.
[`SECURITY.md`](SECURITY.md) documents the trust model in full — what is
guaranteed (the key never crosses the network, is never logged, and is not in the
signed tx) and what is not (WASM memory is not zeroized; host/supply-chain
compromise). **Report vulnerabilities privately** via a GitHub security advisory,
never a public issue.

<details>
<summary><b>Daemon-verified on testnet</b> — txids</summary>

All three flows were built by this code and accepted by a Verus testnet daemon:

- **t→z** `1edf8aa6…6623` (native) and `d142edf8…a0ef` (built in WASM)
- **z→z** `53ea99fc…89feb` — fully private, recipient received 9.9999
- **z→t** `86951c8d…bd8a` — transparent recipient received 0.05
- **z→z, fully lightwalletd-sourced** `07e3b38e…f996` — every byte of chain data
  from lightwalletd, signed in WASM, no full node

Note detection is cross-checked against consensus: the nullifier it predicts for
a note matches the on-chain nullifier of the spend that later consumed it,
byte-for-byte. The ZIP-243 serializer/sighash is regression-tested against
daemon-made golden vectors (`cargo test`).

</details>

## Examples

- [`examples/extension`](examples/extension) — a runnable **MV3 browser
  extension**: detect notes, read the inbox, and broadcast a private `z→z` from
  Chrome, proving in a Web Worker.
- [`examples/messenger`](examples/messenger) — an end-to-end **shielded-memo
  messenger**: framed messages carried in zero-value notes.

## Project layout

```
src/            TypeScript: validation, money, wallet orchestration, transport
  browser/      gRPC-web transport + Web Worker prover (no external gRPC dep)
crate/          Rust: ZIP-243 sighash, v4 serializer, Sapling proving
  pkg/          committed WASM build (so a fresh clone works without Rust)
proto/          stock Zcash lightwalletd gRPC definitions
examples/       runnable extension + messenger demos
test/           vitest suite (money, hex, protobuf, gRPC-web, wallet, zaddr, …)
```

Docs: [SECURITY](SECURITY.md) · [CONTRIBUTING](CONTRIBUTING.md) ·
[RELEASING](RELEASING.md) · [NOTICE](NOTICE) ·
[Code of Conduct](CODE_OF_CONDUCT.md)

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). The gate is
`npm run build` → `npm run typecheck` → `npm test`, plus `cargo test` for the
crate. Commits follow [Conventional Commits](https://www.conventionalcommits.org/)
(they drive the automated release).

## License

Apache-2.0. See [LICENSE](LICENSE). Third-party provenance for the WASM prover's
bundled Rust crates, the vendored lightwalletd protos, and the proving parameters
is in [NOTICE](NOTICE).

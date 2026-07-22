# @chainvue/verus-sapling

Offline signing of **Verus shielded (Sapling) transactions** — `t→z`, `z→z`,
`z→t`, with memo. Companion to
[`@chainvue/verus-sdk`](https://www.npmjs.com/package/@chainvue/verus-sdk),
which handles transparent transactions.

Same model as the SDK: **it builds and signs bytes; the consumer broadcasts.**
No full node runs on the signing host.

> **Status: working, proven on testnet.** The Sapling prover is implemented
> (Rust in `crate/`) and all three flows have been built by this code and
> **accepted by a Verus testnet daemon**:
> - **t→z** `1edf8aa6…6623` (native) and `d142edf8…a0ef` (**built in wasm**)
> - **z→z** `53ea99fc…89feb` — fully private, recipient got 9.9999
> - **z→t** `86951c8d…bd8a` — transparent recipient got 0.05
> - **z→z, fully lightwalletd-sourced** `07e3b38e…f996` — every byte of chain
>   data from lightwalletd, signed in wasm (no full node)
>
> The prover **compiles to wasm32** (`crate/pkg/`; single-threaded proving
> ~5 s t→z, ~20 s z→z spend) and is loaded via `src/wasm.ts`.
>
> **Client-side note detection** is implemented and proven: the wallet finds its
> own notes by trial-decrypting compact blocks (`src/scan.rs` → wasm
> `detectNotes`), with no `z_listunspent`. Cross-checked against consensus — the
> nullifier it predicts for a note matches the on-chain nullifier of the spend
> that later consumed it, byte-for-byte.
>
> **Typed lightwalletd orchestration** (`src/wallet.ts`): `detectNotes()` and
> `buildShieldedSpend()` source all chain data from a `LightwalletdTransport` and
> run the prover — proven end to end against a live testnet lightwalletd through
> the compiled package. A **browser gRPC-web transport** (`./browser`) and a
> **Web Worker prover** ship today; a runnable MV3 extension in
> `examples/extension/` broadcasts a private z→z from Chrome.

## Why a separate package

Shielded signing needs zk-SNARK proving (Groth16/BLS12-381), RedJubjub
signatures, and note encryption — a WASM prover plus ~50 MB of proving
parameters. Keeping it here preserves `@chainvue/verus-sdk`'s pure-TS,
tiny-dependency, 100%-offline design. Shielded support is opt-in.

## Verus = stock Zcash Sapling (de-risked)

Confirmed against Verus source: the daemon builds **unmodified
`zcash/librustzcash`**, uses **byte-identical Zcash Sapling MPC params**, and
keeps the **stock consensus branch id `0x76b809bb`** and version group id
`0x892f2085`. The only Verus-specific value threaded through the shielded path
is that branch id (already exported as `CONSENSUS_BRANCH_ID` by the SDK).
Consequence: the prover is expected to be an **adaptation of an existing Zcash
Sapling WASM prover** (WebZjs / ChainSafe zcash-wasm / librustzcash→WASM), not a
from-scratch circuit.

## The one unavoidable dependency

- **`t→z` (shielding)** needs **no** note-commitment-tree witness — only the
  transparent UTXOs you already fetch. This is the true "sign privately with
  zero extra backend" case.
- **`z→z` / `z→t`** must spend shielded notes, which requires each note's Merkle
  **witness + anchor** and **note detection**. Those come from a chain-scanning
  service — **Verus lightwalletd** (`VerusCoin/lightwalletd`, standard gRPC
  `GetBlockRange` / `GetTreeState`) or a full node. The signing host still runs
  no full node, but this service is required. See `ShieldedSpendInput` in
  [`src/types.ts`](src/types.ts).

## API surface (today)

The proven path: load the wasm prover, then use the lightwalletd-driven
orchestration. Chain data comes through a `LightwalletdTransport`; the concrete
Node gRPC client is on the `./lightwalletd` subpath (browsers implement the same
interface over a gRPC-web proxy — the package root pulls in **no** gRPC).

```ts
import { detectNotes, buildShieldedSpend, initSapling } from '@chainvue/verus-sapling';
import { LightwalletdClient } from '@chainvue/verus-sapling/lightwalletd';

await initSapling(wasmBytes);                          // load the wasm module
const client = new LightwalletdClient('lightwalletd:9077');

// 1. Find the wallet's own notes — no z_listunspent, no full node.
const notes = await detectNotes(client, detectProver, {
  key: { extskHex },              // or { dfvkHex } for a read-only scanner
  fromHeight: walletBirthday,     // toHeight defaults to the chain tip
});

// 2. Spend one detected note (z→z / z→t) with a memo.
const { hex } = await buildShieldedSpend(client, spendProver, {
  note: { txid: notes[0].txid, outputIndex: notes[0].outputIndex, extskHex },
  shieldedOutputs: [{ address, valueSats, memo }],
});
await client.sendTransaction(hex);
```

`detectProver` / `spendProver` are thin callbacks the caller wires to the wasm
builders (`detectNotes` on the main thread; `spendShielded` in a Web Worker for
the ~20 s prove). All satoshi amounts are `bigint`; memos are `string`, ≤ 512
bytes. For t→z shielding use the `shieldT2z` wasm builder directly.

## Proving parameters

The Sapling prover needs two parameter files — the **canonical Zcash Sapling MPC
parameters**, byte-identical for Verus. They are **not** bundled (≈50 MB would
bloat every install); the caller fetches them once and passes their bytes to
`initSapling` / the prover:

| file | size | SHA-256 |
| --- | --- | --- |
| `sapling-spend.params` | ~47 MB | `8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13` |
| `sapling-output.params` | ~3.5 MB | `2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4` |

**Always verify the SHA-256** after fetching. Get them from any Zcash full node
(`zcutil/fetch-params.sh`), a local Verus install, or your own host — then cache
them: IndexedDB/Cache API in the browser, the filesystem in Node. The prover is
parameter-agnostic; supplying non-canonical params yields proofs the daemon
rejects.

## Status

All three flows (`t→z`, `z→z`, `z→t`) are implemented and **accepted by a Verus
testnet daemon** — the project's bar throughout is daemon acceptance, not
self-consistent TypeScript round-trips. The prover compiles to wasm32; note
detection, lightwalletd orchestration, a browser gRPC-web transport, a Web Worker
prover, and a runnable extension all ship. The ZIP-243 serializer/sighash is
regression-tested against daemon-made golden vectors (`crate` `cargo test`), and
the pure TS surface has a vitest suite.

**Before mainnet / real funds:** review key handling (the full spending key is on
the signing host — the same trust surface as transparent WIF signing). ZIP-212
enforcement is `Off`, which is correct for Verus: consensus is frozen at Sapling
on both mainnet and testnet (Canopy, which would gate ZIP-212, is not in Verus's
upgrade set).

## License

Apache-2.0. See [LICENSE](LICENSE). Third-party provenance for the WASM prover's
bundled Rust crates and the proving parameters is in [NOTICE](NOTICE).

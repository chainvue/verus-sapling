# Verus Shielded Demo — minimal MV3 extension

A one-popup browser extension that **detects shielded notes and signs a private
(Sapling) Verus transaction entirely client-side** — the spending key never
leaves the browser; only the signed bytes go to the network.

It wires together the whole proven stack:

```
popup (main thread)                         Web Worker
  ├─ LightwalletdWebClient  ──gRPC-web──►  grpcwebproxy → lightwalletd
  ├─ detectNotes ─────────────────────────►  wasm detect_notes  (cheap)
  └─ buildShieldedSpend ──────────────────►  wasm spend_shielded (~20 s)
```

> **Testnet demo, not hardened.** You paste a testnet spending key into the
> popup; it is kept in `chrome.storage.session` (in-memory, never written to
> disk, cleared when the browser closes) — never `chrome.storage.local`. Only
> non-secret settings (lightwalletd URL, scan height) are persisted to disk.
> Still: don't use a mainnet key. See [`SECURITY.md`](../../SECURITY.md).

## Prerequisites (local demo — no tunnel, no TLS, $0)

1. **gRPC-web proxy reachable at `localhost:8080`.** Run `grpcwebproxy` in front
   of your Verus lightwalletd. If it lives on a remote host, forward it to your
   laptop (replace `<lightwalletd-host>` with your SSH host):
   ```bash
   ssh -N -L 8080:127.0.0.1:8080 <lightwalletd-host>
   ```
   `http://localhost` is a browser-trustworthy origin, so no HTTPS is needed.

2. **Serve the ~50 MB proving params at `localhost:8081`.** They're byte-identical
   to Zcash's `sapling-spend.params` / `sapling-output.params`:
   ```bash
   cd "$HOME/Library/Application Support/ZcashParams"
   python3 -m http.server 8081
   ```
   (No CORS config needed — the extension's `host_permissions` cover it.)

## Build & load

```bash
npm run build:ext          # tsc + esbuild → examples/extension/build/
```
Then: **chrome://extensions → Developer mode → Load unpacked →** select
`examples/extension/build/`.

## Use

1. Click **Load prover + params** (fetches the wasm + params, boots the worker).
2. Paste your **spending key** (169-byte `ExtendedSpendingKey` hex) and a
   **scan-from height** (a block at/just before your note), then **Detect my
   notes**.
3. Click a detected note, fill **recipient** (`zs…`), **amount**, and **memo**,
   then **Build + broadcast**. The ~20 s prove runs in the worker; on success the
   log shows the broadcast txid.

## What to point elsewhere for a remote demo

Change **lightwalletd gRPC-web proxy** in the popup from `http://localhost:8080`
to your Zero Trust tunnel hostname (which must have **no Cloudflare Access
policy**, so the extension's calls aren't bounced to a login page). Everything
else is unchanged.

## Notes / limits

- Detection scans `[fromHeight, tip]` and drops notes spent within that range —
  scan from your wallet birthday for a complete unspent set.
- The params fetch is uncached here; a real wallet caches them in IndexedDB.
- One note per spend (the demo doesn't select/merge multiple notes).

# Shielded messenger (example)

A decentralized, private messenger in ~100 lines on top of `@chainvue/verus-sapling`:
messages are **shielded memos** — encrypted to the recipient's viewing key,
carried on-chain in 0-value notes, read back client-side. No server holds the
messages; the chain does.

- **`message.mjs`** — the memo framing: a 12-byte transport header + chunking
  (messages > 500 B span multiple 512-byte memos), and a JSON payload
  `{ v, from?, ts, text }` after reassembly. Frames start with `0xFF` so
  ZIP-302-compliant wallets don't render the binary as text.
- **`demo.mjs`** — end-to-end: send a message (0-value note + framed memo) to an
  address, then scan → decrypt → reassemble it back. Send-to-self by default.

## What it uses

| Step | SDK piece |
|------|-----------|
| frame + chunk the message | `message.mjs` (this example) |
| send (0-value output + `memoHex`, change to self) | `buildShieldedSpend` + gRPC-web `sendTransaction` |
| find incoming notes | `detectNotes` (wasm, over lightwalletd) |
| decrypt the memo | `readNote` (wasm) |
| reassemble chunks → message | `Reassembler` (this example) |

Everything is client-side; the spending/viewing key never leaves the process.

## Run

Prereqs (same as the extension demo): the gRPC-web proxy at `http://localhost:8080`
(`ssh -N -L 8080:127.0.0.1:8080 vrsc-testnet`), the wasm built (`crate/pkg`), and
the package built (`npm run build`). Then:

```bash
node examples/messenger/demo.mjs <extsk-file> <my-zs-address> <fromHeight> ["message"]
```

- `<extsk-file>` — a file containing the address's 169-byte spending-key hex.
- `<my-zs-address>` — an address you control that holds a spendable note (pays
  the fee; the message and change go back to it).
- `<fromHeight>` — a block at/below your note's creation height.

The message tx must mine (~1 block) before the inbox loop finds it; the demo
polls for ~4 minutes.

## Notes / next steps for a real app

- **Contacts** = z-addresses. Include `from` in the payload so replies are
  possible (the chain hides the real sender).
- **0-value message notes** accumulate; sweep them periodically.
- **Latency = block time**; this is async/email cadence, not live IM.
- Multiple chunks of one message can ride in **one tx** (multiple outputs),
  delivered atomically.
- A read-only inbox is possible with a **viewing key only** (`dfvkHex`) — no
  spending key needed to receive.

# Sapling reference vectors (Verus testnet, VRSCTEST)

Ground-truth Verus Sapling **v4** transactions captured from a real testnet
daemon (`verusd -chain=vrsctest`, chain `test`, Sapling active, branch id
`76b809bb`). These are the byte-layout targets the WASM prover must reproduce —
a build is correct when it produces bytes a Verus daemon accepts, and these show
exactly what "accepted" looks like for each flow.

Each pair is `<flow>.hex` (raw serialized tx) + `<flow>.json`
(`getrawtransaction <txid> 1` decode).

| File  | Flow | valueBalance | vShieldedSpend | vShieldedOutput | vin | vout | Notes |
|-------|------|--------------|----------------|-----------------|-----|------|-------|
| `t2z` | transparent → shielded | **−1.0** (value into pool) | 0 | 1 | 1 | 1 | memo `"Hello-t2z"` (hex `48656c6c6f2d74327a`) in the output's `encCiphertext`; transparent input + P2PKH change |
| `z2z` | shielded → shielded     | **+0.0001** (= fee only)   | 1 | 2 | 0 | 0 | memo `"Hello-z2z"`; 2 outputs = recipient + shielded change |
| `z2t` | shielded → transparent  | **+0.3001** (out 0.3 + fee) | 1 | 1 | 0 | 1 | 1 shielded output = shielded change; transparent P2PKH out |

All: `version 4`, `overwintered true`, `versiongroupid 892f2085`, `bindingSig`
present. Fee 0.0001 on each.

## valueBalance sign convention (load-bearing)

`valueBalance` is the net value moved **out of** the shielded pool:
- t→z: negative (value enters the pool).
- z→z: equals the fee (value stays in the pool; only the fee leaves to miners).
- z→t: transparent output(s) + fee (value leaves the pool).

## Provenance (testnet only — no secrets)

- t→z from R-addr `RWKve6J7EB8YiFegJ4KGvuuzZwyt8URkUb` → `zs1wq9ne3v9u6cdugue9v9a6nen7g9erj899xqj0ywazd2a90lp94jt7cjsqh0m4rfnyd8kwts90sq`
- z→z `zs1wq9ne…` → `zs13c3ed8lydqlue0m2m08z2x8fw6q7g50fhwlputafyjp3f48j7qhp4l5rattk6evxxydqk0euhfr`
- z→t `zs195njn…` → R-addr `RANytcx4qzWUpYSSEgMZ7RQ5mW3UAYYCGa`

Captured 2026-07-22. Regenerate with the daemon via the helper in
`scratchpad/verus-capture.sh` (kept out of the package; testnet-only).

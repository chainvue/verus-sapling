# Contributing to @chainvue/verus-sapling

Thanks for your interest! This library signs **real money** (shielded Verus
transactions), so we optimize for correctness, safety, and reviewability over
speed. Small, focused, well-tested changes are very welcome.

- 🔒 **Security issues:** do **not** open a public issue. See [SECURITY.md](SECURITY.md).
- 💬 **Questions / ideas:** use GitHub Discussions or a feature-request issue.
- 🐛 **Bugs:** open a bug-report issue. Never paste keys, seeds, or `.params`.

## Ground rules

- **The signer stays offline.** It builds and signs bytes; a consumer
  broadcasts. Don't add network calls to the signing path.
- **Money is `bigint` end-to-end.** Never reintroduce `number` for satoshis.
  `toSafeNumber` is the *only* checked crossing into float64.
- **Errors are typed** (`ShieldedError` / `ShieldedInputError`), validated at the
  boundary. No raw `Error` at public boundaries; no swallowed failures.
- **The daemon is the bar.** Consensus/byte-layout changes must be shown to be
  accepted by a real Verus daemon (`decoderawtransaction` / `sendrawtransaction`),
  not just self-consistent tests.
- **Keep public APIs stable** unless the PR is explicitly about changing them.

## Development setup

```bash
git clone https://github.com/chainvue/verus-sapling
cd verus-sapling
npm install
```

You do **not** need a Rust toolchain for most work: the compiled WASM prover is
committed in `crate/pkg/`, so a fresh clone typechecks and tests immediately.

### The gate (run before opening a PR)

```bash
npm run build        # tsc
npm run typecheck    # tsc --noEmit
npm test             # vitest
cargo test --manifest-path crate/Cargo.toml   # only if you touched the Rust crate
```

All must pass. There is no ESLint step in this package.

### Rebuilding the WASM prover (only if you change `crate/src/`)

Requires the Rust toolchain plus `wasm-pack` and the wasm target:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
wasm-pack build crate --target web --release   # regenerates crate/pkg/
rm -f crate/pkg/.gitignore                      # see the gotcha below
```

Commit the regenerated `crate/pkg/` in the same PR.

> **Gotcha:** `wasm-pack` writes a `crate/pkg/.gitignore` containing `*`. npm
> honors it and **drops the entire `crate/pkg/` (the wasm!) from the published
> tarball**, shipping a broken package. Always `rm crate/pkg/.gitignore` after
> building, and confirm with `npm pack --dry-run | grep crate/pkg` (you should
> see the `.wasm`).

### Running the examples

- `examples/extension/` — a runnable MV3 browser extension (`npm run build:ext`).
- `examples/messenger/` — an end-to-end shielded-memo messenger demo.

Both need a lightwalletd + gRPC-web proxy backend; see their READMEs.

## Commit & PR conventions

Commit messages and PR titles follow [Conventional Commits](https://www.conventionalcommits.org/) —
they **drive the automated release** ([RELEASING.md](RELEASING.md)):

| prefix | effect |
| --- | --- |
| `fix:` / `perf:` | patch release |
| `feat:` | minor release |
| `feat!:` or `BREAKING CHANGE:` | minor while 0.x (breaking) |
| `docs:` / `chore:` / `test:` / `refactor:` / `ci:` | no release |

- Keep diffs small and focused; don't mix a refactor with a feature.
- Add or update tests for every behavior change; add a regression test for bug fixes.
- Update `README.md` / `SECURITY.md` when behavior or the trust model changes.
- Do **not** hand-edit `version` in `package.json` or `CHANGELOG.md` — the
  release pipeline owns both.

## License

By contributing, you agree that your contributions are licensed under the
project's [Apache-2.0](LICENSE) license.

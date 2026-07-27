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
cargo install wasm-pack --version 0.14.0 --locked   # pinned: see below
wasm-pack build crate --target web --release        # regenerates crate/pkg/
rm -f crate/pkg/.gitignore                          # see the gotcha below
```

Commit the regenerated `crate/pkg/` in the same PR, so CI's Node-only jobs
exercise the binary your source actually produces.

**What is committed is not what gets published.** The release job rebuilds the
prover from the tagged source with the pinned toolchain and publishes *that*,
then commits the result back in the release commit. This exists because v0.1.0
shipped a stale binary — one that did not rebuild from its own tag — since
committing the artifact is a human step and the step was missed. Keeping the
copy in git is a convenience (it keeps `npm run build` / `typecheck` / `test`
working without a Rust toolchain); it is not the source of truth for npm.

**Versions are pinned in three places and must agree:** `crate/rust-toolchain.toml`,
the two Rust jobs in `.github/workflows/ci.yml`, and the release job in
`.github/workflows/release.yml` — rustc `1.95.0`, wasm-pack `0.14.0`. wasm-pack
bundles the `wasm-opt` that rewrites the binary, so an unpinned install changes
the output bytes on its own.

> **Byte-for-byte reproduction across machines is not achieved.** The binary
> embeds ~60 absolute `CARGO_HOME` paths (dependency sources reached through
> panic locations), so a build with a different home directory differs no matter
> how the toolchain is pinned — which is why `wasm-drift` reports a warning
> rather than failing. Closing that would need `--remap-path-prefix` at every
> build site; Cargo's `trim-paths`, the clean fix, is still unstable as of Cargo
> 1.97.1.

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

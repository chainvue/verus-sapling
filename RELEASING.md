# Releasing

Releases are automated with [semantic-release](https://semantic-release.gitbook.io/)
driven by [Conventional Commits](https://www.conventionalcommits.org/). You do
**not** hand-edit `version` in `package.json` or `CHANGELOG.md` — the pipeline
owns both. Every push to `main` runs `.github/workflows/release.yml`:

| commit type | release |
| --- | --- |
| `fix:` / `perf:` / `revert:` | patch |
| `feat:` | minor |
| `feat!:` / `BREAKING CHANGE:` | minor **while 0.x** (see `.releaserc.json` `releaseRules`) |
| `chore:` / `test:` / `docs:` / `ci:` | no release |

A push with no releasable commits is a no-op. Preview a run without publishing
via the **workflow_dispatch → dry-run** button on the Release workflow.

## Publishing model

- `@semantic-release/npm` runs with `npmPublish: false` — it only bumps the
  version in `package.json`; it verifies **no** npm token.
- The actual publish is `npm publish` (via `@semantic-release/exec`) using npm
  **OIDC trusted publishing** — no `NPM_TOKEN` secret. Provenance is emitted
  (`publishConfig.provenance` + `id-token: write` + `NPM_CONFIG_PROVENANCE`).
- What ships is controlled by the `files` allowlist in `package.json`: `dist/`,
  `crate/pkg/` (the committed wasm), `LICENSE`, `NOTICE`, `README.md`. Verify
  with `npm pack --dry-run`.

## One-time setup

The GitHub repo, the push, and the `v0.0.0` baseline tag are already in place.
Three steps remain, **in order** — npm OIDC trusted publishing needs the package
to exist first, so the very first publish is a manual bootstrap:

1. **Bootstrap the package with one manual publish.** From a clean checkout,
   logged in to npm as a `@chainvue` member:

   ```bash
   npm login
   npm publish --access public   # `prepack` builds dist/; creates the package
   ```

   This publishes the current `package.json` version. Semantic-release owns every
   version *after*: from the `v0.0.0` tag + the accrued `fix:` commits it computes
   `0.0.1` on the next release.

2. **Configure OIDC trusted publishing** (now that the package exists):
   npmjs.com → the `@chainvue/verus-sapling` package → *Settings → Trusted
   Publisher* → **GitHub Actions**, repository `chainvue/verus-sapling`, workflow
   `release.yml`. Token-less; provenance via `id-token: write`. No `NPM_TOKEN`
   secret needed.

3. **Activate the Release workflow**: GitHub → repo *Settings → Secrets and
   variables → Actions → Variables* → add `RELEASE_ENABLED = true`. Until set, the
   `release` job is skipped (green); once set, every push to `main` releases via
   OIDC.

## Local dry-run

With the remote configured you can preview locally:

```bash
npx semantic-release --dry-run --no-ci
```

This computes the next version and release notes without publishing or tagging.

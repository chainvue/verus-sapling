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

## One-time setup (before the first push to `main`)

1. **Create the GitHub repo and remote**, then push. Until then the pipeline is
   inert (no CI host).

2. **Register the npm trusted publisher** for `@chainvue/verus-sapling`:
   npmjs.com → the package (or your org) → *Settings → Trusted publishers* → add
   the GitHub repo and workflow `release.yml`. Without this, `npm publish` in CI
   has no authorization. (Alternative: set an `NPM_TOKEN` secret and switch the
   exec `publishCmd` back to a token-based publish — less secure.)

3. **Seed the baseline tag** so the first computed release is `0.0.1`, not
   semantic-release's default first version of `1.0.0`:

   ```bash
   git tag v0.0.0 <initial-commit-sha>   # e.g. the "Initial commit" sha
   git push origin v0.0.0
   ```

   From that baseline the accumulated `fix:` commits compute `0.0.1`. If you
   would rather start at `0.1.0`, land a `feat:` commit before the first release
   (or tag the desired starting point minus one increment).

## Local dry-run

With the remote configured you can preview locally:

```bash
npx semantic-release --dry-run --no-ci
```

This computes the next version and release notes without publishing or tagging.

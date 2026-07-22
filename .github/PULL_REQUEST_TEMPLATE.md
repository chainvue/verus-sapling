<!--
Thanks for contributing! Keep PRs small and focused. The title MUST follow
Conventional Commits (feat:, fix:, docs:, chore:, test:, refactor:, perf:) —
it drives the automated release. See CONTRIBUTING.md.
-->

## What & why

<!-- What does this change, and why? Link any issue: "Closes #123". -->

## Type of change

- [ ] `fix:` — bug fix (patch)
- [ ] `feat:` — new capability (minor)
- [ ] `docs:` / `chore:` / `test:` / `refactor:` — no release
- [ ] Breaking change (describe the migration below)

## Checklist

- [ ] `npm run build` (tsc) passes
- [ ] `npm run typecheck` passes
- [ ] `npm test` (vitest) passes
- [ ] `cargo test` passes if the Rust crate changed (`crate/`)
- [ ] Money paths stay `bigint` (no `number` satoshis reintroduced)
- [ ] No secrets, keys, or `.params` committed
- [ ] Docs / README / SECURITY updated if behavior or the trust model changed
- [ ] If the WASM was rebuilt, `crate/pkg/` is regenerated and committed

## Notes for reviewers

<!-- Anything tricky: consensus/byte-layout impact, daemon acceptance evidence, security considerations. -->

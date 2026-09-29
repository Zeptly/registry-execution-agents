# Contributing

1. Read [architecture](docs/architecture.md), [artifact model](docs/artifact-model.md) and [sealing & versioning](docs/sealing-and-versioning.md).
2. Work on a branch; never push to `main` directly. Branches/PRs are governance transport only.
3. `npm ci && npm run ci`; against your base also run `node scripts/check-changes.mjs --base origin/main`.
4. Keep one identity/concern per PR.

## Rules

- **Never edit a sealed version.** Create a new version directory, `seal` it, and attach attestations.
- Attestations, approvals and lifecycle events are **append-only**.
- New agents and evolutions enter as **candidates**; promotion uses `scripts/promote.mjs` and requires digest-bound evaluation and security-review attestations plus a governed approval.
- Canonical artifacts pin references by exact version **and** digest.
- **No endpoints, credentials, tapes, transcripts or customer data.** Use structured references and `evidence://` pointers. Version directories accept only `prompts/`, `contracts/`, `evals/` files of allowed types (LF-only UTF-8, size-limited, no symlinks).
- Examples and fixtures live in `synthetic/` with `synthetic.` ids and can never be referenced from `registry/`.
- After changing artifacts or overlays run `npm run build:index` and commit the indexes (CI verifies them).
- Changes to `schemas/`, `scripts/` and `.github/` need registry-maintainer and security review, plus tests in `test/`.

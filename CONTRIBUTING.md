# Contributing

1. Read [architecture](docs/architecture.md), [agent definition](docs/agent-definition.md) and [versioning](docs/versioning.md).
2. Work on a branch; never push to `main`.
3. Run `npm ci && npm run ci` and, against your base, `node scripts/check-changes.mjs --base origin/main`.
4. Open a PR using the template. Keep one agent (or one concern) per PR.

## Rules
- **Never edit a released version.** Bump the version, update `CHANGELOG.md`, record the release (`npm run release -- exec.<slug> …`).
- **Never edit or reorder `releases.yaml` entries**; append only (via the script).
- **No endpoints, credentials, raw prompts/transcripts/tapes or customer data.** Use logical names and evidence pointers.
- Dependencies are `id` + version; released agents pin exact versions.
- Security/permission expansion: bump at least minor and set `security.review.security_review_required: true`.
- Candidate mutations must include provenance, mutation rationale and evidence refs, and cannot merge as `candidate`.
- Changes to `schemas/`, `scripts/` and `.github/` need registry-maintainer + security review; add/adjust tests in `test/`.
- Commit messages: imperative, scoped (`triage: tighten non-ticket handling`).

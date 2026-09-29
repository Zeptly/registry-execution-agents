# Protocol v0.1 conformance

This registry implements the approved **Zeptly Registry Protocol v0.1**. Nothing here was inferred from sibling repositories.

| Normative rule | Implementation |
|---|---|
| Every artifact has `kind`, `metadata.id/version/registry` | `execution-agent.schema.json` |
| Published versions immutable, addressed by exact digest | `seal.yaml`, `computeSeal`, `check-changes` |
| Canonical SemVer; candidate exceeds every canonical | `rules.mjs` (cross-object rules) |
| Candidates are registry objects; Git is transport | `<domain>/candidates/`, [maturity-and-promotion](maturity-and-promotion.md) |
| `maturity`, `origin`, `lifecycle` independent | envelope fields + overlay |
| Lifecycle append-only overlay with active/deprecated/revoked | `lifecycle.schema.json`, `changes.mjs` |
| Structured `{registry,id,version,digest?}` references | `common.schema.json#/$defs/reference` |
| Runtime resolves range → exact version + digest → lock → evidence | [references-and-resolution](references-and-resolution.md) (runtime side) |
| Attestations bind to the exact subject digest | `rules.mjs` (`sealRules`), stale = error |
| Raw tapes/trajectories outside Git | [evidence-model](evidence-model.md); URL/secret scans |
| Compiler/runtime must not alter classification | classification is in the digest |
| Deterministic generated indexes | `build-index.mjs --check` |
| Promotion requires validation, evals, provenance, security review, digest-bound attestations, governed approval | `promotionGates` in `rules.mjs`, `promote.mjs` |
| Synthetic examples isolated | `synthetic/` tree + `synthetic.` namespace |
| Runtime code, namespace ownership, gateway contracts, Evidence Protocol out of scope | not implemented; see [decisions](decisions.md) |

## Class-specific preservation

Durable task contracts, retry, timeout, checkpoint, state and execution policies, evidence pointers and the synthetic examples are carried over into `spec` (keys camelCased; enum values unchanged).

## Migration from the earlier draft

| Earlier draft | Now |
|---|---|
| Mutable head `agents/<slug>/agent.yaml` + `releases.yaml` ledger + tags | Immutable sealed version directories; digest in `seal.yaml`; no tags needed |
| `candidate` status blocked from merging; candidate = Git branch | `maturity: candidate` sealed objects under `candidates/` |
| `status` (draft…retired) | `maturity` + lifecycle overlay + `origin` |
| `skill.*`/`cap.*`/`tool.*`/`model.*` strings | Structured references |
| Evidence URI schemes (`cortex://` …) | Opaque `evidence://` pointers |
| `runtime_contract` versioning | Removed (deferred) |
| Examples in `agents/` | `synthetic/` domain |

# Cross-Registry Reconciliation Required

**Status: OPEN. Nothing in this document resolves anything.** This registry was built in isolation. Several choices below were made as *working defaults* so the tooling could be implemented and tested; they must be reconciled with `Zeptly/registry-skills`, `registry-qb-agents` and `Zeptly/runtime-trigger` before being treated as Zeptly-wide conventions.

## Reconciliation items

### A. Head definition + release ledger vs directory-per-version
This registry keeps a **mutable head definition** (`agents/<slug>/agent.yaml`) plus an **append-only, digest-pinned release ledger** (`releases.yaml`) and git tags. `registry-qb-agents` currently proposes **directory-per-version immutable artifacts**. The two models make different trade-offs (duplication vs. reliance on Git history/tags for retrieving old versions; how a runtime resolves an exact version). Not resolved here.

### B. Candidates as Git branches vs candidates in registry data
This registry represents candidate improvements **primarily as Git branches/PRs** (`status: candidate` is blocked from merging by CI). Other registries may represent candidates **inside registry data** (e.g. checked-in candidate records). Not resolved here.

### C. Identifier and dependency-reference syntax
Identifier and reference syntax has **not been standardised** across Zeptly registries. This registry currently uses `exec.<slug>` IDs, `exec.<slug>@<version>` tags, and `skill.*` / `cap.*` / `tool.*` / `model.*` / `secret.*` namespaces with `{id, version}` bindings. Not resolved here.

## Provisional choices (all subject to A/B/C)

| # | Choice | Where it lives | Coupled to |
|---|---|---|---|
| P1 | Mutable head definition + immutable release ledger | `agents/*/agent.yaml`, `releases.yaml`, `scripts/lib/changes.mjs` | A |
| P2 | Candidate-as-Git-branch model; `candidate` never merges | `docs/lifecycle.md`, `merge-gate` job, `examples/candidates/` | B |
| P3 | `exec.<slug>@version` identity/tag syntax | schemas `agentId`, `releases.schema.json` `git_tag`, `tag-releases` | C |
| P4 | `skill.*`, `cap.*`, `tool.*`, `model.*` (and `secret.*`) namespaces | `execution-agent.schema.json` `$defs` | C |
| P5 | Evidence URI schemes (`cortex`, `tape`, `evalrun`, `trace`, `artifact`, `git`) | `evidenceRef.uri` pattern | Cortex / runtime |
| P6 | Runtime-contract versioning (`compatibility.runtime_contract`) | schema + `docs/compatibility-and-interop.md` | runtime-trigger |
| P7 | Release-tag conventions (`exec.<slug>@x.y.z`, CI-created after merge) | `tag-releases` workflow, `docs/versioning.md` | A, C |

## What is NOT provisional (kept stable)
- Runtime sessions/tapes stay **outside Git**; definitions hold only immutable/verifiable evidence *references* (URI + digest).
- **Released-definition immutability** (digest-pinned; enforced by `validate` and `check-changes`, covered by tests).
- Definitions contain logical names only: no endpoints, no secrets.

## Guidance for reconciliation
Prefer changing the *mapping layer* (schema patterns, `changes.mjs`, `tag-releases`, docs) over the invariants above. If model A changes to directory-per-version, the digest algorithm and ledger semantics in `scripts/lib/registry.mjs` are the reusable parts. The full list of open decisions is in [decisions.md](decisions.md).

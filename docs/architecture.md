# Architecture

## Boundaries

```
 registry-skills / tiny-agents / qb-agents  ── structured references {registry,id,version,digest?} ──┐
                                                                                                    ▼
 ┌───────────────────────────────  registry-execution-agents (this repo: the WHAT)  ─────────────────────┐
 │  registry/  canonical + candidates (sealed, immutable)  ·  lifecycle overlays  ·  index.json           │
 │  synthetic/ isolated examples                                                                          │
 └───────────────▲──────────────────────────────────────────────────────────────┬────────────────────────┘
                 │ candidate objects (governed via PR)                          │ resolver: range → exact version → digest
   evaluation / evolution proposers                                             ▼
                                                                     runtime (the HOW) → runtime lock → evidence (outside Git)
```

- **Owned here:** identity, sealed content, `spec` semantics, maturity, lifecycle overlays, provenance, digest-bound attestations, indexes.
- **Not owned here:** execution, scheduling, secrets, gateways, model catalogues, telemetry, tapes, the Evidence Protocol, capability/tool/model namespace ownership. Artifacts contain structured references and logical names only. Validators reject endpoints (URL schemes, `host:port`) and credential-shaped values in the artifact and in every sidecar payload file.

## Identity and immutability

An artifact version is a directory. Its **seal** (`seal.yaml`) records a content digest over the canonical artifact plus every payload file. From then on the object never changes: validation recomputes the seal, and `check-changes` compares against the base ref. Only governance state changes, and only append-only: attestations, approvals, lifecycle events; plus the one-way `candidate → canonical` maturity move, which keeps the digest.

## Two domains

| Domain | Directory | Ids | May contain |
|---|---|---|---|
| production | `registry/` | anything except `synthetic.*` | real artifacts |
| synthetic | `synthetic/` | must start with `synthetic.` | examples and fixtures |

Production artifacts may not reference synthetic ids; objects may not leave the synthetic domain; the production index is rebuilt and checked to contain no synthetic entries.

## Evolution loop (candidates as registry objects)

```
canonical id@v → execution → evidence (outside Git) → evaluation → candidate object (id@v', origin: evolved)
      ▲                                                                   │ sealed, attested (digest-bound)
      └────── promotion: gates + approvals → same sealed object under canonical/ ◄──┘
```

Git branches/PRs carry a candidate into the repository for review; the candidate is meaningful as a registry object regardless of the branch. See [maturity-and-promotion](maturity-and-promotion.md).

## AgentGit influence (concepts only)

| AgentGit idea | Here |
|---|---|
| Checkpoint/commit | Sealed artifact version (digest) |
| Non-destructive branching | Candidate object with `origin.evolution.sourceRefs` to the version it evolved from |
| Rollback | Lifecycle overlay (`revoked`/`deprecated`) and re-resolution to a prior version; nothing is erased |
| Tool history / trajectories | Runtime tapes, kept outside Git and referenced by `evidence://` pointers |
| Lineage / evidence chain | `sourceRefs` + digest-bound attestations |

Runtime-level checkpoint/rollback behaviour is declared in `spec.checkpointPolicy` and executed by the runtime. No SQLite, LangGraph or AgentGit dependency.

## Enforcement map

| Rule | Where |
|---|---|
| Schemas (envelope, spec, seal, overlay, index) | `schemas/`, `scripts/validate.mjs` |
| Semantic rules, promotion gates, isolation, reference structure | `scripts/lib/rules.mjs` |
| Seal correctness, stale attestations | `rules.mjs` (`sealRules`) |
| Immutability and append-only history vs base | `scripts/check-changes.mjs`, `lib/changes.mjs` |
| Deterministic indexes | `scripts/build-index.mjs --check` |
| Human review of schemas/scripts/workflows | `CODEOWNERS` (placeholder handles) |

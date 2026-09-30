# registry-execution-agents

The canonical registry of **Zeptly Execution Agent** artifacts, conforming to **Zeptly Registry Protocol v0.1** (`apiVersion: registry.zeptly.dev/v1alpha1`).

> This registry defines **what** an Execution Agent is. A runtime (later, `Zeptly/runtime-trigger` on Trigger.dev) decides **how** it runs. No runtime, gateway or evidence-store code lives here.

Scope: Execution Agents only. The protocol envelope is shared with other registries; the `spec` of an `ExecutionAgent` is owned here and preserves durable task contracts and retry, timeout, checkpoint, state and execution policies.

## Model at a glance

| Concern | How it is represented |
|---|---|
| Published version | Immutable directory `<id>/<version>/` holding `artifact.yaml`, payload files and `seal.yaml`. Addressed by **version + content digest**. |
| Maturity | `metadata.maturity`: `candidate` or `canonical`. Candidates are **registry objects** (Git branches/PRs are only governance transport). |
| Lifecycle | Append-only **overlay** (`lifecycle/<id>.yaml`): `active`, `deprecated`, `revoked`. |
| Origin | `metadata.origin.type`: `native`, `upstream-seed`, `evolved` (evolution lineage and `kind` live only at `metadata.origin.evolution`). |
| References | Structured `{registry, id, version, digest?}` objects. Canonical artifacts pin exact version **and** digest. |
| Attestations / approvals | Bound to the exact subject digest; **stale ones fail validation**. |
| Evidence | Opaque `evidence://…` pointers (synthetic evidence only as `evidence://synthetic/…`). Raw tapes/trajectories never enter Git; version directories follow a strict file allow-list. |
| Indexes | Deterministic derived files `registry/index.json`, `synthetic/index.json` (code-point ordering, no timestamps), checked in CI. |
| Synthetic examples | Isolated `synthetic/` tree + `synthetic.` id namespace. Can never enter the production index. |

## Layout

```
registry/                        PRODUCTION domain (currently empty: no production artifacts yet)
  canonical/<id>/<version>/      artifact.yaml · seal.yaml · prompts/ · contracts/ · evals/
  candidates/<id>/<version>/     same shape, maturity: candidate
  lifecycle/<id>.yaml            append-only lifecycle overlay
  index.json                     generated
synthetic/                       ISOLATED synthetic examples (same structure, ids start with `synthetic.`)
schemas/                         common · execution-agent · seal · lifecycle · index · eval-suite
scripts/                         validate · seal · attest · promote · build-index · check-changes
docs/  test/  .github/
```

## Quick start

```bash
npm ci
npm run ci                                      # validate both domains, indexes are current, tests
node scripts/check-changes.mjs --base origin/main   # immutability against a base ref

node scripts/seal.mjs <artifact-dir>            # write seal.yaml (content digest)
node scripts/attest.mjs <artifact-dir> --type evaluation --suite <id> --result pass --ref evidence://…
node scripts/attest.mjs <artifact-dir> --approval promotion --approver github:<user>
node scripts/promote.mjs <id> <version>         # candidate -> canonical (gates enforced, digest unchanged)
npm run build:index                             # regenerate both indexes
```

## Docs

[Architecture](docs/architecture.md) · [Artifact model](docs/artifact-model.md) · [Sealing & versioning](docs/sealing-and-versioning.md) · [Maturity & promotion](docs/maturity-and-promotion.md) · [Lifecycle](docs/lifecycle.md) · [References & resolution](docs/references-and-resolution.md) · [Evidence model](docs/evidence-model.md) · [Security](docs/security.md) · [Protocol conformance](docs/protocol-conformance.md) · [Deferred decisions](docs/decisions.md)

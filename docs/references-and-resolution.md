# References and resolution

## Structure

```yaml
{ registry: skills, id: ticket-classification, version: "^1.0.0", digest: null }
```

- `references[]` (envelope): dependencies on registry artifacts; `registry` ∈ `skills | tiny-agents | execution-agents | qb-agents`.
- Origin/provenance `sourceRefs`: exact `{registry,id,version,digest}` artifact refs or `evidence://` pointers.
- Platform references (tools, capabilities, models, secrets) use the same shape, but `registry` is an **opaque label**: namespace ownership is a deferred platform decision, so only structure is validated.

Everything validates structurally offline. Only `registry: execution-agents` references can be resolved locally, and they are (version satisfaction, digest equality, canonical→canonical only). References to other registries are structure-checked only; no network access occurs.

## Executable dependencies vs lineage (lifecycle eligibility)

Two kinds of local `execution-agents` reference are validated differently:

| Kind | Where | Eligibility |
|---|---|---|
| **Executable dependency** | `references[]` | target must be **canonical** and lifecycle-eligible: `revoked` **never** satisfies; `deprecated` satisfies only an **explicit exact pin**; **range selection excludes** deprecated and revoked versions and picks the highest eligible version |
| **Lineage (historical)** | `metadata.origin.evolution.sourceRefs` | describes an ancestor; any maturity and any lifecycle state, including `revoked` — this never authorizes executing it. Existence and digest are still verified |

The effective lifecycle comes from the append-only overlay for the exact `(version, digest)`. A dependent that is itself effectively `revoked` is not held to dependency eligibility (it can no longer run). This is validation-time behaviour only; it is not a resolver.

## Pinning

| Maturity | Requirement |
|---|---|
| candidate | ranges (`^`/`~`) and `digest: null` allowed |
| canonical | exact version **and** digest for `references`; exact versions for platform references that carry one |

## Runtime locks are runtime-owned

This registry does **not** generate, store or validate runtime locks. Producing a lock (declared range → exact version → digest, recorded in evidence) is a runtime responsibility. The registry supplies the inputs only: the index (`registry/index.json`), the seal digest, and structurally valid references. No registry-side lock shape is defined here; when a shared lock shape exists, the runtime will emit it, including an explicit representation of unresolved foreign references. Foreign (non-`execution-agents`) references are validated structurally only, and the registry never claims they resolved.

## Resolution model

```
declared range → resolver → exact version → content digest → runtime lock → evidence
```

The resolver (a runtime concern) picks an exact version from the index (`registry/index.json`: identity, version, digest, maturity, lifecycle, origin, location), verifies the digest against `seal.yaml`, refuses `revoked`, and records the lock in evidence. The digest algorithm is `computeSeal` in `scripts/lib/core.mjs`; consumers may port it.

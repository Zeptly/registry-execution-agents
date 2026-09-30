# References and resolution

## Structure

```yaml
{ registry: skills, id: ticket-classification, version: "^1.0.0" }
# pinned: { …, version: 1.2.0, digest: sha256:…, digestAlgorithm: zeptly-jcs-v1 }
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

Pins use the **artifactDigest**; any reference carrying a digest also carries `digestAlgorithm: zeptly-jcs-v1`. Prerelease versions satisfy a range only when the range names a prerelease; malformed ranges (`*`, `1.x`, `>=`, `^1.0`, build metadata) are rejected with code `invalid-range`.

## Pinning

| Maturity | Requirement |
|---|---|
| candidate | ranges (`^`/`~`) and `digest: null` allowed |
| canonical | exact version **and** digest for `references`; exact versions for platform references that carry one |

## Runtime locks are runtime-owned

This registry does **not** implement a resolver, generate locks or read peer indexes (Protocol v0.2 §13.5 fixtures are therefore not provided here). Producing a `RuntimeLock` (`complete`, `entries[].requested/status/unresolved{code,message}`, e.g. `no-peer-index`, `invalid-range`) is a runtime responsibility. The registry's obligation is that its generated index is consumable by such a resolver: each entry carries `registry`, `id`, `version`, `artifactDigest`, `sealDigest`, `digestAlgorithm`, `maturity`, effective `lifecycle`, `origin` and `location`, and the top level carries `domain`. Production and synthetic indexes are separate and must not be mixed. Foreign (non-`execution-agents`) references are validated structurally only; the registry never claims they resolved.

## Resolution model

```
declared range → resolver → exact version → artifact digest → runtime lock → evidence
```

The resolver (a runtime concern) picks an exact version from the index, verifies the digest against `seal.yaml`, refuses `revoked`, resolves `deprecated` only by exact pin, requires explicit opt-in for candidates, and records the lock in evidence. Index ordering (code-point `id`, SemVer, digests) is separate from JCS key ordering (UTF-16).

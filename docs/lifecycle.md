# Lifecycle

Lifecycle is an **append-only overlay**, independent of maturity and origin. `metadata.lifecycle` in the artifact is a publication marker (excluded from the digest) recording the state at publication (`active`); the effective state is the last overlay event for that exact `(id, version, digest)` (the `artifactDigest`; overlays carry `digestAlgorithm: zeptly-jcs-v1`), defaulting to `active`.

```yaml
# registry/lifecycle/support.ticket-triage.yaml
apiVersion: registry.zeptly.dev/v1alpha1
kind: LifecycleOverlay
digestAlgorithm: zeptly-jcs-v1
subject: { registry: execution-agents, id: support.ticket-triage }
events:
  - { version: 1.0.0, digest: sha256:…, state: deprecated, at: "2026-10-01T00:00:00Z", actor: team:x, reason: superseded, supersededBy: {registry: execution-agents, id: support.ticket-triage, version: 1.1.0} }
```

| From | To |
|---|---|
| active | deprecated, revoked |
| deprecated | active, revoked |
| revoked | (terminal) |

`deprecated` and `revoked` require a `reason`. Events must be chronological and each must match an existing artifact's digest. Existing events are never edited, removed or reordered (`check-changes`). Overlays apply to candidates too (e.g. revoking a rejected candidate); artifacts are never deleted.

Indexes report the effective lifecycle; resolvers should refuse `revoked`, warn on `deprecated`.

**Eligibility as an executable dependency** (validated for local `references[]`): `revoked` never satisfies a dependency; `deprecated` satisfies only an explicit exact pin and is excluded from range selection. Historical lineage (`origin.evolution.sourceRefs`) may name a revoked ancestor without authorizing its execution. See [references-and-resolution](references-and-resolution.md#executable-dependencies-vs-lineage-lifecycle-eligibility).

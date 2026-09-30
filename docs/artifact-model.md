# Artifact model

Machine schema: [`schemas/execution-agent.schema.json`](../schemas/execution-agent.schema.json) with shared definitions in [`common.schema.json`](../schemas/common.schema.json). Unknown fields are rejected.

## Envelope (Protocol v0.1)

```yaml
apiVersion: registry.zeptly.dev/v1alpha1
kind: ExecutionAgent
metadata:
  id: support.ticket-triage          # dotted lowercase segments; permanent
  version: 1.0.0                     # SemVer
  registry: execution-agents
  origin: { type: native }           # native | upstream-seed | discovered | refined | evolved
  maturity: canonical                # candidate | canonical
  lifecycle: active                  # publication marker only (not in the digest); the effective state is the overlay
spec: { … }                          # Execution Agent semantics (below)
references: [ {registry: skills, id: ticket-classification, version: 1.2.0, digest: sha256:…} ]
provenance: { createdAt, authors, sourceRefs, transformations }
security: { classification, capabilities: [refs], approvals: [governed approvals] }
attestations: [ {type, ref: evidence://…, subjectDigest: sha256:…, sealDigest: sha256:…, suite?: {id, version, digest}, result?} ]
```

## Origin

| `origin.type` | Meaning | Required block |
|---|---|---|
| `native` | Created in this registry | none |
| `upstream-seed` | Seeded from an upstream source | `origin.import {source, license?}` |
| `discovered` / `refined` | Found or refined by evidence | optional `origin.evolution` |
| `evolved` | Derived from an earlier version by evidence | `origin.evolution {kind, sourceRefs, rationale, proposer, expectedEffect?}` (required) |

`metadata.origin.evolution.kind` is the **sole** location of the evolution kind (`discovered | refined | generalised`). Nothing under `provenance` carries an evolution kind, and the schema rejects it there. The index's `origin.evolutionKind` is derived data.

## `spec` (class-specific, preserved)

| Field | Meaning |
|---|---|
| `name`, `description`, `purpose{summary,goals,nonGoals}`, `owners`, `tags` | Human meaning. |
| `instructions.file` | Markdown instructions (payload file, sealed). |
| `contract.input/output` | JSON Schemas (`schema` inline or `schemaFile`); `delivery` for output mode/size. Eval inputs are validated against the input contract. |
| `tools[]` | Structured tool references with `sideEffects`, `requiresApproval` and an optional capability reference. |
| `modelPolicy` | `tier`, ordered `models` (structured references), required features, sampling, budget. |
| `executionPolicy` | `single_pass` / `workflow` / `agent_loop`, step cap, idempotency, triggers, human-in-the-loop. |
| `timeoutPolicy`, `retryPolicy` | Run/step/tool limits; attempts, backoff, retry and never-retry classes. |
| `checkpointPolicy` | Strategy, resumability, captured items, non-destructive rollback and compensation. |
| `state` | Persistence and declared stores (scope, retention, PII). |
| `dataHandling`, `secrets`, `permissions` | PII/redaction/residency; secret **names**; scopes, egress mode, side-effect class, runtime approvals. |
| `evaluation` | Required suites (`evals/*.yaml`) and promotion gates. |
| `observability` | Tracing, metrics, and what a run must record as evidence. |
| `compatibility.requiredRuntimeFeatures` | Feature labels the runtime must provide. Runtime-contract versioning is deferred. |

## Attestations

`{type, ref: evidence://…, subjectDigest, sealDigest, suite?, result?, issuedAt?, attestor?}`. `type` ∈ `evaluation | security-review | provenance`. `subjectDigest` is the `artifactDigest`; `sealDigest` (registry-local) binds the payload, which is outside the artifact digest. For `evaluation`, `suite` is `{id, version, digest}` (suite digest = sha256 of the suite file bytes) and `result` (`pass | fail | inconclusive`) is required; only a `pass` matching the current suite and both digests satisfies promotion (see [maturity-and-promotion](maturity-and-promotion.md)). `suite`/`result` are rejected on other types. Attestations are append-only and excluded from the digest.

## Independent dimensions

`maturity` (candidate|canonical), `metadata.lifecycle` / overlay (active|deprecated|revoked) and `origin` (native|upstream-seed|discovered|refined|evolved) are separate fields and change independently. Maturity is governance state, not content; it is excluded from the digest.

## Cross-field rules (validator-enforced)

Irreversible tools require approval and a matching `permissions.sideEffects`; side effects need a write scope; retries with side effects need idempotency; rollback with irreversible effects needs compensation; step/tool timeouts ≤ run timeout; checkpoint/timeout coherence; `confidential`/`restricted` need evidence redaction, `restricted` cannot run `humanInTheLoop: never`; egress `none` conflicts with declared capabilities; no endpoints (URL schemes, `host:port`) or credential-shaped strings in the artifact or any sidecar payload file. Canonical artifacts additionally need a required evaluation suite, tracing on, and the promotion gates (explicit passing evaluation result per required suite, bound to the digest). Full list: `scripts/lib/rules.mjs`.

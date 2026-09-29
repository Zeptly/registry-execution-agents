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
  origin: { type: authored }         # authored | imported | evolved
  maturity: canonical                # candidate | canonical
  lifecycle: active                  # lifecycle AT PUBLICATION; the effective state is the overlay
spec: { … }                          # Execution Agent semantics (below)
references: [ {registry: skills, id: ticket-classification, version: 1.2.0, digest: sha256:…} ]
provenance: { createdAt, authors, sourceRefs, transformations }
security: { classification, capabilities: [refs], approvals: [governed approvals] }
attestations: [ {type, ref: evidence://…, subjectDigest: sha256:…, suite?} ]
```

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

## Independent dimensions

`maturity` (candidate|canonical), `metadata.lifecycle` / overlay (active|deprecated|revoked) and `origin` (authored|imported|evolved) are separate fields and change independently. Maturity is governance state, not content; it is excluded from the digest.

## Cross-field rules (validator-enforced)

Irreversible tools require approval and a matching `permissions.sideEffects`; side effects need a write scope; retries with side effects need idempotency; rollback with irreversible effects needs compensation; step/tool timeouts ≤ run timeout; checkpoint/timeout coherence; `confidential`/`restricted` need evidence redaction, `restricted` cannot run `humanInTheLoop: never`; egress `none` conflicts with declared capabilities; no `http(s)` URLs or credential-shaped strings. Canonical artifacts additionally need a required evaluation suite, tracing on, and the promotion gates. Full list: `scripts/lib/rules.mjs`.

# Execution Agent definition reference

> **PROVISIONAL — pending [cross-registry reconciliation](cross-registry-reconciliation.md).** Identifier namespaces (`exec.`, `skill.`, `cap.`, `tool.`, `model.`, `secret.`) are provisional.

Authoritative machine schema: [`schemas/execution-agent.schema.json`](../schemas/execution-agent.schema.json). This page explains intent. Unknown fields are rejected; use `extensions` (`x-` keys) for experiments — runtimes must ignore them.

| Section | Meaning |
|---|---|
| `id` | Permanent `exec.<kebab-slug>`; equals directory name. Never reused, never renamed. |
| `name`, `description`, `purpose{summary,goals,non_goals}` | Human meaning. Changing `purpose` is a **major** change. |
| `version`, `status`, `lifecycle` | Semver; lifecycle state; mutable status metadata (excluded from digest). |
| `owners` | Accountable principals (`team:`, `github:`). |
| `provenance` | Origin, authors, `change_ref`, `derived_from`, mutation rationale, evidence refs. See [evidence-model](evidence-model.md). |
| `instructions.file` | Markdown instructions; hashed. Treated by runtimes as the agent's system prompt. |
| `contract.input/output` | JSON Schema (inline or file). Eval inputs are validated against the input schema. |
| `skills[]` | `skill.*` from `Zeptly/registry-skills`, with version (exact when released). |
| `capabilities[]` | `cap.*` abstract abilities served by gateways (e.g. `cap.messaging.post`) and why they are needed. |
| `tools[]` | `tool.*` bindings, optionally tied to a capability; declare `side_effects` and `requires_approval`. |
| `model_policy` | Tier, ordered `model.*` aliases (resolved by the AI Gateway), required features, budget. No vendor IDs/endpoints. |
| `execution_policy` | `single_pass`/`workflow`/`agent_loop`, step cap, idempotency, triggers, human-in-the-loop. |
| `timeout_policy`, `retry_policy` | Run/step/tool limits; attempts, backoff, retry and never-retry classes. |
| `checkpoint_policy` | Strategy, resumability, captured items, non-destructive rollback and compensation. |
| `state` | Persistence level and declared stores (scope, retention, PII). |
| `security` | Classification, data handling, logical `secret_refs`, review requirement. |
| `permissions` | Scopes (`domain:read|write|admin`), egress mode, side-effect class, approvals. |
| `evaluation` | Required suites (`evals/*.yaml`) and promotion gates. |
| `observability` | Tracing, metrics, and **evidence recording** (tape contents, retention, sampling). |
| `compatibility` | Needed runtime-contract range, skills-registry range, required runtime features, `supersedes`. |

## Identifier namespaces

`exec.` agents · `skill.` skills (registry-skills) · `cap.<domain>.<name>` capabilities · `tool.` tools · `model.` gateway model aliases · `secret.` secret names. Namespaces of non-owned components are *assumptions* to be confirmed ([decisions](decisions.md)).

## Cross-field rules (validator-enforced)

Highlights: irreversible tools require approval and a matching `permissions.side_effects`; side effects need a write scope; `restricted`/`confidential` need `security_review_required` and evidence redaction; `restricted` cannot run with `human_in_the_loop: never`; retries with side effects need idempotency; rollback with irreversible effects needs compensation; step/tool timeouts ≤ run timeout; active agents need ≥1 required eval suite and non-`off` tracing; no `http(s)` URLs or credential-shaped strings anywhere. Full list: `scripts/lib/semantic.mjs`.

## Adding a new agent

Copy `templates/agent/` to `agents/<slug>/`, edit, run `npm run validate`.

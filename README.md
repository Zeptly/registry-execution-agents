# registry-execution-agents

The canonical, Git-native registry of **Zeptly Execution Agent** definitions.

> This registry defines **what** an Execution Agent is. `Zeptly/runtime-trigger` (on Trigger.dev) decides **how** it runs.
> Git is the authoritative ledger; Trigger.dev, Cortex and telemetry stores are never the source of truth for a definition.

Scope: Execution Agents only. Tiny Agents, Timesavers, QB Agents and Zep are out of scope.

## What's here

| Path | Purpose |
|---|---|
| `agents/<slug>/` | One directory per agent: `agent.yaml`, `releases.yaml` (append-only ledger), `prompts/`, `contracts/`, `evals/`, `CHANGELOG.md` |
| `schemas/` | JSON Schema (2020-12) for manifests, release ledgers and eval suites |
| `scripts/` | Validation, digesting, release recording, change checks, tagging, index build |
| `docs/` | Architecture and rules (start with [architecture](docs/architecture.md)) |
| `examples/candidates/` | A worked candidate-mutation (evidence-driven improvement) that is valid but not mergeable |
| `templates/agent/` | Scaffold for a new agent |
| `.github/workflows/` | CI validation, merge gate and release tagging |

Example agents: `exec.support-ticket-triage` (active), `exec.weekly-metrics-digest` (active, approval-gated side effect), `exec.contract-clause-extractor` (draft, restricted data).

## Quick start

```bash
npm ci
npm run ci                                   # validate agents, examples, run tests
node scripts/check-changes.mjs --base origin/main   # immutability / semver / lifecycle rules vs base
npm run build:index                          # writes dist/registry-index.json (generated, not committed)
```

Add or change an agent: see [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/promotion-workflow.md](docs/promotion-workflow.md).

## Core ideas

1. **Stable identity, explicit versions.** `exec.<slug>` never changes; every reference is `id@version`. Released versions are immutable, pinned by a content digest in `releases.yaml` and by a git tag `exec.<slug>@x.y.z`.
2. **Declarative definitions.** Instructions, I/O contracts, policies (model, execution, timeout, retry, checkpoint), permissions, security, evaluation and observability requirements — no endpoints, no secrets, no runtime code.
3. **Evidence informs change; it never applies it.** Execution → tape/evidence → evaluation → *candidate* → PR → validation → promotion. Nothing writes to canonical definitions except a reviewed merge.
4. **Pointers, not payloads.** Tapes and telemetry live outside Git and are referenced by logical URI + digest ([evidence model](docs/evidence-model.md)).
5. **Portable.** YAML, JSON, Markdown; Node scripts with three small dependencies (`ajv`, `ajv-formats`, `yaml`).

## Docs

- [Architecture](docs/architecture.md) — layout, boundaries, AgentGit influence
- [Agent definition reference](docs/agent-definition.md)
- [Versioning](docs/versioning.md) · [Lifecycle](docs/lifecycle.md)
- [Evidence model](docs/evidence-model.md) · [Promotion workflow](docs/promotion-workflow.md)
- [Security](docs/security.md) · [Compatibility & interoperability](docs/compatibility-and-interop.md)
- [Decisions & open questions](docs/decisions.md)

# Architecture

> **PROVISIONAL — pending [cross-registry reconciliation](cross-registry-reconciliation.md).** The head-definition + release-ledger model (A), candidates-as-branches (B), `exec.<slug>@version` identity and `skill.*`/`cap.*`/`tool.*`/`model.*` namespaces (C) are working defaults, not Zeptly-wide conventions.

## Boundaries

```
                     Zeptly/registry-skills  (skill.* definitions)
                              ▲  id@version refs
 ┌────────────────────────────┴───────────────────────────┐
 │  registry-execution-agents   (THIS REPO — the WHAT)     │
 │  agents/<slug>/agent.yaml  + releases.yaml + git tags   │
 └───────┬─────────────────────────────────▲──────────────┘
         │ read exact id@version+digest    │ candidate PRs (branch → validate → promote)
         ▼                                 │
 Zeptly/runtime-trigger  (the HOW)   evaluation / evolution proposers
   Trigger.dev tasks ──executes──► sessions, tapes, traces ──► Supabase/Cortex (evidence store)
   AI Gateway (model.* aliases)  ·  Railway capability gateways (cap.* / tool.*)
```

- **This repo owns:** identity, definition, versions, lifecycle, provenance, contracts, policies, evaluation *requirements*, promotion history.
- **This repo does not own:** execution, scheduling, secrets, model endpoints, provider gateways, telemetry, tapes. Definitions therefore contain *logical names* (`model.balanced-default`, `cap.messaging.post`, `secret.x`) and never URLs or credentials; validation rejects `http(s)://` strings.
- **Runtime contract:** the runtime resolves `id@version`, verifies the digest, checks `compatibility`, then maps logical names to infrastructure. See [compatibility-and-interop](compatibility-and-interop.md).

## Repository layout

```
agents/<slug>/
  agent.yaml            canonical manifest (id = exec.<slug>)
  releases.yaml         append-only ledger: version → digest → git tag → approvals/evidence
  prompts/system.md     instructions (hashed with the manifest)
  contracts/*.json      input/output JSON Schemas (or inline in the manifest)
  evals/*.yaml          declarative evaluation suites (hashed)
  CHANGELOG.md
schemas/                execution-agent, releases, eval-suite JSON Schemas
scripts/                validate · release · check-changes · tag-releases · build-index
docs/  examples/  templates/  .github/
```

## How Git is the ledger (AgentGit-inspired)

[AgentGit](https://github.com/MAS-Infra-Layer/Agent-Git) versions *agent runs*: external/internal sessions, checkpoints, non-destructive branching from a checkpoint, tool-call tracks, and rollback that forks rather than erases. Zeptly keeps those ideas but splits them across two planes so no runtime store becomes canonical:

| AgentGit concept | Zeptly translation | Plane |
|---|---|---|
| Commit / checkpoint | A released agent **version** (`releases.yaml` entry + git tag + digest) | Definition (Git) |
| Non-destructive branch | **Candidate** branch/PR derived from a released version (`provenance.derived_from`) | Definition (Git) |
| Rollback | Re-point consumers to a prior `id@version`, or deprecate; history is never rewritten | Definition (Git) |
| Lineage | `derived_from` chain + `supersedes` / `replaced_by` | Definition (Git) |
| Sessions / internal sessions | Runtime sessions; checkpoint/rollback behaviour declared in `checkpoint_policy` | Execution (runtime) |
| Tool track / reproducible trajectory | **Tape** recorded per `observability.evidence`; stored externally | Evidence (Cortex/object store) |
| Evidence chain | `evidenceRef` pointers with digests attached to candidates and releases | Bridge |

Not adopted: SQLite persistence, LangGraph coupling, Python API. Nothing here imports or depends on AgentGit.

## Evolution loop

```
canonical id@v ─► execution ─► session/tape ─► evaluation ─► candidate mutation
        ▲                                                         │ branch + PR (evidence refs)
        │                                                         ▼
   new canonical id@v+1 ◄── promotion (gates, approvals, release entry, tag) ◄── validation (CI)
```

Only the merge of a reviewed PR changes canonical state. See [promotion-workflow](promotion-workflow.md).

## Enforcement

| Rule | Where enforced |
|---|---|
| Schema shape | `schemas/*.json` via `scripts/validate.mjs` |
| Semantic coherence (policies, security coupling, pins, endpoints) | `scripts/lib/semantic.mjs` |
| Released version immutability (digest) | `validate` (ledger vs digest) + `check-changes` (vs base) |
| Ledger append-only, semver bump adequacy, legal status transitions | `scripts/check-changes.mjs` |
| Candidates cannot merge | CI `merge-gate` job (`--forbid-candidates`) |
| Tags for releases | `tag-releases` workflow |
| Human review of schemas/scripts/workflows | `CODEOWNERS` |

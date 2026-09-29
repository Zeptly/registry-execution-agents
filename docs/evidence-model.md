# Evidence & provenance model

> **PROVISIONAL — pending [cross-registry reconciliation](cross-registry-reconciliation.md).** The URI schemes are provisional. The principle — tapes/sessions stay outside Git; definitions carry only immutable, verifiable references — is NOT provisional.

**Principle:** execution produces evidence; evidence may motivate a candidate; a candidate is only ever a proposal. Large or sensitive runtime data stays out of Git.

## What lives where

| Artifact | Home | In Git? |
|---|---|---|
| Canonical definition, ledger, changelog | this repo | Yes |
| Session, tape (prompts, model outputs, tool calls/results, checkpoints, state diffs), traces | Supabase/Cortex or object storage, written by the runtime | **No — pointer only** |
| Eval run results | eval harness store | Pointer + summary |
| Review/approval | GitHub PR | PR + `approved_by` in ledger |

What a run must record is declared per agent in `observability.evidence`; the runtime enforces redaction (`security.data_handling.redact_in_evidence`).

## `evidenceRef`

```yaml
- id: failing-sessions            # unique within the manifest
  kind: session                   # session | tape | checkpoint | eval_run | trace | artifact | review | incident
  role: motivates                 # motivates | supports | baseline | regression | approval
  uri: cortex://sessions/exec.support-ticket-triage/batch-2026-10-03   # logical locator, never http(s)
  digest: sha256:…                # content hash of the referenced evidence bundle (recommended)
  agent_version: 1.0.0            # version that produced it
  summary: 14 sessions where …    # human-readable, no raw data
```

URI schemes are logical (`cortex`, `tape`, `evalrun`, `trace`, `artifact`, `git`); the runtime/Cortex resolves them. The digest lets a reviewer or auditor confirm the bundle they retrieve is the one the PR cited (evidence chain).

## Provenance

`provenance.origin`:

- `human_authored` — written by a person.
- `imported` — brought from elsewhere (`source.origin_ref`, `license`).
- `derived` — based on another agent (`derived_from`).
- `candidate_mutation` — proposed from evidence: requires `derived_from` (same agent, a *released* lower version), `mutation{kind,rationale,proposer,expected_effect}` and `evidence[]` with at least one `motivates` entry. Proposers may be agents (`agent:<id>`) — but only through a PR.

`change_ref` is `bootstrap` or `github:<owner>/<repo>#<n>`, tying each version to its reviewed change. Lineage across versions = `derived_from` chain + git history + ledger.

## Reproducibility & rollback

- Reproducible trajectory: tape + the exact `id@version+digest` that ran (runtimes should stamp both on every session).
- Rollback of a *definition*: point consumers at a previous `id@version` (tags are permanent) or deprecate the bad version; never rewrite history.
- Rollback of a *run*: declared in `checkpoint_policy.rollback` and executed by the runtime as a fork from a checkpoint (non-destructive); compensation for side effects is tool-declared or manual.

See `examples/candidates/support-ticket-triage/` for a complete example.

# Security considerations

## Threat model (registry level)
| Threat | Mitigation |
|---|---|
| Silent mutation of a production definition | Digest immutability, append-only ledger, PR-only changes, tags, CODEOWNERS |
| Self-improving agent widens its own privileges | Candidates cannot merge; permission expansion forces ≥ minor bump + `security_review_required`; human approval gate |
| Secrets or endpoints leaked into Git | Validator rejects `http(s)://` strings and credential-shaped patterns; only logical `secret.*` names allowed; `redact_in_evidence` |
| Sensitive execution data in Git | Evidence by pointer only; tapes stay in Cortex with redaction and retention declared |
| Prompt injection via task inputs | Instructions declare inputs untrusted; irreversible tools require approval; egress restricted to declared capabilities |
| Supply-chain drift of dependencies | Exact pins (+ optional digest) for released agents |
| Workflow tampering | `.github/` and `schemas/` are CODEOWNERS-protected security paths |

## Classification
`public` < `internal` < `confidential` < `restricted`. `confidential`/`restricted` require security review and evidence redaction; `restricted` cannot run fully autonomously. Classification changes are treated as permission expansion.

## Permissions
Scopes are `domain:read|write|admin`. Definitions *declare* what they need; enforcement is the runtime's and gateways' job (least privilege, workspace-scoped). `side_effects` is the max class across tools: `none` / `reversible` / `irreversible`. Irreversible ⇒ per-action approval.

## Repository settings (owner action — NOT configured by this repository)
This repo does not configure or assume any GitHub settings. Repository owners should decide whether to apply them. The CI checks this registry provides, and which any branch protection/ruleset should require, are:

- `validate` (workflow `validate`, job `validate`) — schema, semantic validation, tests, change checks vs base.
- `merge-gate` (workflow `validate`, job `merge-gate`) — blocks `status: candidate` from merging.

Also recommended (owner decisions): CODEOWNERS review with real teams (current handles are placeholders), no force-push to `main`, protection for `exec.*@*` tags, secret scanning and push protection. Report vulnerabilities per [SECURITY.md](../SECURITY.md).

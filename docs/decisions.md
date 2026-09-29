# Decisions & open questions

> **PROVISIONAL.** Every "decision" below is a working default made to build and test this registry in isolation. None is a finalised Zeptly-wide convention. See [Cross-Registry Reconciliation Required](cross-registry-reconciliation.md) (items A, B, C). Open questions were deliberately **not** closed by inventing conventions.

## Working defaults (PROVISIONAL unless marked stable)
| # | Decision | Rationale |
|---|---|---|
| D1 (P1, A) | One manifest per agent at HEAD; history via git + tags + ledger (not a `versions/` directory per release) | Avoids duplicated files and drift; Git already versions; ledger digest + tag gives immutability |
| D2 (stable invariant support) | Digest excludes `status`/`lifecycle` | Deprecation shouldn't require a new version |
| D3 (P2, B) | `candidate` never merges | Keeps main = canonical; candidates are PR branches |
| D4 (P5; the pointer-only principle is stable) | Evidence by logical URI + digest | No endpoints in Git; portable across Cortex/object stores |
| D5 | Node + JSON Schema (Ajv) for tooling | Same ecosystem as Trigger.dev/TypeScript runtime; tiny deps |
| D6 (P4, C) | Logical names for models/caps/tools/secrets | Infrastructure-agnostic definitions |
| D7 (P7) | Tags created by CI after merge | Ledger lands with the PR; tag follows the merge commit |

## Open questions (need owners outside this repo)
1. **Skill ID/version scheme** in `Zeptly/registry-skills` — `skill.<slug>` + semver assumed. Adjust `skillId` pattern if it differs.
2. **Capability & tool taxonomy** (`cap.<domain>.<name>`, `tool.*`) — who owns the catalogue? Should tool contracts (side effects, compensation) be sourced from a registry rather than restated per agent?
3. **Evidence URI schemes** and Cortex resolution/authorization model; whether digest is mandatory for release evidence.
4. **Model alias catalogue** owned by the AI Gateway (`model.*`) and how tiers map.
5. **Runtime contract versioning** — `Zeptly/runtime-trigger` needs to publish version numbers matching `compatibility.runtime_contract`.
6. **Cross-repo validation** — CI check that referenced skills exist (needs registry-skills index/API or a checkout).
7. **Who may propose candidates** (agents, service accounts) and required approver counts per classification (branch protection/rulesets).
8. **Workspace-level overrides** — currently none: this registry is global; per-workspace customization (if any) should be a separate layer that references `id@version`.
9. **Signing** — sign release tags/digests (e.g. Sigstore) if runtimes need tamper evidence beyond Git access control.
10. **Bump-rule heuristic** in `check-changes` covers top-level schema properties only; deep-schema diffing could be added.

11. **Reconciliation A/B/C** — head-definition + ledger vs directory-per-version (A); candidates as branches vs registry data (B); cross-registry identifier/reference syntax (C). See [cross-registry-reconciliation.md](cross-registry-reconciliation.md).
12. **Branch protection / rulesets** — repository-owner action; required checks `validate` and `merge-gate` are documented in `docs/security.md`, not configured by this repo.
13. **CODEOWNERS teams** — handles in `.github/CODEOWNERS` are placeholders until real org teams exist.

# Decisions & open questions

## Decisions (defaults taken)
| # | Decision | Rationale |
|---|---|---|
| D1 | One manifest per agent at HEAD; history via git + tags + ledger (not a `versions/` directory per release) | Avoids duplicated files and drift; Git already versions; ledger digest + tag gives immutability |
| D2 | Digest excludes `status`/`lifecycle` | Deprecation shouldn't require a new version |
| D3 | `candidate` never merges | Keeps main = canonical; candidates are PR branches |
| D4 | Evidence by logical URI + digest | No endpoints in Git; portable across Cortex/object stores |
| D5 | Node + JSON Schema (Ajv) for tooling | Same ecosystem as Trigger.dev/TypeScript runtime; tiny deps |
| D6 | Logical names for models/caps/tools/secrets | Infrastructure-agnostic definitions |
| D7 | Tags created by CI after merge | Ledger lands with the PR; tag follows the merge commit |

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

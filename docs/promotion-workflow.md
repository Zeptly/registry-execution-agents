# Change & promotion workflow

## New agent
1. Copy `templates/agent/` → `agents/<slug>/`; set `status: draft`, version `0.1.0`.
2. `npm run validate`; open PR. Merge as `draft` (incubation) or continue to promotion below.

## Improving an existing agent (human)
1. Branch. Edit the definition; bump `version` per [versioning](versioning.md); update `CHANGELOG.md`.
2. `npm run ci` and `node scripts/check-changes.mjs --base origin/main`.
3. Open PR using the template. CI runs validation, tests, change checks and the merge gate.

## Candidate mutation (evidence-driven, possibly agent-proposed)
1. Proposer reads evidence from Cortex, creates branch `candidate/<agent>-<short-desc>`.
2. Edits the definition; sets `status: candidate`, next version, `provenance.origin: candidate_mutation`, `derived_from` (released version + digest), `mutation`, and `evidence[]` (`motivates`, `baseline`, later `supports`).
3. Opens a **draft PR**. The `merge-gate` job stays red while `status: candidate`; other checks run normally.
4. Evaluation runs (in the runtime/eval harness) against the required suites; results are attached as `eval_run` evidence.
5. Reviewers check the gates in `evaluation.promotion_gates` (no regression, cost/latency limits, minimum runs, human approval).

## Promotion
1. Set `status: active`; run `npm run release -- exec.<slug> --change-ref github:Zeptly/registry-execution-agents#<PR> --approved-by github:<reviewer>` and add `evaluation_evidence` refs to the new ledger entry.
2. Pins must be exact; security-relevant changes need CODEOWNERS/security approval.
3. Merge (squash or merge commit; no history rewrites). The `tag-releases` workflow tags `exec.<slug>@<version>`.
4. Runtimes adopt the new version on their own schedule; the previous version remains resolvable until deprecated.

## Deprecation / retirement
PR that sets `status: deprecated` (with `lifecycle.status_reason`, optional `replaced_by`, `sunset_at`), later `retired`. No version bump required.

## Non-negotiables
- No direct pushes to `main`; branch protection requires `validate` and `merge-gate`.
- Nothing (including agents) writes to canonical definitions except via reviewed PR.
- Never edit a released version; never edit ledger entries.

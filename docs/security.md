# Security

| Threat | Mitigation |
|---|---|
| Silent change to a published definition | Seals, immutability checks vs base, append-only attestations/overlays, PR review |
| Runtime or compiler alters declared classification | Classification is inside the digest; canonical artifacts carry a digest-bound security review |
| Self-improving agent widens its own privileges | Candidates are separate sealed objects; promotion needs digest-bound evaluation, security review and governed approval |
| Stale/misapplied assurance | Attestations/approvals fail validation when `subjectDigest` ≠ current digest |
| Secrets/endpoints in Git | Validators scan the artifact **and every sidecar payload file** for endpoints (URL schemes, `host:port`) and credential patterns; only JSON Schema meta-schema ids under `$schema` are exempt; artifacts carry secret **names** only |
| Raw runtime records (tapes, traces, transcripts) or oversized/odd files smuggled into a version | Strict file allow-list, size limits, no symlinks, LF/UTF-8 only, runtime-record name and content detection ([sealing-and-versioning](sealing-and-versioning.md#file-policy)) |
| Sensitive execution data in Git | Evidence by pointer only; `redactInEvidence` required for confidential/restricted and PII |
| Synthetic content passed off as production | Isolated tree + `synthetic.` namespace; production index/checks reject it |
| Prompt injection via task inputs | Instructions treat inputs as untrusted; irreversible tools require approval; egress limited to declared capabilities |

## Classification

`public < internal < confidential < restricted`. `confidential`/`restricted` require evidence redaction and a digest-bound `security-review` approval to be canonical; `restricted` cannot run with `humanInTheLoop: never`.

## Required repository checks (owner action — NOT configured by this repo)

This repository configures no GitHub settings. Owners who enable branch protection/rulesets should require the check **`validate`** (workflow `validate`, single job). It runs schema + semantic validation of both domains, deterministic index checks, unit tests, and (on PRs) immutability vs the base branch. CODEOWNERS handles in `.github/CODEOWNERS` are **placeholders** until real teams exist. Also recommended: no force-push to `main`, secret scanning and push protection. Vulnerabilities: see [SECURITY.md](../SECURITY.md).

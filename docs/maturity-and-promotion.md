# Maturity and promotion

## Candidates are registry objects

A candidate is a sealed artifact under `<domain>/candidates/<id>/<version>/` with `metadata.maturity: candidate`. It can be evaluated, attested, referenced by evidence and revoked (lifecycle overlay) without any Git branch semantics. Git branches and pull requests are the transport by which a candidate reaches the registry; merging a candidate PR adds a candidate, not a canonical version.

An evolved candidate (`origin.type: evolved`; `discovered`/`refined` may carry one too) must include `origin.evolution`:
`kind`, `rationale`, `proposer`, and `sourceRefs` containing (a) the exact source version + digest it evolved from (lower version, resolved locally) and (b) at least one evidence pointer with role `motivates`.

## Promotion

Promotion moves the sealed object from `candidates/` to `canonical/` and flips `metadata.maturity`. Artifact and seal digests are unchanged, so existing attestations remain valid. `node scripts/promote.mjs <id> <version>` refuses and rolls back unless every gate holds:

1. schema validation and all semantic checks pass;
2. every **required** evaluation suite has an `evaluation` attestation (`suite` set) with an explicit **`result: pass`**, whose `suite` `{id, version, digest}` matches the current suite file, bound to the current `artifactDigest` and `sealDigest`. A `fail` for the current suite blocks promotion outright (even beside a pass); a missing attestation or an `inconclusive` result never satisfies the gate. A later `pass` after `inconclusive` does satisfy it. `result` is required on `evaluation` attestations and rejected on other types;
3. a `security-review` attestation bound to both digests;
4. provenance present (authors, createdAt);
5. a governed `promotion` approval in `security.approvals` bound to both digests (plus a `security-review` approval for `confidential`/`restricted`);
6. canonical references pin exact versions **and** digests;
7. canonical evolved artifacts of non-public agents require `promotionGates.humanApproval`.

Adding attestations/approvals never changes the digest: `node scripts/attest.mjs …` appends them (`--type evaluation` requires `--suite <declared-suite-id> --result pass|fail|inconclusive`; the suite version and digest are derived from the suite file, and the tool refuses if the artifact or payload changed after sealing). Recorded results are history: they cannot be edited or removed (`check-changes`), so a failure can only be superseded by a new version.

## Stale attestations

`subjectDigest` and `sealDigest` must equal the current artifact and seal digests. If content changes and the seal is recomputed while old attestations remain, validation fails with "is stale". Because sealed content cannot change, in practice this catches re-seal attempts and copy-paste of gates between versions.

## Workflow

1. Create the candidate directory; `seal`; open a PR (governance transport).
2. Run evaluations elsewhere; `attest --type evaluation --suite <id> --result <pass|fail|inconclusive> --ref evidence://…`.
3. Security review + governed approval; `attest --approval …`.
4. `promote`; regenerate indexes; PR merges. CI: validate, index check, tests, immutability vs base.

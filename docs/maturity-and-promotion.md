# Maturity and promotion

## Candidates are registry objects

A candidate is a sealed artifact under `<domain>/candidates/<id>/<version>/` with `metadata.maturity: candidate`. It can be evaluated, attested, referenced by evidence and revoked (lifecycle overlay) without any Git branch semantics. Git branches and pull requests are the transport by which a candidate reaches the registry; merging a candidate PR adds a candidate, not a canonical version.

An evolved candidate (`origin.type: evolved`) must include `origin.evolution`:
`kind`, `rationale`, `proposer`, and `sourceRefs` containing (a) the exact source version + digest it evolved from (lower version, resolved locally) and (b) at least one evidence pointer with role `motivates`.

## Promotion

Promotion moves the sealed object from `candidates/` to `canonical/` and flips `metadata.maturity`. The digest is unchanged, so existing attestations remain valid. `node scripts/promote.mjs <id> <version>` refuses and rolls back unless every gate holds:

1. schema validation and all semantic checks pass;
2. every **required** evaluation suite has an `evaluation` attestation (`suite` set) with an explicit **`result: pass`**, bound to the current addressing digest. A `fail` result bound to the digest blocks promotion outright (even beside a pass); a missing attestation, an attestation with no `result` (unspecified), or an `inconclusive` result never satisfies the gate. A later `pass` after `inconclusive`/unspecified does satisfy it. `result` (`pass | fail | inconclusive`) is only valid on `evaluation` attestations;
3. a `security-review` attestation bound to the digest;
4. provenance present (authors, createdAt);
5. a governed `promotion` approval in `security.approvals` bound to the digest (plus a `security-review` approval for `confidential`/`restricted`);
6. canonical references pin exact versions **and** digests;
7. canonical evolved artifacts of non-public agents require `promotionGates.humanApproval`.

Adding attestations/approvals never changes the digest: `node scripts/attest.mjs …` appends them (`--type evaluation` requires `--suite <id> --result pass|fail|inconclusive`). Recorded results are history: they cannot be edited or removed (`check-changes`), so a failure can only be superseded by a new version.

## Stale attestations

`subjectDigest` must equal the artifact's current digest. If content changes and the seal is recomputed while old attestations remain, validation fails with "is stale". Because sealed content cannot change, in practice this catches re-seal attempts and copy-paste of gates between versions.

## Workflow

1. Create the candidate directory; `seal`; open a PR (governance transport).
2. Run evaluations elsewhere; `attest --type evaluation --suite <id> --result <pass|fail|inconclusive> --ref evidence://…`.
3. Security review + governed approval; `attest --approval …`.
4. `promote`; regenerate indexes; PR merges. CI: validate, index check, tests, immutability vs base.

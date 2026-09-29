# Maturity and promotion

## Candidates are registry objects

A candidate is a sealed artifact under `<domain>/candidates/<id>/<version>/` with `metadata.maturity: candidate`. It can be evaluated, attested, referenced by evidence and revoked (lifecycle overlay) without any Git branch semantics. Git branches and pull requests are the transport by which a candidate reaches the registry; merging a candidate PR adds a candidate, not a canonical version.

An evolved candidate (`origin.type: evolved`) must include `origin.evolution`:
`kind`, `rationale`, `proposer`, and `sourceRefs` containing (a) the exact source version + digest it evolved from (lower version, resolved locally) and (b) at least one evidence pointer with role `motivates`.

## Promotion

Promotion moves the sealed object from `candidates/` to `canonical/` and flips `metadata.maturity`. The digest is unchanged, so existing attestations remain valid. `node scripts/promote.mjs <id> <version>` refuses and rolls back unless every gate holds:

1. schema validation and all semantic checks pass;
2. every **required** evaluation suite has an `evaluation` attestation (`suite` set) bound to the digest;
3. a `security-review` attestation bound to the digest;
4. provenance present (authors, createdAt);
5. a governed `promotion` approval in `security.approvals` bound to the digest (plus a `security-review` approval for `confidential`/`restricted`);
6. canonical references pin exact versions **and** digests;
7. canonical evolved artifacts of non-public agents require `promotionGates.humanApproval`.

Adding attestations/approvals never changes the digest: `node scripts/attest.mjs …` appends them.

## Stale attestations

`subjectDigest` must equal the artifact's current digest. If content changes and the seal is recomputed while old attestations remain, validation fails with "is stale". Because sealed content cannot change, in practice this catches re-seal attempts and copy-paste of gates between versions.

## Workflow

1. Create the candidate directory; `seal`; open a PR (governance transport).
2. Run evaluations elsewhere; `attest` with `evidence://` pointers.
3. Security review + governed approval; `attest --approval …`.
4. `promote`; regenerate indexes; PR merges. CI: validate, index check, tests, immutability vs base.

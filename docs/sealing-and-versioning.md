# Sealing and versioning

## Seal

`seal.yaml` is written by `scripts/seal.mjs` and contains:

```yaml
digest: sha256:…          # identity of this published version
artifactDigest: sha256:…  # canonical JSON of artifact.yaml minus excludedFields
excludedFields: [metadata.maturity, attestations, security.approvals]
files: { prompts/system.md: sha256:…, … }   # every payload file (everything except artifact.yaml/seal.yaml)
```

`digest = sha256(canonicalJson({artifact: artifactDigest, files}))`. Canonical JSON sorts keys, so YAML formatting never affects the digest; adding any file changes it, so no unsealed content can hide in a version directory.

**Excluded fields** are the ones that must change after sealing and are themselves bound to the digest: `attestations` and `security.approvals` reference `subjectDigest`, and `metadata.maturity` records the one-way governance move to canonical. Everything else, including `security.classification`, `security.capabilities`, `origin`, `provenance` and all of `spec`, is covered.

## Rules

- A version directory is never edited after sealing. Fix forward with a new version.
- Canonical versions use SemVer; version numbers are unique per identity.
- A candidate's version must exceed **every** canonical version of the same id (candidates of one id must use distinct versions).
- `check-changes` rejects digest changes, deletion, moves out of a domain, reversion to candidate, and non-append-only edits to attestations, approvals and overlays.

## Suggested bump semantics (reviewer-enforced)

| Change | Bump |
|---|---|
| Instruction wording, policy tuning, eval additions | patch |
| Compatible contract extension, new references/tools/models, security/permission expansion | minor |
| Purpose change; removed/newly-required contract fields | major |

The registry does not compute bump adequacy; the digest and ordering rules above are what is mechanically enforced.

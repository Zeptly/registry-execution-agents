# Diagnostics and exit codes

Protocol v0.2 §9. Implemented in `scripts/lib/diag.mjs`.

| Exit | Meaning |
|---:|---|
| `0` | Success |
| `1` | A valid request that cannot be satisfied: promotion gates unmet, candidate/canonical already exists, version already sealed |
| `2` | Malformed input, schema/semantic validation errors, usage errors, internal errors |

Every problem is a `Diag` with a machine-readable `code`, `message`, and, where known, `file`, `path`, `line` and `column`. `validate.mjs --json` prints them as JSON; text output is `<file>: <path> <message>` and never a stack trace. Readers throw a coded `InputError` instead of uncaught exceptions.

## Code catalogue

**Input and parsing:** `utf8-invalid`, `utf8-bom`, `nul-byte`, `lone-surrogate`, `line-ending-cr`, `yaml-invalid`, `yaml-multiple-documents`, `yaml-duplicate-key`, `yaml-unsafe-integer`, `yaml-unsupported-tag`, `yaml-anchor`, `yaml-alias`, `yaml-non-string-key`, `yaml-merge-key`, `yaml-non-finite-number`, `yaml-number-not-json`, `non-finite-number`, `jcs-unsupported-value`

**Files and tree:** `symlink-rejected`, `path-case-collision`, `file-too-large`, `file-limit-exceeded`, `file-extension-not-allowed`, `file-not-allowed`, `path-too-deep`, `runtime-record-detected`, `endpoint-detected`, `credential-detected`, `tree-structure-invalid`, `path-mismatch`, `maturity-tree-mismatch`, `duplicate-version`, `version-not-advancing`, `schema-invalid`

**Seals and attestations:** `seal-missing`, `seal-mismatch`, `seal-subject-mismatch`, `digest-algorithm-unsupported`, `attestation-stale`, `approval-stale`

**Promotion:** `promotion-evaluation-failed`, `promotion-evaluation-not-passing`, `promotion-evaluation-suite-mismatch`, `promotion-evaluation-missing`, `promotion-security-review-missing`, `promotion-approval-missing`

**References and lifecycle:** `reference-not-exact`, `reference-digest-missing`, `reference-unresolved`, `reference-digest-mismatch`, `reference-self`, `lineage-unresolved`, `lineage-digest-mismatch`, `dependency-revoked`, `dependency-deprecated-range`, `dependency-ineligible`, `invalid-range`, `lifecycle-transition-illegal`, `lifecycle-order`, `lifecycle-reason-missing`, `lifecycle-target-missing`, `lifecycle-digest-mismatch`

**Synthetic and immutability:** `synthetic-namespace`, `synthetic-marker`, `synthetic-evidence`, `immutability-violation`, `validation-error`

Codes are stable identifiers; message text may change. Unrecognised messages fall back to `validation-error`.

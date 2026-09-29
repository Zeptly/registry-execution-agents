# Sealing and versioning

## Two digests

`seal.yaml` (written by `scripts/seal.mjs`) records both:

```yaml
digest: sha256:…          # directory seal = the ADDRESSING digest (indexes, references, attestations, approvals, lifecycle events)
artifactDigest: sha256:…  # artifact-content scope only
excludedFields: [metadata.version, metadata.maturity, metadata.lifecycle, attestations, security.approvals]
files: { prompts/system.md: sha256:…, … }   # every allowed payload file, hashed over raw bytes
```

- `artifactDigest = sha256(JCS(artifact minus excludedFields))`
- `digest = sha256(JCS({artifact: artifactDigest, files}))`

The version is not part of either digest: identical content has one digest, and a reference is always `version + digest`.

| Field/category | `artifactDigest` | `digest` (directory seal) | Reason |
|---|---:|---:|---|
| `apiVersion`, `kind`, `metadata.id`, `metadata.registry` | ✓ | ✓ | Identity |
| `metadata.origin` | ✓ | ✓ | How the content came to be (lineage) |
| `spec` | ✓ | ✓ | Durable content |
| `references` | ✓ | ✓ | Dependencies |
| `provenance` | ✓ | ✓ | Content history |
| `security.classification`, `security.capabilities` | ✓ | ✓ | Must not change after sealing |
| Payload files (`prompts/`, `contracts/`, `evals/`) | ✗ | ✓ | Canonical payload, covered by the directory seal |
| `metadata.version` | ✗ | ✗ | Address, not content (directory name and `seal.subject`) |
| `metadata.maturity` | ✗ | ✗ | Governance state; promotion moves the object |
| `metadata.lifecycle` | ✗ | ✗ | Publication marker; the effective state is the overlay |
| Lifecycle overlays | ✗ | ✗ | Separate append-only files |
| `attestations`, `security.approvals` | ✗ | ✗ | They bind to the digest |
| `artifact.yaml` formatting, `seal.yaml` | ✗ | ✗ | Digest is over parsed canonical JSON; seal is circular |

Registry-local interpretation: `metadata.origin` is treated as provenance (included) and `metadata.lifecycle` as a governance marker (excluded).

## Canonical JSON policy

One policy for every digest: **RFC 8785 (JCS)** over the parsed value (`canonicalJson`, `scripts/lib/core.mjs`): keys sorted by UTF-16 code units, no whitespace, ECMAScript number/string serialization, numbers are IEEE-754 doubles. Values JCS cannot represent (`undefined`, functions, NaN/Infinity, lone surrogates, non-plain objects) are **rejected**. Because the digest is over the parsed value, YAML formatting, comments and key order never matter.

Golden vectors (`test/registry.test.mjs`): the RFC 8785 key-ordering and number examples, and a fixed artifact whose `artifactDigest` and `digest` were computed independently (Python) and are pinned in the test.

## Line endings and text

Payload bytes are hashed as-is. Files must therefore be **UTF-8 without BOM, LF-only, no NUL**; the validator rejects CR, BOM, NUL and invalid UTF-8 in every version-directory file. `.gitattributes` forces `eol=lf` so Git checkouts cannot alter bytes.

## File policy

A version directory may contain only:

| Location | Allowed |
|---|---|
| root | `artifact.yaml`, `seal.yaml` |
| `prompts/` | `.md`, `.txt` |
| `contracts/` | `.json`, `.yaml`, `.yml` |
| `evals/` | `.yaml`, `.yml`, `.json` |

Everything else is rejected. Names match `^[A-Za-z0-9][A-Za-z0-9._-]*$` (≤64 chars), nesting ≤3 levels. Limits: ≤64 files, ≤256 KiB per file, ≤1 MiB per version directory. **Symlinks are never followed and are rejected** (in version directories and in the tree structure); special files are rejected; unexpected entries in `canonical/`, `candidates/` and the domain root are rejected. Names or content that indicate tapes, traces or transcripts are rejected ([evidence-model](evidence-model.md#enforcement)). `seal.mjs` refuses to seal a directory that violates the policy. Limits live in `scripts/lib/files.mjs`.

## Rules

- A version directory is never edited after sealing. Fix forward with a new version.
- Canonical versions use SemVer; a version is unique per identity.
- A candidate's version must exceed **every** canonical version of the same id (candidates of one id use distinct versions).
- `check-changes` rejects digest changes, deletion, domain moves, reversion to candidate and non-append-only edits to attestations, approvals and overlays.
- Indexes order entries by code-point `id`, then SemVer, then code-point `digest`, using a locale-independent comparator (`compareCodePoints`), and contain no timestamps or commit ids.

## Suggested bump semantics (reviewer-enforced)

| Change | Bump |
|---|---|
| Instruction wording, policy tuning, eval additions | patch |
| Compatible contract extension, new references/tools/models, security/permission expansion | minor |
| Purpose change; removed/newly-required contract fields | major |

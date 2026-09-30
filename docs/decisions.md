# Deferred decisions

Outside Protocol v0.1/v0.2 and **not decided here**:

1. Evidence Protocol ownership and schema (only opaque `evidence://` pointers are validated).
2. Capability / tool / gateway / model namespace ownership. Platform references use opaque registry labels; only structure is checked.
3. Signing of seals/tags/attestations.
4. Peer-index distribution and cross-registry (network) reference verification.
5. Workspace overrides.
6. Traffic channels (e.g. stable/beta pointers).
7. Nested QB execution.
8. Runtime-trigger contract versioning (`compatibility` carries only `requiredRuntimeFeatures` labels).

## Registry-local choices to confirm (working decisions)

- Candidates of one identity use distinct versions; promotion keeps the version and digest.
- Digest scope: see [sealing-and-versioning](sealing-and-versioning.md). `metadata.origin` is included (provenance) and `metadata.lifecycle` is excluded (governance marker); these two placements are registry-local interpretations.
- Runtime locks are runtime-owned; this registry emits none.
- Attestation `result` (`pass | fail | inconclusive`) on `evaluation` attestations; promotion needs an explicit `pass` per required suite and any `fail` bound to the digest blocks it (registry-local).
- Executable local dependencies: revoked never eligible; deprecated only by exact pin; ranges exclude both; lineage is historical and unrestricted by lifecycle; revoked dependents are exempt (registry-local).
- YAML numbers: integer-valued literals outside ±(2^53−1) are rejected at the source; the strict reader applies to all YAML the registry reads (registry-local).
- Case-insensitive path collisions inside a version directory are rejected (registry-local).
- Id grammar: dotted lowercase segments (`^[a-z][a-z0-9]*(-[a-z0-9]+)*(\.…)*$`); `synthetic.` prefix marks the synthetic namespace.
- Attestation types: `evaluation`, `security-review`, `provenance`; approval types: `security-review`, `promotion`.
- Governance placeholders: team handles in synthetic examples and `.github/CODEOWNERS` are placeholders.
- Bump adequacy is reviewer-enforced, not computed.

## Protocol v0.2 registry-local interpretations (to confirm)

- `seal.yaml` `payload[]` entries are `{path, sha256: "sha256:<hex>"}`; index fields are `artifactDigest` and `sealDigest`; reference/lock digest pins mean the artifact digest.
- `origin.type` `discovered`/`refined` may carry `origin.evolution`; `evolved` requires it; `native`/`upstream-seed` forbid it; `upstream-seed` requires `import`.
- `metadata.lifecycle` must be `active` at publication (excluded from the digest).
- Attestations and approvals carry `sealDigest` in addition to `subjectDigest`, because payload files are outside the artifact digest.
- Evaluation suite digest = sha256 of the suite file bytes; suite version comes from the suite file.
- Synthetic marker is `provenance.synthetic: true` (required in `synthetic/`, forbidden in production).
- YAML numbers must match the JSON number grammar; `digestAlgorithm` is required on overlays and on any reference carrying a digest.
- Exit-code assignment and diagnostic code names: [diagnostics](diagnostics.md).
- No resolver, lock generator or peer-index access; shared vectors are pending (local vectors in `test/vectors/`).

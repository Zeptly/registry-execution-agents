# Deferred decisions

Outside Protocol v0.1 and **not decided here**:

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

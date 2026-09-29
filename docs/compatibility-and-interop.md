# Compatibility & interoperability

## Consumer contract (for `Zeptly/runtime-trigger`)
1. Enumerate agents from the git tags/ledgers (or the generated `dist/registry-index.json`, published as a CI artifact).
2. Resolve `id@version` from tag `exec.<slug>@<version>`; recompute the digest per [versioning](versioning.md) and compare with the ledger. Refuse on mismatch.
3. Only `active` (and `deprecated`, with a warning) are runnable.
4. Check `compatibility.runtime_contract` (min / max_exclusive), `required_runtime_features`, and resolve every `skill.*@v` against `Zeptly/registry-skills` (`skills_registry` gives the accepted registry-schema range).
5. Map logical names: `model.*` → AI Gateway, `cap.*`/`tool.*` → provider gateways (Railway), `secret.*` → secret store. **Unresolvable required names ⇒ do not start the run.**
6. Enforce `permissions`, `timeout_policy`, `retry_policy`, `checkpoint_policy`; record the tape per `observability.evidence`; stamp sessions with `id@version+digest`.
7. Write evidence to Cortex; propose changes only via PRs to this repo.

The reference algorithm for the digest is `definitionDigest` in `scripts/lib/registry.mjs`; runtimes may vendor or port it. Digest format changes require a schema major version.

## Schema evolution
`schema_version` is `"1.0"`. Backward-compatible additions (optional fields) → `1.x`; breaking changes → `2.0` with a migration note and a period where both are accepted. Runtimes must reject unknown `schema_version` majors.

## Registry-skills, Supabase/Cortex, Gateways
Not implemented here and not assumed to exist yet. The interface is *names + versions only*; no service is contacted by any script in this repo. Cross-repo validation (do the referenced `skill.*` versions exist?) is a documented future step, to be added once `registry-skills` publishes an index — see [decisions](decisions.md).

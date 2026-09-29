# Evidence model

**Principle (unchanged):** runtime sessions, tapes and trajectories stay outside Git. Registry artifacts contain only immutable or verifiable evidence **pointers**.

- Pointer form: `evidence://<opaque path>` (schema pattern only). The **Evidence Protocol** (ownership, schema, resolution, authorisation) is a separate platform contract and deferred; this registry never dereferences a pointer.
- Where pointers appear: `attestations[].ref`, `security.approvals[].ref`, `origin.evolution.sourceRefs[]` and `provenance.sourceRefs[]` (evidence entries carry `role`, `summary` and an optional `digest` of the referenced bundle).
- What runs must record is declared per agent in `spec.observability.evidence` (`recordTape`, `tapeIncludes`, `retentionDays`, `samplingRate`) and enforced by the runtime, with `spec.dataHandling.redactInEvidence` honoured.
- Attestations bind to an artifact **digest** and are never valid for any other content.
- Runtimes should stamp sessions with the resolved lock (`id@version + digest`) so trajectories are reproducible against the exact sealed artifact.

Disallowed in this repository: raw tapes, transcripts, customer data, `http(s)` endpoints, credentials.

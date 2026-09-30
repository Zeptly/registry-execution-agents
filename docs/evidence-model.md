# Evidence model

**Principle (unchanged):** runtime sessions, tapes and trajectories stay outside Git. Registry artifacts contain only immutable or verifiable evidence **pointers**.

- Pointer form: `evidence://<opaque path>` (schema pattern only). The **Evidence Protocol** (ownership, schema, resolution, authorisation) is a separate platform contract and deferred; this registry never dereferences a pointer.
- Where pointers appear: `attestations[].ref`, `security.approvals[].ref`, `origin.evolution.sourceRefs[]` and `provenance.sourceRefs[]` (evidence entries carry `role`, `summary` and an optional `digest` of the referenced bundle).
- What runs must record is declared per agent in `spec.observability.evidence` (`recordTape`, `tapeIncludes`, `retentionDays`, `samplingRate`) and enforced by the runtime, with `spec.dataHandling.redactInEvidence` honoured.
- Attestations bind to an artifact **digest** (`subjectDigest`, plus the registry-local `sealDigest` for payload) and are never valid for any other content.
- Runtimes should stamp sessions with the resolved lock (`id@version + digest`) so trajectories are reproducible against the exact sealed artifact.

Disallowed in this repository: raw tapes, transcripts, customer data, endpoints, credentials.

## Enforcement

- **Synthetic evidence restriction.** In the `synthetic/` domain every evidence pointer (attestation `ref`, approval `ref`, `sourceRefs[].evidence`, `origin.evolution.sourceRefs[].evidence`) must start with `evidence://synthetic/`. In the production domain a pointer starting with `evidence://synthetic/` is rejected. Synthetic evidence can therefore never justify a production artifact.
- **Evaluation attestations carry an explicit `result`** (`pass | fail | inconclusive`); only a `pass` for the current suite (id, version, digest) bound to the current digests counts toward promotion. The pointed-to evidence itself is never read.
- **Payload scans.** Every sidecar payload file (`prompts/`, `contracts/`, `evals/`) is scanned for credentials and endpoints (`https?`, `wss?`, `ftp`, `s3`, `gs`, database and broker schemes, `localhost:port`, `ip:port`), with the JSON Schema meta-schema id under `$schema` as the only exemption.
- **Runtime-record detection.** File and directory names matching tape/trace/transcript/trajectory/span/chatlog, JSON Lines/NDJSON, keys such as `trace_id`, `span_id`, `tool_calls`, `tool_call_id`, `transcript`, `trajectory`, `tape`, chat arrays of ≥4 role/content messages, and ≥10 role-prefixed turns in prompt text are rejected. These are heuristics; the file allow-list is the primary control.

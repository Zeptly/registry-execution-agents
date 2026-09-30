# Golden vectors (Protocol v0.2, `digestAlgorithm: zeptly-jcs-v1`)

Language-neutral JSON data consumed by `test/vectors.test.mjs` and reproducible from `generate_vectors.py` (Python, independent of the JavaScript implementation).

| File | Content |
|---|---|
| `parser.json` | Inputs (YAML text or raw bytes as hex) for the JSON-compatible YAML subset: accepted inputs with the parsed value and its canonical JSON; rejected inputs with the machine-readable code |
| `canonicalization.json` | RFC 8785 JCS vectors (UTF-16 key order, ECMAScript numbers, no Unicode normalization) with canonical text, UTF-8 hex and SHA-256; rejection vectors (lone surrogates) |
| `digest.json` | A complete artifact + payload, the expected artifact projection canonical text, artifact digest, payload entries, directory-seal input and seal digest; structured mutation variants (version-only, maturity, lifecycle marker, attestations, approvals, identity, origin, spec, runtime approvals, references, provenance, classification, capabilities, payload mutation/deletion/addition) with the expected digests; CRLF / lone-CR payload rejections |

Status: **registry-local**, authored from the amendment text. The protocol distribution's shared vectors were not available when these were written; an implementation is conformant only when it reproduces every shared vector, so these should be reconciled with (or replaced by) the shared set.
Number vectors with exponents use literal RFC 8785 expectations (Python float formatting differs from ECMAScript) and are verified in CI against the reference implementation (`canonicalize`).

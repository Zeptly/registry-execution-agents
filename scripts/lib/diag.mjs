/**
 * Diagnostics and exit codes (Protocol v0.2 §9).
 *  - exit 0: success
 *  - exit 1: a valid request that cannot be satisfied (e.g. an unresolved reference, a refused promotion, re-sealing a sealed version)
 *  - exit 2: malformed input or validation errors
 * Every reported problem keeps a file, an optional path and a machine-readable code (`--json` output on the CLIs).
 */
export const EXIT = { OK: 0, UNSATISFIED: 1, INVALID: 2 };

export class Diag {
  constructor(code, message, { file, path, line, column } = {}) {
    this.code = code; this.message = message; this.file = file; this.path = path; this.line = line; this.column = column;
  }
  toString() { return this.message; } // keeps string semantics (join, template literals, regex matching)
  toJSON() { return Object.fromEntries(Object.entries({ code: this.code, file: this.file, path: this.path, line: this.line, column: this.column, message: this.message }).filter(([, v]) => v !== undefined)); }
}

/** Thrown by the input readers (text, YAML, canonical JSON). Carries one or more coded problems. */
export class InputError extends Error {
  constructor(problems) {
    const list = Array.isArray(problems) ? problems : [problems];
    super(list.map((p) => p.message).join("; "));
    this.problems = list; this.code = list[0].code;
  }
}

/** Ordered mapping of legacy message text to stable machine-readable codes. First match wins. */
const CODES = [
  [/not valid UTF-8/, "utf8-invalid"], [/UTF-8 BOM not allowed/, "utf8-bom"], [/NUL (byte|character)/, "nul-byte"], [/lone surrogate/, "lone-surrogate"],
  [/CR characters not allowed/, "line-ending-cr"],
  [/invalid YAML|unparseable/, "yaml-invalid"], [/multiple documents/, "yaml-multiple-documents"], [/Map keys must be unique|duplicate key/i, "yaml-duplicate-key"],
  [/outside the safe range/, "yaml-unsafe-integer"],
  [/symlinks are not allowed/, "symlink-rejected"], [/case-insensitive path collision/, "path-case-collision"], [/exceeds the \d+-byte file limit/, "file-too-large"],
  [/files exceeds the limit|total size .* exceeds/, "file-limit-exceeded"], [/extension '.*' not allowed/, "file-extension-not-allowed"],
  [/not allowed at version-directory root|not in allow-list|file\/directory name not allowed|not a regular file/, "file-not-allowed"], [/exceeds maximum depth/, "path-too-deep"],
  [/raw runtime record|looks like a conversation transcript|key only occurs in raw runtime records/, "runtime-record-detected"],
  [/contains an endpoint/, "endpoint-detected"], [/looks like a credential/, "credential-detected"],
  [/only version directories are allowed|only identity directories are allowed|unexpected entry at domain root|must be a real directory/, "tree-structure-invalid"],
  [/missing seal\.yaml/, "seal-missing"], [/seal digest mismatch|seal file list|artifact digest mismatch|seal payload/, "seal-mismatch"], [/seal subject does not match/, "seal-subject-mismatch"],
  [/digestAlgorithm/, "digest-algorithm-unsupported"],
  [/attestations\[\d+\].*is stale/, "attestation-stale"], [/security\.approvals\[\d+\].*is stale/, "approval-stale"],
  [/failing evaluation result/, "promotion-evaluation-failed"], [/no passing evaluation result/, "promotion-evaluation-not-passing"], [/suite identity|suite digest|suite version/, "promotion-evaluation-suite-mismatch"],
  [/lacks a digest-bound 'evaluation'/, "promotion-evaluation-missing"], [/'security-review' attestation/, "promotion-security-review-missing"],
  [/'promotion' approval|'security-review' approval/, "promotion-approval-missing"],
  [/canonical artifact: reference .* must pin an exact version|must pin an exact version/, "reference-not-exact"], [/must carry a digest/, "reference-digest-missing"],
  [/unresolved local reference/, "reference-unresolved"], [/unresolved lineage reference/, "lineage-unresolved"], [/lineage reference .* digest mismatch/, "lineage-digest-mismatch"],
  [/reference .* digest mismatch/, "reference-digest-mismatch"], [/reference to itself/, "reference-self"],
  [/executable dependency .* is revoked|revoked artifacts are never eligible/, "dependency-revoked"], [/executable dependency .* is deprecated/, "dependency-deprecated-range"],
  [/no eligible version satisfies/, "dependency-ineligible"], [/invalid range/, "invalid-range"],
  [/illegal lifecycle transition/, "lifecycle-transition-illegal"], [/chronological order/, "lifecycle-order"], [/requires a reason/, "lifecycle-reason-missing"],
  [/no artifact .*@/, "lifecycle-target-missing"], [/digest does not match/, "lifecycle-digest-mismatch"],
  [/synthetic-domain ids must start|synthetic artifacts cannot exist|cannot reference synthetic/, "synthetic-namespace"], [/synthetic marker|provenance\.synthetic/, "synthetic-marker"],
  [/synthetic artifacts may only use|cannot cite synthetic evidence/, "synthetic-evidence"],
  [/must equal metadata\.id\/version/, "path-mismatch"], [/does not match tree/, "maturity-tree-mismatch"], [/must exceed every canonical version/, "version-not-advancing"],
  [/exists in more than one tree/, "duplicate-version"],
  [/removed or moved|content digest changed|seal digest changed|cannot revert to candidate|was modified or removed|was modified, removed or reordered|origin changed|removed; overlays are append-only/, "immutability-violation"],
  [/artifact\.yaml: \//, "schema-invalid"], [/seal\.yaml: \//, "schema-invalid"],
];
export const codeFor = (message) => (CODES.find(([re]) => re.test(message)) ?? [null, "validation-error"])[1];

/** Convert a legacy string message to a Diag, extracting the file/path labels when the message carries them. */
export function toDiag(message, { file: defaultFile } = {}) {
  if (message instanceof Diag) return message;
  const m = /^([A-Za-z0-9_.\/-]+\.(?:ya?ml|json|md|txt)):\s*(\/[^\s]*)?/.exec(message);
  return new Diag(codeFor(message), message, { file: m ? m[1] : defaultFile, path: m?.[2] });
}

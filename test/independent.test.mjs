// Maintained regression coverage ported from the audit evidence package.
// The digest is recomputed here WITHOUT importing the registry's canonicalizer, seal, or file-walk code: the canonical JSON comes
// from the third-party RFC 8785 reference implementation (`canonicalize`, devDependency), hashing/file enumeration are local
// to this file. (The YAML parser is shared with production, so parsing is not independently verified.)
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cpSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse, stringify } from "yaml";
import canonicalize from "canonicalize";
import { makeValidators, loadDomain, canonicalJson } from "../scripts/lib/core.mjs";
import { validateDomain } from "../scripts/lib/rules.mjs";
import { checkDomainChange } from "../scripts/lib/changes.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SYN = join(ROOT, "synthetic");
const v = makeValidators();
const EXCLUDED = ["metadata.version", "metadata.maturity", "metadata.lifecycle", "attestations", "security.approvals"];
const H = (b) => "sha256:" + createHash("sha256").update(b).digest("hex");
const rd = (p) => parse(readFileSync(p, "utf8"));
const wr = (p, o) => writeFileSync(p, stringify(o));
const tmp = () => mkdtempSync(join(tmpdir(), "indep-"));
const copySyn = () => { const d = join(tmp(), "synthetic"); cpSync(SYN, d, { recursive: true }); return d; };
const errs = (root) => validateDomain(loadDomain(root), "synthetic", v).flatMap((r) => r.errors).join("\n");

function walkFiles(dir, rel = "") {
  return readdirSync(join(dir, rel), { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walkFiles(dir, `${rel}${e.name}/`) : [`${rel}${e.name}`]));
}
/** Independent recomputation of { artifactDigest, digest, files } for one version directory. */
function independentSeal(dir) {
  const a = rd(join(dir, "artifact.yaml"));
  for (const path of EXCLUDED) { const k = path.split("."); let c = a; for (const p of k.slice(0, -1)) c = c?.[p]; if (c) delete c[k.at(-1)]; }
  const artifactDigest = H(Buffer.from(canonicalize(a), "utf8"));
  const files = Object.fromEntries(walkFiles(dir).filter((f) => f !== "artifact.yaml" && f !== "seal.yaml").sort().map((f) => [f, H(readFileSync(join(dir, f)))]));
  return { artifactDigest, digest: H(Buffer.from(canonicalize({ artifact: artifactDigest, files }), "utf8")), files };
}
const objects = (root) => ["canonical", "candidates"].flatMap((t) => readdirSync(join(root, t)).filter((n) => !n.startsWith(".")).flatMap((id) => readdirSync(join(root, t, id)).map((ver) => join(root, t, id, ver))));

test("populated fixtures: every committed seal matches the independent recomputation (artifact digest, file hashes, directory seal)", () => {
  const all = objects(SYN);
  assert.equal(all.length, 4);
  for (const dir of all) {
    const seal = rd(join(dir, "seal.yaml")), ind = independentSeal(dir);
    assert.equal(ind.artifactDigest, seal.artifactDigest, `${dir} artifactDigest`);
    assert.deepEqual(ind.files, seal.files, `${dir} files`);
    assert.equal(ind.digest, seal.digest, `${dir} digest`);
  }
});

test("golden vectors agree with the third-party RFC 8785 implementation (RFC samples, edge cases, every shipped artifact body)", () => {
  const cases = [
    { "€": "Euro Sign", "\r": "Carriage Return", "דּ": "Hebrew Letter Dalet With Dagesh", 1: "One", "😀": "Emoji: Grinning Face", "\u0080": "Control", "ö": "Latin Small Letter O With Diaeresis" },
    [333333333.33333329, 1e30, 4.5, 2e-3, 1e-27],
    [0, -0, 1, 1.5, 100, 1e21, 1e-7, 0.1, 5e-324],
    ["\u0001\u001f", "\"\\/", "  \u007f", "😀", "café", "é"],
    { b: [true, null, { z: 1, a: [] }], a: {} },
  ];
  for (const c of cases) assert.equal(canonicalJson(c), canonicalize(c));
  for (const dir of objects(SYN)) { const a = rd(join(dir, "artifact.yaml")); for (const p of EXCLUDED) { const k = p.split("."); let x = a; for (const q of k.slice(0, -1)) x = x?.[q]; if (x) delete x[k.at(-1)]; } assert.equal(canonicalJson(a), canonicalize(a), dir); }
  assert.throws(() => canonicalize({ a: "\ud800" })); assert.throws(() => canonicalJson({ a: "\ud800" }));
});

const TRIAGE = "canonical/synthetic.support-ticket-triage/1.0.0";
test("modification: changing a payload or digest-scoped field changes the independent digest and fails validation", () => {
  const root = copySyn(), dir = join(root, TRIAGE), sealed = rd(join(dir, "seal.yaml"));
  assert.equal(errs(root), "");
  writeFileSync(join(dir, "prompts/system.md"), readFileSync(join(dir, "prompts/system.md"), "utf8") + "tampered\n");
  const ind = independentSeal(dir);
  assert.notEqual(ind.digest, sealed.digest); assert.equal(ind.artifactDigest, sealed.artifactDigest); // payload: directory seal only
  assert.match(errs(root), /seal digest mismatch/); assert.match(errs(root), /seal file list\/hashes differ/);
  const root2 = copySyn(), dir2 = join(root2, TRIAGE), a = rd(join(dir2, "artifact.yaml"));
  a.spec.description = "A description that was changed after sealing.";
  wr(join(dir2, "artifact.yaml"), a);
  const ind2 = independentSeal(dir2);
  assert.notEqual(ind2.artifactDigest, sealed.artifactDigest); assert.notEqual(ind2.digest, sealed.digest);
  assert.match(errs(root2), /seal digest mismatch/);
});

test("modification: changing excluded fields leaves the independent digest unchanged", () => {
  const root = copySyn(), dir = join(root, TRIAGE), sealed = rd(join(dir, "seal.yaml"));
  const a = rd(join(dir, "artifact.yaml"));
  a.attestations.push({ type: "provenance", ref: "evidence://synthetic/p/1", subjectDigest: sealed.digest });
  a.security.approvals.push({ type: "security-review", approver: "team:x", approvedAt: "2026-02-01T00:00:00Z", subjectDigest: sealed.digest });
  wr(join(dir, "artifact.yaml"), a);
  assert.equal(independentSeal(dir).digest, sealed.digest);
  assert.equal(errs(root), "");
});

test("deletion: removing a payload file, the seal, or a whole object is detected", () => {
  const root = copySyn(), dir = join(root, TRIAGE), sealed = rd(join(dir, "seal.yaml"));
  rmSync(join(dir, "evals/golden-triage.yaml"));
  const ind = independentSeal(dir);
  assert.ok(!("evals/golden-triage.yaml" in ind.files)); assert.notEqual(ind.digest, sealed.digest);
  const out = errs(root); assert.match(out, /referenced file missing: evals\/golden-triage\.yaml/); assert.match(out, /seal file list\/hashes differ/);
  const r2 = copySyn(); rmSync(join(r2, TRIAGE, "seal.yaml")); assert.match(errs(r2), /missing seal\.yaml/);
  const base = SYN, head = copySyn(); rmSync(join(head, "canonical/synthetic.support-ticket-triage"), { recursive: true });
  assert.match(checkDomainChange(loadDomain(base), loadDomain(head)).join("\n"), /synthetic\.support-ticket-triage@1\.0\.0: removed or moved/);
});

test("populated-baseline immutability: editing or removing recorded evaluation history is rejected; appending is allowed", () => {
  const base = SYN, X = "candidates/synthetic.contract-clause-extractor/0.1.0";
  const change = (head) => checkDomainChange(loadDomain(base), loadDomain(head)).join("\n");
  // flipping a recorded failing result to pass rewrites history
  const flip = copySyn(); const a = rd(join(flip, X, "artifact.yaml")); a.attestations.find((x) => x.result === "fail").result = "pass"; wr(join(flip, X, "artifact.yaml"), a);
  assert.match(change(flip), /attestations\[\d\] was modified or removed/);
  // removing the failing result
  const rm = copySyn(); const b = rd(join(rm, X, "artifact.yaml")); b.attestations = b.attestations.filter((x) => x.result !== "fail"); wr(join(rm, X, "artifact.yaml"), b);
  assert.match(change(rm), /attestations\[\d\] was modified or removed/);
  // appending a later pass is allowed by immutability, but the gate still refuses promotion while a failure is recorded
  const app = copySyn(); const c = rd(join(app, X, "artifact.yaml")); const digest = rd(join(app, X, "seal.yaml")).digest;
  c.attestations.push({ type: "evaluation", suite: "golden-clauses", result: "pass", ref: "evidence://synthetic/evaluation/x/run-3", subjectDigest: digest }); wr(join(app, X, "artifact.yaml"), c);
  assert.equal(change(app), "");
  assert.equal(errs(app), ""); // candidates are not gated...
  const promoted = join(app, "canonical/synthetic.contract-clause-extractor"); mkdirSync(promoted, { recursive: true });
  cpSync(join(app, X), join(promoted, "0.1.0"), { recursive: true }); rmSync(join(app, "candidates/synthetic.contract-clause-extractor"), { recursive: true });
  const d = rd(join(promoted, "0.1.0/artifact.yaml")); d.metadata.maturity = "canonical"; wr(join(promoted, "0.1.0/artifact.yaml"), d);
  assert.match(errs(app), /failing evaluation result bound to this digest; a failed result blocks promotion/); // ...but promotion is
});

test("populated-baseline immutability: committed fixtures are preserved exactly against themselves", () => {
  assert.equal(checkDomainChange(loadDomain(SYN), loadDomain(SYN)).join("\n"), "");
});

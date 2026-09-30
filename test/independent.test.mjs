// Maintained independent verification of the FINAL seals (Protocol v0.2). Digests are recomputed here WITHOUT importing the registry's
// digest, JCS wrapper, file-walk, parser or index code: a test-only JCS serializer, a local file walk, Node's crypto, and the `yaml`
// package's plain parser. The RFC 8785 reference implementation (`canonicalize`) is used as a third check of the serializer.
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cpSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync, renameSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse, stringify } from "yaml";
import canonicalize from "canonicalize";
import { makeValidators, loadDomain } from "../scripts/lib/core.mjs";
import { canonicalJson } from "../scripts/lib/jcs.mjs";
import { validateDomain } from "../scripts/lib/rules.mjs";
import { checkDomainChange } from "../scripts/lib/changes.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SYN = join(ROOT, "synthetic");
const v = makeValidators();
const H = (b) => "sha256:" + createHash("sha256").update(b).digest("hex");
const rd = (p) => parse(readFileSync(p, "utf8"));
const wr = (p, o) => writeFileSync(p, stringify(o));
const tmp = () => mkdtempSync(join(tmpdir(), "indep-"));
const copySyn = () => { const d = join(tmp(), "synthetic"); cpSync(SYN, d, { recursive: true }); return d; };
const errs = (root) => validateDomain(loadDomain(root), "synthetic", v).flatMap((r) => r.errors).join("\n");
const change = (base, head) => checkDomainChange(loadDomain(base), loadDomain(head)).join("\n");

/** Test-only RFC 8785 serializer: keys sorted by UTF-16 code units (default sort), ES number/string serialization. */
function jcs(x) {
  if (x === null) return "null";
  if (typeof x === "boolean") return x ? "true" : "false";
  if (typeof x === "number") { assert.ok(Number.isFinite(x)); return JSON.stringify(x); }
  if (typeof x === "string") return JSON.stringify(x);
  if (Array.isArray(x)) return "[" + x.map(jcs).join(",") + "]";
  return "{" + Object.keys(x).sort().map((k) => JSON.stringify(k) + ":" + jcs(x[k])).join(",") + "}";
}
const walkFiles = (dir, rel = "") => readdirSync(join(dir, rel), { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walkFiles(dir, `${rel}${e.name}/`) : [`${rel}${e.name}`]));

/** Independent computation of { artifactDigest, sealDigest, payload } per the v0.2 amendment text. */
function independentSeal(dir) {
  const a = rd(join(dir, "artifact.yaml"));
  const projection = {
    apiVersion: a.apiVersion, kind: a.kind, metadata: { id: a.metadata.id, registry: a.metadata.registry, origin: a.metadata.origin },
    spec: a.spec, references: a.references, provenance: a.provenance, security: { classification: a.security.classification, capabilities: a.security.capabilities },
  };
  const artifactDigest = H(Buffer.from(jcs(projection), "utf8"));
  assert.equal(jcs(projection), canonicalize(projection)); // the reference implementation agrees on the exact bytes
  const payload = walkFiles(dir).filter((f) => f !== "artifact.yaml" && f !== "seal.yaml").sort().map((path) => ({ path, sha256: H(readFileSync(join(dir, path))) }));
  const sealDigest = H(Buffer.from(jcs({ registry: a.metadata.registry, id: a.metadata.id, version: a.metadata.version, payload }), "utf8"));
  return { artifactDigest, sealDigest, payload };
}
const objects = (root) => ["canonical", "candidates"].flatMap((t) => readdirSync(join(root, t)).filter((n) => !n.startsWith(".")).flatMap((id) => readdirSync(join(root, t, id)).map((ver) => join(root, t, id, ver))));
const TRIAGE = "canonical/synthetic.support-ticket-triage/1.0.0";
const EXTRACTOR = "candidates/synthetic.contract-clause-extractor/0.1.0";

test("every committed seal matches the independent recomputation (artifact digest, payload entries, directory seal, algorithm id)", () => {
  const all = objects(SYN);
  assert.equal(all.length, 4);
  for (const dir of all) {
    const seal = rd(join(dir, "seal.yaml")), ind = independentSeal(dir);
    assert.equal(seal.digestAlgorithm, "zeptly-jcs-v1", dir);
    assert.equal(ind.artifactDigest, seal.artifactDigest, `${dir} artifactDigest`);
    assert.deepEqual(ind.payload, seal.payload, `${dir} payload`);
    assert.equal(ind.sealDigest, seal.sealDigest, `${dir} sealDigest`);
  }
});

test("committed indexes carry the independently recomputed digests, algorithm and domain", () => {
  const idx = JSON.parse(readFileSync(join(SYN, "index.json"), "utf8"));
  assert.equal(idx.digestAlgorithm, "zeptly-jcs-v1"); assert.equal(idx.domain, "synthetic"); assert.equal(idx.registry, "execution-agents");
  for (const e of idx.entries) {
    const ind = independentSeal(join(ROOT, e.location));
    assert.deepEqual([e.artifactDigest, e.sealDigest, e.digestAlgorithm, e.registry], [ind.artifactDigest, ind.sealDigest, "zeptly-jcs-v1", "execution-agents"]);
  }
});

test("the three JCS implementations (test-only, production wrapper, reference) agree on fixture projections and RFC samples", () => {
  const samples = [{ "€": 1, "\r": 2, "דּ": 3, 1: 4, "😀": 5, "\u0080": 6, "ö": 7 }, [333333333.33333329, 1e30, 4.5, 2e-3, 1e-27], ["é", "é", " "]];
  for (const s of samples) { assert.equal(jcs(s), canonicalize(s)); assert.equal(jcs(s), canonicalJson(s)); }
  for (const dir of objects(SYN)) { const a = rd(join(dir, "artifact.yaml")); assert.equal(jcs(a.spec), canonicalJson(a.spec)); }
});

test("modification: payload change moves only the directory seal and stales seal-bound records; spec change moves both", () => {
  const root = copySyn(), dir = join(root, TRIAGE), sealed = rd(join(dir, "seal.yaml"));
  assert.equal(errs(root), "");
  writeFileSync(join(dir, "prompts/system.md"), readFileSync(join(dir, "prompts/system.md"), "utf8") + "tampered\n");
  const ind = independentSeal(dir);
  assert.equal(ind.artifactDigest, sealed.artifactDigest); assert.notEqual(ind.sealDigest, sealed.sealDigest);
  const out = errs(root);
  assert.match(out, /seal digest mismatch/); assert.match(out, /seal payload list\/hashes differ/); assert.match(out, /attestations\[\d\] \(\w[\w-]*\) is stale: sealDigest/);
  const root2 = copySyn(), dir2 = join(root2, TRIAGE), a = rd(join(dir2, "artifact.yaml"));
  a.spec.description = "A description that was changed after sealing.";
  wr(join(dir2, "artifact.yaml"), a);
  const ind2 = independentSeal(dir2);
  assert.notEqual(ind2.artifactDigest, sealed.artifactDigest);
  assert.match(errs(root2), /artifact digest mismatch/); assert.match(errs(root2), /is stale: subjectDigest/);
});

test("excluded fields: version text, maturity, lifecycle marker, appended attestations and approvals leave the independent artifact digest unchanged", () => {
  const dir = join(copySyn(), TRIAGE), sealed = rd(join(dir, "seal.yaml"));
  const a = rd(join(dir, "artifact.yaml"));
  a.metadata.maturity = "candidate"; a.metadata.lifecycle = "active";
  a.attestations.push({ type: "provenance", ref: "evidence://synthetic/p/1", subjectDigest: sealed.artifactDigest, sealDigest: sealed.sealDigest });
  a.security.approvals.push({ type: "security-review", approver: "team:x", approvedAt: "2026-02-01T00:00:00Z", subjectDigest: sealed.artifactDigest, sealDigest: sealed.sealDigest });
  wr(join(dir, "artifact.yaml"), a);
  assert.equal(independentSeal(dir).artifactDigest, sealed.artifactDigest);
  const b = rd(join(dir, "artifact.yaml")); b.metadata.version = "9.9.9"; wr(join(dir, "artifact.yaml"), b);
  const v9 = independentSeal(dir);
  assert.equal(v9.artifactDigest, sealed.artifactDigest); assert.notEqual(v9.sealDigest, sealed.sealDigest); // the version is in the seal, not the artifact digest
});

test("deletion: a removed payload file, seal or whole object is detected", () => {
  const root = copySyn(), dir = join(root, TRIAGE), sealed = rd(join(dir, "seal.yaml"));
  rmSync(join(dir, "evals/golden-triage.yaml"));
  const ind = independentSeal(dir);
  assert.ok(!ind.payload.some((p) => p.path === "evals/golden-triage.yaml")); assert.notEqual(ind.sealDigest, sealed.sealDigest);
  const out = errs(root); assert.match(out, /referenced file missing: evals\/golden-triage\.yaml/); assert.match(out, /seal payload list\/hashes differ/);
  const r2 = copySyn(); rmSync(join(r2, TRIAGE, "seal.yaml")); assert.match(errs(r2), /missing seal\.yaml/);
  const head = copySyn(); rmSync(join(head, "canonical/synthetic.support-ticket-triage"), { recursive: true });
  assert.match(change(SYN, head), /synthetic\.support-ticket-triage@1\.0\.0: removed or moved/);
});

test("populated baseline: payload changes, version-only moves and deletions are immutability violations", () => {
  const base = SYN;
  const head = copySyn(); writeFileSync(join(head, TRIAGE, "prompts/system.md"), "changed\n");
  wr(join(head, TRIAGE, "seal.yaml"), (() => { const s = rd(join(head, TRIAGE, "seal.yaml")); const i = independentSeal(join(head, TRIAGE)); return { ...s, sealDigest: i.sealDigest, payload: i.payload }; })());
  assert.match(change(base, head), /content digest changed \(payload\/seal/);
  // editing only the version field in place: the identity key changes, so the published object is reported as removed/moved
  const moved = copySyn(); const a = rd(join(moved, TRIAGE, "artifact.yaml")); a.metadata.version = "1.0.7"; wr(join(moved, TRIAGE, "artifact.yaml"), a);
  assert.match(change(base, moved), /synthetic\.support-ticket-triage@1\.0\.0: removed or moved/);
  assert.match(errs(moved), /must equal metadata\.id\/version/);
});

test("populated baseline: a version-only copy keeps the artifact digest but has a different seal, so copied evaluation evidence does not carry over", () => {
  const root = copySyn(), src = join(root, TRIAGE), dst = join(root, "canonical/synthetic.support-ticket-triage/1.0.1");
  cpSync(src, dst, { recursive: true });
  const a = rd(join(dst, "artifact.yaml")); a.metadata.version = "1.0.1"; wr(join(dst, "artifact.yaml"), a);
  const ind = independentSeal(dst), old = rd(join(src, "seal.yaml"));
  assert.equal(ind.artifactDigest, old.artifactDigest); assert.notEqual(ind.sealDigest, old.sealDigest);
  wr(join(dst, "seal.yaml"), { ...old, subject: { ...old.subject, version: "1.0.1" }, artifactDigest: ind.artifactDigest, sealDigest: ind.sealDigest, payload: ind.payload });
  // the evaluation/review/approval records were issued for the 1.0.0 seal and are stale for 1.0.1
  const out = errs(root);
  assert.match(out, /attestations\[\d\] \(evaluation\) is stale: sealDigest/); assert.match(out, /security\.approvals\[0\] \(promotion\) is stale: sealDigest/);
  assert.equal(change(SYN, root), ""); // adding a new version is not an immutability violation
});

test("populated baseline: lifecycle overlays are append-only and bound to the artifact digest", () => {
  const base = copySyn(); const id = "synthetic.support-ticket-triage";
  const ad = rd(join(base, TRIAGE, "seal.yaml")).artifactDigest;
  const overlay = (events) => ({ apiVersion: "registry.zeptly.dev/v1alpha1", kind: "LifecycleOverlay", digestAlgorithm: "zeptly-jcs-v1", subject: { registry: "execution-agents", id }, events });
  const ev = (state, at, reason) => ({ version: "1.0.0", digest: ad, state, at, actor: "team:x", ...(reason ? { reason } : {}) });
  mkdirSync(join(base, "lifecycle"), { recursive: true });
  wr(join(base, "lifecycle", `${id}.yaml`), overlay([ev("deprecated", "2026-02-01T00:00:00Z", "superseded")]));
  assert.equal(errs(base), "");
  const head = (events) => { const h = join(tmp(), "synthetic"); cpSync(base, h, { recursive: true }); if (events) wr(join(h, "lifecycle", `${id}.yaml`), overlay(events)); else rmSync(join(h, "lifecycle", `${id}.yaml`)); return h; };
  assert.equal(change(base, head([ev("deprecated", "2026-02-01T00:00:00Z", "superseded"), ev("revoked", "2026-03-01T00:00:00Z", "unsafe")])), ""); // append ok
  assert.match(change(base, head([ev("deprecated", "2026-02-01T00:00:00Z", "rewritten reason")])), /event 0 was modified/);
  assert.match(change(base, head(null)), /removed; overlays are append-only/);
  assert.match(change(base, head([ev("revoked", "2026-01-01T00:00:00Z", "reordered")])), /event 0 was modified/);
  // an overlay bound to a stale digest is rejected
  const bad = head([{ ...ev("deprecated", "2026-02-01T00:00:00Z", "x1y"), digest: "sha256:" + "0".repeat(64) }]);
  assert.match(errs(bad), /digest does not match/);
});

test("populated baseline: attestations and approvals are append-only; recorded failures cannot be rewritten", () => {
  const change2 = (head) => change(SYN, head);
  const flip = copySyn(); const a = rd(join(flip, EXTRACTOR, "artifact.yaml")); a.attestations.find((x) => x.result === "fail").result = "pass"; wr(join(flip, EXTRACTOR, "artifact.yaml"), a);
  assert.match(change2(flip), /attestations\[\d\] was modified or removed/);
  const rm = copySyn(); const b = rd(join(rm, EXTRACTOR, "artifact.yaml")); b.attestations = b.attestations.filter((x) => x.result !== "fail"); wr(join(rm, EXTRACTOR, "artifact.yaml"), b);
  assert.match(change2(rm), /attestations\[\d\] was modified or removed/);
  const ap = copySyn(); const c = rd(join(ap, TRIAGE, "artifact.yaml")); c.security.approvals = []; wr(join(ap, TRIAGE, "artifact.yaml"), c);
  assert.match(change2(ap), /security\.approvals\[0\] was modified or removed/);
  const app = copySyn(); const d = rd(join(app, TRIAGE, "artifact.yaml")); const s = rd(join(app, TRIAGE, "seal.yaml"));
  d.attestations.push({ type: "provenance", ref: "evidence://synthetic/p/2", subjectDigest: s.artifactDigest, sealDigest: s.sealDigest });
  d.security.approvals.push({ type: "security-review", approver: "team:y", approvedAt: "2026-02-01T00:00:00Z", subjectDigest: s.artifactDigest, sealDigest: s.sealDigest });
  wr(join(app, TRIAGE, "artifact.yaml"), d);
  assert.equal(change2(app), ""); assert.equal(errs(app), ""); // appends are allowed
});

test("populated baseline: the committed fixtures are preserved exactly against themselves", () => {
  assert.equal(change(SYN, SYN), "");
});

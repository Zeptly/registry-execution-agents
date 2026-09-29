import test from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, renameSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { stringify, parse } from "yaml";
import { REPO_ROOT, makeValidators, loadDomain, computeSeal, canonicalJson, compareCodePoints, DOMAINS } from "../scripts/lib/core.mjs";
import { scanVersionDir, LIMITS } from "../scripts/lib/files.mjs";
import { validateDomain } from "../scripts/lib/rules.mjs";
import { checkDomainChange } from "../scripts/lib/changes.mjs";
import { buildIndex } from "../scripts/lib/index.mjs";
import { compare, satisfies } from "../scripts/lib/semver.mjs";

const v = makeValidators();
const SYN = join(REPO_ROOT, "synthetic");
const TRIAGE = join(SYN, "canonical/synthetic.support-ticket-triage/1.0.0");
const CAND = join(SYN, "candidates/synthetic.support-ticket-triage/1.0.1");
const PID = "support.ticket-triage";

const rd = (p) => parse(readFileSync(p, "utf8"));
const wr = (p, o) => writeFileSync(p, stringify(o));
const tmp = () => mkdtempSync(join(tmpdir(), "reg-test-"));
const run = (root, name = "production") => validateDomain(loadDomain(root), name, v);
const errsOf = (root, name) => run(root, name).flatMap((r) => r.errors).join("\n");
const edit = (dir, fn) => { const a = rd(join(dir, "artifact.yaml")); fn(a); wr(join(dir, "artifact.yaml"), a); };

/** Re-seal a directory and (optionally) re-issue every gate bound to the new digest. */
function seal(dir, { gates = true } = {}) {
  const a = rd(join(dir, "artifact.yaml"));
  a.attestations = []; a.security.approvals = [];
  wr(join(dir, "artifact.yaml"), a);
  const s = computeSeal(a, dir);
  wr(join(dir, "seal.yaml"), s);
  if (gates) {
    a.attestations = [
      ...a.spec.evaluation.suites.filter((x) => x.required).map((x) => ({ type: "evaluation", suite: x.id, ref: "evidence://t/eval", subjectDigest: s.digest })),
      { type: "security-review", ref: "evidence://t/sec", subjectDigest: s.digest },
    ];
    a.security.approvals = [{ type: "promotion", approver: "team:x", approvedAt: "2026-01-01T00:00:00Z", subjectDigest: s.digest }];
    wr(join(dir, "artifact.yaml"), a);
  }
  return s.digest;
}

/** A production-domain canonical artifact derived from the synthetic example, properly sealed and gated. */
function prodDomain(mutate) {
  const root = join(tmp(), "registry");
  const dir = join(root, "canonical", PID, "1.0.0");
  mkdirSync(join(root, "candidates"), { recursive: true }); mkdirSync(join(root, "lifecycle"), { recursive: true });
  cpSync(TRIAGE, dir, { recursive: true });
  const a = rd(join(dir, "artifact.yaml"));
  a.metadata.id = PID;
  mutate?.(a, dir);
  wr(join(dir, "artifact.yaml"), a);
  const digest = seal(dir);
  return { root, dir, digest };
}
const baseline = () => prodDomain();

test("shipped domains validate", () => {
  for (const [name, d] of Object.entries(DOMAINS)) {
    const bad = run(join(REPO_ROOT, d), name).filter((r) => r.errors.length);
    assert.deepEqual(bad, [], name);
  }
});

test("production domain holds no synthetic content; committed indexes are current and deterministic", () => {
  for (const [name, d] of Object.entries(DOMAINS)) {
    const root = join(REPO_ROOT, d);
    const idx = buildIndex(loadDomain(root), name);
    assert.ok(v.index(idx));
    assert.equal(JSON.stringify(idx), JSON.stringify(buildIndex(loadDomain(root), name)));
    assert.equal(readFileSync(join(root, "index.json"), "utf8"), JSON.stringify(idx, null, 2) + "\n", `${d}/index.json is stale`);
    if (name === "production") assert.ok(!idx.entries.some((e) => e.id.startsWith("synthetic.")));
  }
});

test("index carries identity, version, digest, maturity, lifecycle, origin and location", () => {
  const e = buildIndex(loadDomain(SYN), "synthetic").entries.find((x) => x.id === "synthetic.support-ticket-triage" && x.version === "1.0.1");
  assert.equal(e.maturity, "candidate"); assert.equal(e.lifecycle, "active");
  assert.deepEqual(e.origin, { type: "evolved", evolutionKind: "refined" });
  assert.match(e.digest, /^sha256:[0-9a-f]{64}$/); assert.match(e.location, /^synthetic\/candidates\//);
});

test("a properly sealed and gated production artifact is accepted", () => {
  assert.equal(errsOf(baseline().root), "");
});

test("maturity, lifecycle and origin are independent fields", () => {
  const a = rd(join(CAND, "artifact.yaml"));
  assert.deepEqual([a.metadata.maturity, a.metadata.lifecycle, a.metadata.origin.type], ["candidate", "active", "evolved"]);
  assert.equal(rd(join(TRIAGE, "artifact.yaml")).metadata.origin.type, "native");
});

test("editing content after sealing is rejected (immutability)", () => {
  const { root, dir } = baseline();
  writeFileSync(join(dir, "prompts/system.md"), readFileSync(join(dir, "prompts/system.md"), "utf8") + "\nextra\n");
  assert.match(errsOf(root), /seal digest mismatch/);
});

test("stale attestations and approvals fail validation", () => {
  const { root, dir } = baseline();
  edit(dir, (a) => { a.spec.description = "A changed description that alters the digest."; });
  wr(join(dir, "seal.yaml"), computeSeal(rd(join(dir, "artifact.yaml")), dir)); // re-seal but keep old attestations
  const out = errsOf(root);
  assert.match(out, /attestations\[0\].*is stale/);
  assert.match(out, /security\.approvals\[0\].*is stale/);
});

test("canonical promotion gates: evaluation, security review, promotion approval", () => {
  const { root, dir } = baseline();
  edit(dir, (a) => { a.attestations = []; a.security.approvals = []; });
  const out = errsOf(root);
  assert.match(out, /'evaluation' attestation for required suite/);
  assert.match(out, /'security-review' attestation/);
  assert.match(out, /'promotion' approval/);
});

test("restricted classification needs a digest-bound security-review approval", () => {
  const { root } = prodDomain((a) => { a.security.classification = "restricted"; a.spec.executionPolicy.humanInTheLoop = "on_demand"; });
  assert.match(errsOf(root), /requires a digest-bound 'security-review' approval/);
});

test("synthetic content cannot enter the production domain", () => {
  const { root } = prodDomain((a) => { a.metadata.id = "synthetic.support-ticket-triage"; });
  assert.match(errsOf(root), /synthetic artifacts cannot exist in the production domain/);
  const b = prodDomain((a) => { a.references.push({ registry: "skills", id: "synthetic.thing", version: "1.0.0", digest: "sha256:" + "a".repeat(64) }); });
  assert.match(errsOf(b.root), /cannot reference synthetic/);
});

test("synthetic domain requires the synthetic namespace", () => {
  const root = join(tmp(), "synthetic");
  cpSync(SYN, root, { recursive: true });
  edit(join(root, "canonical/synthetic.support-ticket-triage/1.0.0"), (a) => { a.metadata.id = "support.ticket-triage"; });
  assert.match(errsOf(root, "synthetic"), /must start with 'synthetic\.'/);
});

test("references must be structured; canonical references are exact and digest-bound", () => {
  const { root, dir } = baseline();
  edit(dir, (a) => { a.references = ["skill.ticket-classification@1.2.0"]; });
  assert.match(errsOf(root), /artifact\.yaml: \/references\/0/);
  const b = prodDomain((a) => { a.references[0].version = "^1.2.0"; a.references[1].digest = null; });
  const out = errsOf(b.root);
  assert.match(out, /must pin an exact version/); assert.match(out, /must carry a digest/);
  const c = prodDomain((a) => { a.references[0].registry = "made-up"; });
  assert.match(errsOf(c.root), /artifact\.yaml/);
});

test("references validate without network access; local registry references resolve offline", () => {
  const b = prodDomain((a) => { a.references.push({ registry: "execution-agents", id: "support.missing", version: "1.0.0", digest: "sha256:" + "b".repeat(64) }); });
  assert.match(errsOf(b.root), /unresolved local reference execution-agents\/support\.missing/);
});

test("candidate version must exceed every canonical version; maturity must match tree", () => {
  const { root, dir } = baseline();
  const cdir = join(root, "candidates", PID, "1.0.0");
  mkdirSync(join(root, "candidates", PID), { recursive: true });
  cpSync(dir, cdir, { recursive: true });
  edit(cdir, (a) => { a.metadata.maturity = "candidate"; });
  assert.match(errsOf(root), /exists in more than one tree|must exceed every canonical version/);
  const t = prodDomain();
  edit(t.dir, (a) => { a.metadata.maturity = "candidate"; });
  assert.match(errsOf(t.root), /does not match tree/);
});

test("evolved candidates need lineage and motivating evidence", () => {
  const root = join(tmp(), "synthetic");
  cpSync(SYN, root, { recursive: true });
  const dir = join(root, "candidates/synthetic.support-ticket-triage/1.0.1");
  edit(dir, (a) => { a.metadata.origin.evolution.sourceRefs = a.metadata.origin.evolution.sourceRefs.filter((r) => !r.evidence); });
  wr(join(dir, "seal.yaml"), computeSeal(rd(join(dir, "artifact.yaml")), dir));
  assert.match(errsOf(root, "synthetic"), /role 'motivates'/);
});

test("no hard-coded endpoints, credentials or raw runtime data", () => {
  const a = prodDomain((x) => { x.spec.description = "Calls https://api.example.com to classify tickets."; });
  assert.match(errsOf(a.root), /contains an endpoint/);
  const b = prodDomain((x) => { x.spec.purpose.summary = "key sk-abcdefghijklmnopqrstuvwx used here"; });
  assert.match(errsOf(b.root), /credential/);
  const c = prodDomain();
  edit(c.dir, (x) => { x.attestations = [{ type: "evaluation", ref: "https://x.example/run/1", subjectDigest: "sha256:" + "0".repeat(64) }]; });
  assert.match(errsOf(c.root), /artifact\.yaml/); // evidence must be an evidence:// pointer
});

test("class-specific execution semantics are still enforced", () => {
  const a = prodDomain((x) => { x.spec.tools[0].sideEffects = "irreversible"; });
  const out = errsOf(a.root);
  assert.match(out, /requiresApproval/); assert.match(out, /permissions\.sideEffects is lower/);
  const b = prodDomain((x) => { x.spec.timeoutPolicy.stepSeconds = 9999; });
  assert.match(errsOf(b.root), /stepSeconds exceeds runSeconds/);
  const c = prodDomain((x) => { x.spec.checkpointPolicy.strategy = "none"; });
  assert.match(errsOf(c.root), /require a strategy other than 'none'/);
});

// ---- lifecycle overlays
function overlay(root, events) {
  wr(join(root, "lifecycle", `${PID}.yaml`), { apiVersion: "registry.zeptly.dev/v1alpha1", kind: "LifecycleOverlay", subject: { registry: "execution-agents", id: PID }, events });
}
const ev = (digest, state, at, extra = {}) => ({ version: "1.0.0", digest, state, at, actor: "team:x", ...extra });

test("lifecycle overlay: legal transitions, digest binding, reasons, effective lifecycle in index", () => {
  const { root, digest } = baseline();
  overlay(root, [ev(digest, "deprecated", "2026-02-01T00:00:00Z", { reason: "superseded" }), ev(digest, "revoked", "2026-03-01T00:00:00Z", { reason: "unsafe" })]);
  assert.equal(errsOf(root), "");
  assert.equal(buildIndex(loadDomain(root), "production").entries[0].lifecycle, "revoked");
  overlay(root, [ev(digest, "revoked", "2026-02-01T00:00:00Z", { reason: "unsafe" }), ev(digest, "active", "2026-03-01T00:00:00Z")]);
  assert.match(errsOf(root), /illegal lifecycle transition revoked -> active/);
  overlay(root, [ev("sha256:" + "c".repeat(64), "deprecated", "2026-02-01T00:00:00Z", { reason: "other digest" })]);
  assert.match(errsOf(root), /digest does not match/);
  overlay(root, [ev(digest, "deprecated", "2026-02-01T00:00:00Z")]);
  assert.match(errsOf(root), /requires a reason/);
});

// ---- immutability against a base
const snapshot = (root) => { const d = join(tmp(), "registry"); cpSync(root, d, { recursive: true }); return d; };
const changes = (base, head) => checkDomainChange(loadDomain(base), loadDomain(head)).join("\n");

test("change check: content change and deletion are rejected", () => {
  const { root, dir } = baseline();
  const base = snapshot(root);
  writeFileSync(join(dir, "prompts/system.md"), "changed\n");
  wr(join(dir, "seal.yaml"), computeSeal(rd(join(dir, "artifact.yaml")), dir));
  assert.match(changes(base, root), /content digest changed/);
  const del = snapshot(base); rmSync(join(del, "canonical", PID), { recursive: true });
  assert.match(changes(base, del), /removed or moved/);
});

test("change check: attestations, approvals and overlay events are append-only", () => {
  const { root, dir, digest } = baseline();
  overlay(root, [ev(digest, "deprecated", "2026-02-01T00:00:00Z", { reason: "old" })]);
  const base = snapshot(root);
  edit(dir, (a) => { a.attestations.pop(); });
  assert.match(changes(base, root), /attestations\[\d\] was modified or removed/);
  const h2 = snapshot(base); edit(join(h2, "canonical", PID, "1.0.0"), (a) => { a.attestations.push({ type: "provenance", ref: "evidence://t/p", subjectDigest: digest }); });
  assert.equal(changes(base, h2), "");
  const h3 = snapshot(base); overlay(h3, [ev(digest, "deprecated", "2026-02-01T00:00:00Z", { reason: "changed reason" })]);
  assert.match(changes(base, h3), /lifecycle\/.*event 0 was modified/);
  const h4 = snapshot(base); overlay(h4, [ev(digest, "deprecated", "2026-02-01T00:00:00Z", { reason: "old" }), ev(digest, "revoked", "2026-03-01T00:00:00Z", { reason: "worse" })]);
  assert.equal(changes(base, h4), "");
});

test("change check: candidate promotes to canonical keeping its digest; reverting is rejected", () => {
  const { root } = prodDomain();
  const cdir = join(root, "candidates", "support.other", "1.0.0"); mkdirSync(join(root, "candidates", "support.other"), { recursive: true });
  cpSync(join(root, "canonical", PID, "1.0.0"), cdir, { recursive: true });
  edit(cdir, (a) => { a.metadata.id = "support.other"; a.metadata.maturity = "candidate"; });
  seal(cdir, { gates: false });
  assert.equal(errsOf(root), "");
  const base = snapshot(root);
  const head = snapshot(base);
  const to = join(head, "canonical", "support.other"); mkdirSync(to, { recursive: true });
  renameSync(join(head, "candidates", "support.other", "1.0.0"), join(to, "1.0.0"));
  edit(join(to, "1.0.0"), (a) => { a.metadata.maturity = "canonical"; });
  assert.equal(changes(base, head), ""); // same digest: maturity is not content
  assert.match(errsOf(head), /'evaluation' attestation/); // ...but promotion gates still apply
  assert.match(changes(head, base), /cannot revert to candidate/);
});

test("change check: objects cannot leave the synthetic domain (e.g. to enter production)", () => {
  const head = join(tmp(), "synthetic");
  cpSync(SYN, head, { recursive: true });
  rmSync(join(head, "canonical/synthetic.support-ticket-triage"), { recursive: true });
  assert.match(changes(SYN, head), /removed or moved out of this domain/);
});

test("semver helpers", () => {
  assert.equal(compare("1.2.3", "1.10.0"), -1);
  assert.equal(compare("1.0.0-rc.1", "1.0.0"), -1);
  assert.ok(satisfies("1.4.0", "^1.2.0")); assert.ok(!satisfies("2.0.0", "^1.2.0"));
  assert.ok(satisfies("0.1.5", "^0.1.0")); assert.ok(!satisfies("0.2.0", "^0.1.0"));
});

// ---- canonical JSON, golden vectors, digest scope
test("canonical JSON is RFC 8785: code-unit key order, ES number/string serialization (RFC vectors)", () => {
  const rfc = { "\u20ac": "Euro Sign", "\r": "Carriage Return", "\ufb33": "Hebrew Letter Dalet With Dagesh", "1": "One", "\ud83d\ude00": "Emoji: Grinning Face", "\u0080": "Control", "\u00f6": "Latin Small Letter O With Diaeresis" };
  assert.equal(canonicalJson(rfc), '{"\\r":"Carriage Return","1":"One","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis","\u20ac":"Euro Sign","\ud83d\ude00":"Emoji: Grinning Face","\ufb33":"Hebrew Letter Dalet With Dagesh"}');
  assert.equal(canonicalJson([333333333.33333329, 1e30, 4.5, 2e-3, 1e-27]), "[333333333.3333333,1e+30,4.5,0.002,1e-27]");
  assert.equal(canonicalJson({ b: [true, null, "x"], a: { d: 1, c: 2 } }), '{"a":{"c":2,"d":1},"b":[true,null,"x"]}');
});

test("canonical JSON rejects values JCS cannot represent", () => {
  for (const bad of [NaN, Infinity, undefined, () => 1, "\ud800", new Date(0), { a: undefined }]) assert.throws(() => canonicalJson(bad), /canonicalJson/);
});

const GOLDEN_ARTIFACT = {
  apiVersion: "registry.zeptly.dev/v1alpha1", kind: "ExecutionAgent",
  metadata: { id: "golden.vector", version: "9.9.9", registry: "execution-agents", origin: { type: "native" }, maturity: "candidate", lifecycle: "active" },
  spec: { name: "Golden", ratio: 0.05, steps: [1, 2, 3], text: "caf\u00e9" }, references: [],
  provenance: { createdAt: "2026-01-01T00:00:00Z", authors: ["github:golden"], sourceRefs: [], transformations: [] },
  security: { classification: "internal", capabilities: [], approvals: [] }, attestations: [],
};
const GOLDEN = {
  artifactDigest: "sha256:ebc0c4e6916dda2780cc154bbebd02f612e2cd2b24d3e7edbb7fed2131a3ba20", // computed independently (Python, sorted-key compact JSON)
  digest: "sha256:fffde3f155f50baffe76a7f2ad4adb48cc3cdef7d47e439a7ae482d5e0812181",
};
function goldenDir() {
  const dir = tmp(); mkdirSync(join(dir, "prompts"));
  writeFileSync(join(dir, "prompts/system.md"), "Golden prompt\n");
  return dir;
}

test("golden vector: artifact digest and directory seal", () => {
  const seal = computeSeal(GOLDEN_ARTIFACT, goldenDir());
  assert.equal(seal.artifactDigest, GOLDEN.artifactDigest);
  assert.equal(seal.digest, GOLDEN.digest);
  assert.deepEqual(seal.excludedFields, ["metadata.version", "metadata.maturity", "metadata.lifecycle", "attestations", "security.approvals"]);
});

test("digest scope: version, maturity, lifecycle marker, attestations and approvals are excluded; everything else counts", () => {
  const dir = goldenDir();
  const same = (fn) => { const a = JSON.parse(JSON.stringify(GOLDEN_ARTIFACT)); fn(a); return computeSeal(a, dir); };
  for (const fn of [
    (a) => { a.metadata.version = "1.0.0"; },
    (a) => { a.metadata.maturity = "canonical"; },
    (a) => { a.metadata.lifecycle = "active"; },
    (a) => { a.attestations.push({ type: "evaluation", ref: "evidence://x", subjectDigest: GOLDEN.digest }); },
    (a) => { a.security.approvals.push({ type: "promotion", approver: "team:x", approvedAt: "2026-01-01T00:00:00Z", subjectDigest: GOLDEN.digest }); },
  ]) assert.equal(same(fn).digest, GOLDEN.digest);
  for (const fn of [
    (a) => { a.metadata.id = "golden.other"; }, (a) => { a.metadata.origin.type = "evolved"; }, (a) => { a.spec.ratio = 0.06; },
    (a) => { a.references.push({ registry: "skills", id: "x", version: "1.0.0" }); }, (a) => { a.provenance.authors.push("github:b"); },
    (a) => { a.security.classification = "restricted"; }, (a) => { a.security.capabilities.push({ registry: "capabilities", id: "x" }); },
  ]) assert.notEqual(same(fn).artifactDigest, GOLDEN.artifactDigest);
  writeFileSync(join(dir, "prompts/system.md"), "Changed\n");
  const s = computeSeal(GOLDEN_ARTIFACT, dir);
  assert.equal(s.artifactDigest, GOLDEN.artifactDigest); assert.notEqual(s.digest, GOLDEN.digest); // payload is covered by the directory seal only
});

test("digest is independent of YAML formatting and key order", () => {
  const dir = goldenDir();
  const reparsed = parse(stringify(GOLDEN_ARTIFACT, { sortMapEntries: false, lineWidth: 20 }));
  const reversed = JSON.parse(JSON.stringify(Object.fromEntries(Object.entries(GOLDEN_ARTIFACT).reverse())));
  assert.equal(computeSeal(reparsed, dir).digest, GOLDEN.digest);
  assert.equal(computeSeal(reversed, dir).digest, GOLDEN.digest);
});

test("editing metadata.version alone keeps the digest but is rejected by path/seal-subject rules", () => {
  const { root, dir, digest } = baseline();
  edit(dir, (a) => { a.metadata.version = "1.0.1"; });
  assert.equal(computeSeal(rd(join(dir, "artifact.yaml")), dir).digest, digest);
  const out = errsOf(root);
  assert.match(out, /must equal metadata\.id\/version/); assert.match(out, /seal subject does not match/);
});

// ---- vocabulary
test("origin vocabulary: native | upstream-seed | evolved; evolution kind lives only at metadata.origin.evolution.kind", () => {
  const { root, dir } = baseline();
  for (const legacy of ["authored", "imported"]) { edit(dir, (a) => { a.metadata.origin.type = legacy; }); assert.match(errsOf(root), /artifact\.yaml: \/metadata\/origin\/type/); }
  edit(dir, (a) => { a.metadata.origin = { type: "upstream-seed" }; });
  assert.match(errsOf(root), /artifact\.yaml: \/metadata\/origin must have required property 'import'/);
  edit(dir, (a) => { a.metadata.origin = { type: "upstream-seed", import: { source: "upstream-x", license: "MIT" } }; });
  assert.doesNotMatch(errsOf(root), /artifact\.yaml:/);
  edit(dir, (a) => { a.metadata.origin = { type: "native" }; a.provenance.evolution = { kind: "refined" }; });
  assert.match(errsOf(root), /provenance.*evolution/);
  const cand = join(tmp(), "synthetic"); cpSync(SYN, cand, { recursive: true });
  const cdir = join(cand, "candidates/synthetic.support-ticket-triage/1.0.1");
  edit(cdir, (a) => { delete a.metadata.origin.evolution.kind; });
  assert.match(errsOf(cand, "synthetic"), /artifact\.yaml: .*kind/);
  for (const path of ["synthetic/index.json", "registry/index.json"]) assert.doesNotMatch(readFileSync(join(REPO_ROOT, path), "utf8"), /authored|imported/);
});

test("code-point comparator is locale-independent and orders indexes", () => {
  assert.deepEqual(["a.b", "a-b", "a_b", "ab", "a"].sort(compareCodePoints), ["a", "a-b", "a.b", "a_b", "ab"]);
  assert.deepEqual(["\ud83d\ude00", "\ufb33"].sort(compareCodePoints), ["\ufb33", "\ud83d\ude00"]); // U+FB33 < U+1F600 (UTF-16 unit order would differ)
  assert.equal(compareCodePoints("x", "x"), 0);
  const ids = buildIndex(loadDomain(SYN), "synthetic").entries.map((e) => e.id);
  assert.deepEqual(ids, [...ids].sort(compareCodePoints));
});

// ---- file policy
test("file policy: allow-list, extensions, size, runtime-record names, symlinks", () => {
  const { root, dir } = baseline();
  const bad = (rel, body = "x\n") => { mkdirSync(join(dir, rel, ".."), { recursive: true }); writeFileSync(join(dir, rel), body); const r = errsOf(root); rmSync(join(dir, rel)); const top = rel.split("/")[0]; if (!["prompts", "contracts", "evals"].includes(top)) rmSync(join(dir, top), { recursive: true, force: true }); return r; };
  assert.match(bad("notes.txt"), /not allowed at version-directory root/);
  assert.match(bad("prompts/run.log"), /extension '\.log' not allowed/);
  assert.match(bad("prompts/run.jsonl", "{}\n"), /extension '\.jsonl' not allowed/);
  assert.match(bad("prompts/tape.md"), /raw runtime record/);
  assert.match(bad("contracts/trace.json", "{}\n"), /raw runtime record/);
  assert.match(bad("prompts/transcript-1.txt"), /raw runtime record/);
  assert.match(bad(".hidden/x.md"), /not allowed/);
  assert.match(bad("scripts/run.md"), /not in allow-list/);
  assert.match(bad("prompts/big.md", "a".repeat(LIMITS.maxFileBytes + 1)), /exceeds the \d+-byte file limit/);
  symlinkSync(join(dir, "prompts/system.md"), join(dir, "prompts/alias.md"));
  assert.match(errsOf(root), /symlinks are not allowed/);
  assert.ok(scanVersionDir(dir).errors.some((e) => /alias\.md.*symlink/.test(e)));
  rmSync(join(dir, "prompts/alias.md"));
  assert.equal(errsOf(root), "");
});

test("file policy: symlinked or stray entries in the tree structure are rejected", () => {
  const { root } = baseline();
  symlinkSync(join(root, "canonical", PID, "1.0.0"), join(root, "canonical", PID, "1.0.1"));
  assert.match(errsOf(root), /only version directories are allowed here \(symlink\)/);
  writeFileSync(join(root, "canonical", "stray.txt"), "x");
  assert.match(errsOf(root), /only identity directories are allowed here/);
});

test("file policy: LF-only UTF-8, no BOM, no NUL, no NDJSON", () => {
  const { root, dir } = baseline();
  const p = join(dir, "prompts/system.md"), orig = readFileSync(p);
  writeFileSync(p, orig.toString().replace(/\n/g, "\r\n")); assert.match(errsOf(root), /CR characters not allowed/);
  writeFileSync(p, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), orig])); assert.match(errsOf(root), /BOM not allowed/);
  writeFileSync(p, Buffer.concat([orig, Buffer.from([0xff, 0xfe])])); assert.match(errsOf(root), /not valid UTF-8/);
  writeFileSync(p, orig);
  writeFileSync(join(dir, "contracts/lines.json"), '{"a":1}\n{"a":2}\n'); assert.match(errsOf(root), /JSON Lines\/NDJSON are not allowed/);
  rmSync(join(dir, "contracts/lines.json"));
  assert.equal(errsOf(root), "");
});

test("payload scans: sidecar files are scanned for secrets and endpoints; only $schema meta-schema URLs are exempt", () => {
  const { root, dir } = baseline();
  const p = join(dir, "prompts/system.md"), orig = readFileSync(p, "utf8");
  writeFileSync(p, orig + "\nCall https://api.example.com/v1 for data.\n"); assert.match(errsOf(root), /prompts\/system\.md:\d+: contains an endpoint/);
  writeFileSync(p, orig + "\nUse localhost:8080 locally.\n"); assert.match(errsOf(root), /contains an endpoint/);
  writeFileSync(p, orig + "\nkey sk-abcdefghijklmnopqrstuvwx\n"); assert.match(errsOf(root), /looks like a credential/);
  writeFileSync(p, orig);
  const c = join(dir, "contracts/input.schema.json"), co = JSON.parse(readFileSync(c, "utf8"));
  assert.match(co.$schema, /^https:\/\/json-schema\.org\/draft\/2020-12\/schema$/); assert.equal(errsOf(root), ""); // the shipped $schema is allowed
  writeFileSync(c, JSON.stringify({ ...co, description: "see https://internal.example/spec" })); assert.match(errsOf(root), /contracts\/input\.schema\.json.*contains an endpoint/);
  writeFileSync(c, JSON.stringify({ ...co, $schema: "https://evil.example/schema" })); assert.match(errsOf(root), /contains an endpoint/);
});

test("payload scans: tape/trace/transcript content is detected", () => {
  const { root, dir } = baseline();
  const f = join(dir, "contracts/sample.json");
  writeFileSync(f, JSON.stringify({ trace_id: "abc" })); assert.match(errsOf(root), /key only occurs in raw runtime records/);
  writeFileSync(f, JSON.stringify({ x: { tool_calls: [] } })); assert.match(errsOf(root), /key only occurs in raw runtime records/);
  const msgs = ["user", "assistant", "user", "assistant"].map((role) => ({ role, content: "hi" }));
  writeFileSync(f, JSON.stringify({ history: msgs })); assert.match(errsOf(root), /looks like a conversation transcript/);
  writeFileSync(f, JSON.stringify({ history: msgs.slice(0, 2) })); assert.doesNotMatch(errsOf(root), /transcript/);
  rmSync(f);
  const t = join(dir, "prompts/system.md"), o = readFileSync(t, "utf8");
  writeFileSync(t, o + Array.from({ length: 10 }, (_, i) => `${i % 2 ? "Assistant" : "User"}: line ${i}`).join("\n") + "\n");
  assert.match(errsOf(root), /looks like a conversation transcript/);
});

// ---- synthetic evidence restrictions
test("synthetic evidence pointers are required in the synthetic domain and forbidden in production", () => {
  const syn = join(tmp(), "synthetic"); cpSync(SYN, syn, { recursive: true });
  const sdir = join(syn, "canonical/synthetic.support-ticket-triage/1.0.0");
  edit(sdir, (a) => { a.attestations[0].ref = "evidence://real/eval/1"; });
  assert.match(errsOf(syn, "synthetic"), /synthetic artifacts may only use 'evidence:\/\/synthetic\/…' evidence pointers/);
  const prod = baseline();
  edit(prod.dir, (a) => { a.attestations[0].ref = "evidence://synthetic/eval/1"; });
  assert.match(errsOf(prod.root), /production artifacts cannot cite synthetic evidence/);
  const evolved = join(tmp(), "synthetic"); cpSync(SYN, evolved, { recursive: true });
  edit(join(evolved, "candidates/synthetic.support-ticket-triage/1.0.1"), (a) => { a.metadata.origin.evolution.sourceRefs.find((r) => r.evidence).evidence = "evidence://live/sessions/1"; });
  assert.match(errsOf(evolved, "synthetic"), /origin\.evolution\.sourceRefs\[\d\]\.evidence: synthetic artifacts may only use/);
});

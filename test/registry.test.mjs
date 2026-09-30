import test from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, renameSync, symlinkSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { stringify, parse } from "yaml";
import { REPO_ROOT, makeValidators, loadDomain, computeSeal, canonicalJson, compareCodePoints, DOMAINS } from "../scripts/lib/core.mjs";
import { scanVersionDir, LIMITS } from "../scripts/lib/files.mjs";
import { parseYamlStrict, isUnsafeIntegerLiteral } from "../scripts/lib/yaml.mjs";
import { validateDomain } from "../scripts/lib/rules.mjs";
import { checkDomainChange } from "../scripts/lib/changes.mjs";
import { buildIndex } from "../scripts/lib/index.mjs";
import { compare, satisfies } from "../scripts/lib/semver.mjs";
import { EXIT, toDiag } from "../scripts/lib/diag.mjs";

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

/** Evaluation attestation with the v0.2 record shape: suite identity (id, version, digest of the sealed suite file), result, subject and seal binding. */
function evalAtt(dir, sealObj, suiteId, result, extra = {}) {
  const a = rd(join(dir, "artifact.yaml"));
  const su = a.spec.evaluation.suites.find((x) => x.id === suiteId);
  return { type: "evaluation", suite: { id: suiteId, version: rd(join(dir, su.file)).version, digest: sealObj.payload.find((p) => p.path === su.file).sha256 }, result,
    ref: "evidence://t/eval", subjectDigest: sealObj.artifactDigest, sealDigest: sealObj.sealDigest, ...extra };
}

/** Re-seal a directory and (optionally) re-issue every gate bound to the new digests. Returns the artifact digest. */
function seal(dir, { gates = true } = {}) {
  const a = rd(join(dir, "artifact.yaml"));
  a.attestations = []; a.security.approvals = [];
  wr(join(dir, "artifact.yaml"), a);
  const s = computeSeal(a, dir);
  wr(join(dir, "seal.yaml"), s);
  if (gates) {
    const bind = { subjectDigest: s.artifactDigest, sealDigest: s.sealDigest };
    a.attestations = [
      ...a.spec.evaluation.suites.filter((x) => x.required).map((x) => evalAtt(dir, s, x.id, "pass")),
      { type: "security-review", ref: "evidence://t/sec", ...bind },
    ];
    a.security.approvals = [{ type: "promotion", approver: "team:x", approvedAt: "2026-01-01T00:00:00Z", ...bind }];
    wr(join(dir, "artifact.yaml"), a);
  }
  return s.artifactDigest;
}

/** A production-domain canonical artifact derived from the synthetic example (marker removed), properly sealed and gated. */
function prodDomain(mutate) {
  const root = join(tmp(), "registry");
  const dir = join(root, "canonical", PID, "1.0.0");
  mkdirSync(join(root, "candidates"), { recursive: true }); mkdirSync(join(root, "lifecycle"), { recursive: true });
  cpSync(TRIAGE, dir, { recursive: true });
  const a = rd(join(dir, "artifact.yaml"));
  a.metadata.id = PID; delete a.provenance.synthetic;
  mutate?.(a, dir);
  wr(join(dir, "artifact.yaml"), a);
  const digest = seal(dir);
  return { root, dir, digest, sealDigest: rd(join(dir, "seal.yaml")).sealDigest };
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

test("index carries registry, identity, version, artifact digest, directory seal, digest algorithm, maturity, lifecycle, origin and location", () => {
  const idx = buildIndex(loadDomain(SYN), "synthetic");
  assert.equal(idx.registry, "execution-agents"); assert.equal(idx.domain, "synthetic"); assert.equal(idx.digestAlgorithm, "zeptly-jcs-v1");
  const e = idx.entries.find((x) => x.id === "synthetic.support-ticket-triage" && x.version === "1.0.1");
  assert.equal(e.registry, "execution-agents"); assert.equal(e.maturity, "candidate"); assert.equal(e.lifecycle, "active"); assert.equal(e.digestAlgorithm, "zeptly-jcs-v1");
  assert.deepEqual(e.origin, { type: "evolved", evolutionKind: "refined" });
  assert.match(e.artifactDigest, /^sha256:[0-9a-f]{64}$/); assert.match(e.sealDigest, /^sha256:[0-9a-f]{64}$/); assert.notEqual(e.artifactDigest, e.sealDigest);
  assert.match(e.location, /^synthetic\/candidates\//);
  assert.ok(v.index(idx));
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
  const b = prodDomain((a) => { a.references.push({ registry: "skills", id: "synthetic.thing", version: "1.0.0", digest: "sha256:" + "a".repeat(64), digestAlgorithm: "zeptly-jcs-v1" }); });
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
  const b = prodDomain((a) => { a.references.push({ registry: "execution-agents", id: "support.missing", version: "1.0.0", digest: "sha256:" + "b".repeat(64), digestAlgorithm: "zeptly-jcs-v1" }); });
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
  wr(join(root, "lifecycle", `${PID}.yaml`), { apiVersion: "registry.zeptly.dev/v1alpha1", kind: "LifecycleOverlay", digestAlgorithm: "zeptly-jcs-v1", subject: { registry: "execution-agents", id: PID }, events });
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

test("editing metadata.version alone keeps the artifact digest, changes the seal, and is rejected by path/seal-subject rules", () => {
  const { root, dir, digest } = baseline();
  const sealedSeal = rd(join(dir, "seal.yaml")).sealDigest;
  edit(dir, (a) => { a.metadata.version = "1.0.1"; });
  const now = computeSeal(rd(join(dir, "artifact.yaml")), dir);
  assert.equal(now.artifactDigest, digest); assert.notEqual(now.sealDigest, sealedSeal);
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

// ============================================================================================================
// Local defect remediation: evaluation results, lifecycle eligibility, strict text/number input, case collisions
// ============================================================================================================
const emptyDomain = () => { const root = join(tmp(), "registry"); for (const d of ["canonical", "candidates", "lifecycle"]) mkdirSync(join(root, d), { recursive: true }); return root; };
/** A sealed object derived from the TRIAGE fixture under any id/version/tree. Canonical objects get full explicit-pass gates. */
function mkObject(root, tree, id, version, mutate, gates = tree === "canonical") {
  const dir = join(root, tree, id, version);
  mkdirSync(join(root, tree, id), { recursive: true });
  cpSync(TRIAGE, dir, { recursive: true }); rmSync(join(dir, "seal.yaml"));
  const a = rd(join(dir, "artifact.yaml"));
  a.metadata.id = id; a.metadata.version = version; a.metadata.maturity = tree === "canonical" ? "canonical" : "candidate"; delete a.provenance.synthetic;
  mutate?.(a);
  wr(join(dir, "artifact.yaml"), a);
  return { dir, digest: seal(dir, { gates }) };
}
const writeOverlay = (root, id, events) => wr(join(root, "lifecycle", `${id}.yaml`), { apiVersion: "registry.zeptly.dev/v1alpha1", kind: "LifecycleOverlay", digestAlgorithm: "zeptly-jcs-v1", subject: { registry: "execution-agents", id }, events });
const lifeEvent = (version, digest, state, at = "2026-02-01T00:00:00Z") => ({ version, digest, state, at, actor: "team:x", ...(state === "active" ? {} : { reason: "test reason" }) });
const dep = (id, version, digest) => (a) => { a.references.push({ registry: "execution-agents", id, version, digest: digest ?? null, ...(digest ? { digestAlgorithm: "zeptly-jcs-v1" } : {}) }); };

// ---- 1. promotion requires an explicit passing evaluation result bound to the current digest
function evalDomain(results) {
  const d = prodDomain();
  const sealObj = rd(join(d.dir, "seal.yaml"));
  edit(d.dir, (a) => {
    a.attestations = a.attestations.filter((x) => x.type !== "evaluation");
    for (const r of results) a.attestations.push(evalAtt(d.dir, sealObj, "golden-triage", r));
  });
  return { ...d, sealObj };
}
test("evaluation gate: explicit pass satisfies; missing and inconclusive and failed results do not", () => {
  assert.equal(errsOf(evalDomain(["pass"]).root), "");
  assert.match(errsOf(evalDomain([]).root), /lacks a digest-bound 'evaluation' attestation for required suite 'golden-triage'/);
  assert.match(errsOf(evalDomain(["inconclusive"]).root), /no passing evaluation result.*inconclusive/);
  assert.match(errsOf(evalDomain(["fail"]).root), /failing evaluation result.*blocks promotion/);
});

test("evaluation record schema: 'result' and the suite identity {id, version, digest} are required on evaluation attestations", () => {
  const d = evalDomain(["pass"]);
  edit(d.dir, (a) => { delete a.attestations.find((x) => x.type === "evaluation").result; });
  assert.match(errsOf(d.root), /artifact\.yaml: .*attestations\/\d+ must have required property 'result'/);
  const e = evalDomain(["pass"]);
  edit(e.dir, (a) => { a.attestations.find((x) => x.type === "evaluation").suite = "golden-triage"; });
  assert.match(errsOf(e.root), /attestations\/\d+\/suite must be object/);
  const f = evalDomain(["pass"]);
  edit(f.dir, (a) => { delete a.attestations.find((x) => x.type === "evaluation").suite.digest; });
  assert.match(errsOf(f.root), /suite must have required property 'digest'/);
});

test("evaluation gate: a failure blocks even beside a pass; a later pass after inconclusive satisfies", () => {
  assert.match(errsOf(evalDomain(["pass", "fail"]).root), /failing evaluation result/);
  assert.match(errsOf(evalDomain(["fail", "pass"]).root), /failing evaluation result/);
  assert.equal(errsOf(evalDomain(["inconclusive", "pass"]).root), "");
});

test("evaluation gate: the pass must match the sealed suite identity (version and digest) and the subject and seal digests", () => {
  const wrongDigest = evalDomain(["pass"]);
  edit(wrongDigest.dir, (a) => { a.attestations.find((x) => x.type === "evaluation").suite.digest = "sha256:" + "d".repeat(64); });
  assert.match(errsOf(wrongDigest.root), /do not match the sealed suite identity.*digest/);
  const wrongVersion = evalDomain(["pass"]);
  edit(wrongVersion.dir, (a) => { a.attestations.find((x) => x.type === "evaluation").suite.version = "9.9.9"; });
  assert.match(errsOf(wrongVersion.root), /do not match the sealed suite identity/);
  const wrongSubject = evalDomain(["pass"]);
  edit(wrongSubject.dir, (a) => { a.attestations.find((x) => x.type === "evaluation").subjectDigest = "sha256:" + "d".repeat(64); });
  const out = errsOf(wrongSubject.root);
  assert.match(out, /is stale: subjectDigest/); assert.match(out, /lacks a digest-bound 'evaluation' attestation/);
  const wrongSeal = evalDomain(["pass"]);
  edit(wrongSeal.dir, (a) => { a.attestations.find((x) => x.type === "evaluation").sealDigest = "sha256:" + "d".repeat(64); });
  assert.match(errsOf(wrongSeal.root), /is stale: sealDigest/);
  const wrongSuite = evalDomain(["pass"]);
  edit(wrongSuite.dir, (a) => { a.attestations.find((x) => x.type === "evaluation").suite.id = "other-suite"; });
  assert.match(errsOf(wrongSuite.root), /lacks a digest-bound 'evaluation' attestation for required suite 'golden-triage'/);
  // a failing result for a DIFFERENT suite version does not block a passing result for the current one
  const mixed = evalDomain(["pass"]);
  edit(mixed.dir, (a) => { const old = structuredClone(a.attestations.find((x) => x.type === "evaluation")); old.suite.version = "0.9.0"; old.suite.digest = "sha256:" + "c".repeat(64); old.result = "fail"; a.attestations.push(old); });
  assert.equal(errsOf(mixed.root), "");
});

test("evaluation record shape: 'result'/'suite' are rejected on non-evaluation attestations; result enum enforced", () => {
  const d = evalDomain(["pass"]);
  edit(d.dir, (a) => { a.attestations.find((x) => x.type === "security-review").result = "pass"; });
  assert.match(errsOf(d.root), /artifact\.yaml: .*attestations\/\d+ (must NOT be valid|must match "else" schema)/);
  const e = evalDomain(["pass"]);
  edit(e.dir, (a) => { a.attestations.find((x) => x.type === "evaluation").result = "passed"; });
  assert.match(errsOf(e.root), /artifact\.yaml: .*attestations\/\d+\/result/);
});

test("evaluation gate does not apply to candidates; shipped synthetic fixtures model pass, inconclusive and fail explicitly", () => {
  const root = emptyDomain();
  const c = mkObject(root, "candidates", "support.cand", "1.0.0", null, false);
  const dir = join(root, "candidates/support.cand/1.0.0"), sealObj = rd(join(dir, "seal.yaml"));
  edit(dir, (a) => { a.attestations = [evalAtt(dir, sealObj, "golden-triage", "fail")]; });
  assert.equal(errsOf(root), ""); void c;
  const res = (d) => rd(join(d, "artifact.yaml")).attestations.filter((x) => x.type === "evaluation").map((x) => x.result);
  assert.deepEqual(res(TRIAGE), ["pass"]);
  assert.deepEqual(res(join(SYN, "candidates/synthetic.contract-clause-extractor/0.1.0")), ["inconclusive", "fail"]);
  assert.equal(errsOf(SYN, "synthetic"), "");
});

// ---- 2. lifecycle eligibility of executable local dependencies (separate cases)
function depWorld() {
  const root = emptyDomain();
  const d1 = mkObject(root, "canonical", "support.dep", "1.0.0");
  return { root, d1 };
}
test("lifecycle: an active exact pin resolves", () => {
  const { root, d1 } = depWorld();
  mkObject(root, "canonical", "support.app", "1.0.0", dep("support.dep", "1.0.0", d1.digest));
  assert.equal(errsOf(root), "");
});

test("lifecycle: a revoked artifact never satisfies an executable exact pin", () => {
  const { root, d1 } = depWorld();
  mkObject(root, "canonical", "support.app", "1.0.0", dep("support.dep", "1.0.0", d1.digest));
  writeOverlay(root, "support.dep", [lifeEvent("1.0.0", d1.digest, "revoked")]);
  assert.match(errsOf(root), /executable dependency execution-agents\/support\.dep@1\.0\.0 is revoked and cannot satisfy it \(revoked artifacts are never eligible\)/);
});

test("lifecycle: a deprecated artifact still satisfies an explicit exact pin", () => {
  const { root, d1 } = depWorld();
  mkObject(root, "canonical", "support.app", "1.0.0", dep("support.dep", "1.0.0", d1.digest));
  writeOverlay(root, "support.dep", [lifeEvent("1.0.0", d1.digest, "deprecated")]);
  assert.equal(errsOf(root), "");
});

test("lifecycle: range selection excludes deprecated and revoked versions", () => {
  const { root, d1 } = depWorld();
  const d2 = mkObject(root, "canonical", "support.dep", "1.1.0");
  mkObject(root, "candidates", "support.app", "1.0.0", dep("support.dep", "^1.0.0"), false);
  assert.equal(errsOf(root), ""); // two active matches
  writeOverlay(root, "support.dep", [lifeEvent("1.0.0", d1.digest, "deprecated")]);
  assert.equal(errsOf(root), ""); // 1.1.0 remains eligible
  writeOverlay(root, "support.dep", [lifeEvent("1.0.0", d1.digest, "deprecated"), lifeEvent("1.1.0", d2.digest, "revoked", "2026-03-01T00:00:00Z")]);
  assert.match(errsOf(root), /no eligible version satisfies executable dependency execution-agents\/support\.dep@\^1\.0\.0: matching versions are (deprecated\/revoked|revoked\/deprecated) \(range selection excludes deprecated and revoked\)/);
});

test("lifecycle: a range whose only match is deprecated (or only revoked) is unsatisfied", () => {
  const { root, d1 } = depWorld();
  mkObject(root, "candidates", "support.app", "1.0.0", dep("support.dep", "^1.0.0"), false);
  writeOverlay(root, "support.dep", [lifeEvent("1.0.0", d1.digest, "deprecated")]);
  assert.match(errsOf(root), /no eligible version satisfies .*matching versions are deprecated/);
  writeOverlay(root, "support.dep", [lifeEvent("1.0.0", d1.digest, "revoked")]);
  assert.match(errsOf(root), /no eligible version satisfies .*matching versions are revoked/);
});

test("lifecycle: lineage may describe a revoked ancestor without authorizing its execution", () => {
  const root = emptyDomain();
  const anc = mkObject(root, "canonical", "support.tool", "1.0.0");
  const evolve = (a) => {
    a.metadata.origin = { type: "evolved", evolution: { kind: "refined", rationale: "Tightened the instructions.", proposer: "agent:p", sourceRefs: [
      { registry: "execution-agents", id: "support.tool", version: "1.0.0", digest: anc.digest, digestAlgorithm: "zeptly-jcs-v1" },
      { evidence: "evidence://t/sessions/1", role: "motivates", summary: "Sessions showing the issue." }] } };
  };
  mkObject(root, "candidates", "support.tool", "1.0.1", evolve, false);
  writeOverlay(root, "support.tool", [lifeEvent("1.0.0", anc.digest, "revoked")]);
  assert.equal(errsOf(root), ""); // historical lineage to a revoked ancestor is valid
  // ...but the same revoked ancestor cannot be used as an executable dependency (separate case)
  mkObject(root, "canonical", "support.app", "1.0.0", dep("support.tool", "1.0.0", anc.digest));
  assert.match(errsOf(root), /executable dependency execution-agents\/support\.tool@1\.0\.0 is revoked/);
});

test("lifecycle: lineage still verifies existence and digest", () => {
  const root = emptyDomain();
  const anc = mkObject(root, "canonical", "support.tool", "1.0.0");
  const evolve = (digest) => (a) => { a.metadata.origin = { type: "evolved", evolution: { kind: "refined", rationale: "Tightened the instructions.", proposer: "agent:p", sourceRefs: [
    { registry: "execution-agents", id: "support.tool", version: "1.0.0", digest, digestAlgorithm: "zeptly-jcs-v1" }, { evidence: "evidence://t/sessions/1", role: "motivates", summary: "Sessions showing the issue." }] } }; };
  mkObject(root, "candidates", "support.tool", "1.0.1", evolve("sha256:" + "e".repeat(64)), false);
  assert.match(errsOf(root), /lineage reference execution-agents\/support\.tool@1\.0\.0 digest mismatch/);
  rmSync(join(root, "candidates/support.tool"), { recursive: true });
  mkObject(root, "candidates", "support.tool", "1.0.1", (a) => { evolve(anc.digest)(a); a.metadata.origin.evolution.sourceRefs[0].version = "0.9.0"; }, false);
  assert.match(errsOf(root), /unresolved lineage reference execution-agents\/support\.tool@0\.9\.0/);
});

test("lifecycle: dependents that are themselves revoked are not held to dependency eligibility", () => {
  const { root, d1 } = depWorld();
  const app = mkObject(root, "canonical", "support.app", "1.0.0", dep("support.dep", "1.0.0", d1.digest));
  writeOverlay(root, "support.dep", [lifeEvent("1.0.0", d1.digest, "revoked")]);
  assert.match(errsOf(root), /is revoked and cannot satisfy it/);
  writeOverlay(root, "support.app", [lifeEvent("1.0.0", app.digest, "revoked")]);
  assert.equal(errsOf(root), "");
});

// ---- 3. fatal UTF-8 and BOM policy for artifact.yaml / seal.yaml / overlays, with controlled diagnostics
test("artifact.yaml and seal.yaml: invalid UTF-8 and BOM are rejected with controlled diagnostics", () => {
  for (const file of ["artifact.yaml", "seal.yaml"]) {
    const { root, dir } = baseline();
    const p = join(dir, file), orig = readFileSync(p);
    writeFileSync(p, Buffer.concat([orig, Buffer.from([0xff, 0xfe, 0x0a])]));
    assert.match(errsOf(root), new RegExp(`${file.replace(".", "\\.")}: not valid UTF-8`));
    writeFileSync(p, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), orig]));
    assert.match(errsOf(root), new RegExp(`${file.replace(".", "\\.")}: UTF-8 BOM not allowed`));
    writeFileSync(p, orig);
    assert.equal(errsOf(root), "");
  }
});

test("unreadable YAML never crashes validation or indexing; diagnostics are file-labelled", () => {
  const { root, dir } = baseline();
  const p = join(dir, "artifact.yaml"), orig = readFileSync(p);
  writeFileSync(p, "a: [unterminated\n");
  assert.match(errsOf(root), /artifact\.yaml: invalid YAML/);
  assert.throws(() => buildIndex(loadDomain(root), "production"), /cannot index unreadable artifacts/);
  writeFileSync(p, orig);
  writeFileSync(join(root, "lifecycle", `${PID}.yaml`), Buffer.from([0xff, 0xfe]));
  assert.match(errsOf(root), new RegExp(`${PID.replace(".", "\\.")}\\.yaml: not valid UTF-8`));
  assert.doesNotThrow(() => checkDomainChange(loadDomain(root), loadDomain(root)));
});

// ---- 4. integer-valued numbers outside the safe range are rejected before precision is lost
test("yaml numbers: unsafe integer-valued literals are rejected at the source in every spelling, with positioned coded diagnostics", () => {
  for (const lit of ["9007199254740992", "-9007199254740992", "9007199254740993", "12345678901234567890", "10000000000000000",
    "9007199254740993.0", "9007199254740993e0", "90071992547409930e-1", "1e16", "1E21", "1e21", "1.5e300"])
    assert.throws(() => parseYamlStrict(`a: ${lit}\n`), /outside the safe range/, lit);
  for (const lit of ["+9007199254740993", "0x20000000000000", "0o1000000000000000000"]) assert.throws(() => parseYamlStrict(`a: ${lit}\n`), /not a JSON-compatible decimal/, lit);
  assert.throws(() => parseYamlStrict("a: [1, {b: 9007199254740993}]\n"), /outside the safe range/);
  assert.throws(() => parseYamlStrict("9007199254740993: x\n"), (e) => e.problems.some((p) => p.code === "yaml-non-string-key") || /outside the safe range/.test(e.message));
  assert.throws(() => parseYamlStrict("a: 1\nb: 12345678901234567890\n"), (e) => e.problems[0].code === "yaml-unsafe-integer" && e.problems[0].line === 2 && e.problems[0].column === 4 && /line 2, column 4/.test(e.message));
});

test("yaml numbers: safe integers and fractional JSON-grammar numbers behave as before; non-JSON spellings are rejected", () => {
  const v = parseYamlStrict("a: 9007199254740991\nb: -9007199254740991\nc: 0.05\nd: 333333333.33333329\ne: 123456789012345678e-2\nf: 1e-7\ng: 2.5e3\nh: 4.5e15\ni: 0\nj: 0.0\nk: 1.0\nm: 9007199254740993.5\nn: 1e15\np: -0\n");
  assert.deepEqual(v, { a: 9007199254740991, b: -9007199254740991, c: 0.05, d: 333333333.3333333, e: 1234567890123456.8, f: 1e-7, g: 2500, h: 4.5e15, i: 0, j: 0, k: 1, m: 9007199254740994, n: 1e15, p: 0 });
  for (const bad of ["a: .5\n", "a: 5.\n", "a: +1\n", "a: 007\n", "a: 0x10\n", "a: .inf\n", "a: .nan\n"]) assert.throws(() => parseYamlStrict(bad), /JSON-compatible decimal|non-finite/, bad);
  assert.equal(isUnsafeIntegerLiteral("0x10"), null); // not a decimal literal
  assert.equal(isUnsafeIntegerLiteral("123456789012345678e-2"), false); // fractional
  assert.equal(isUnsafeIntegerLiteral("9007199254740991"), false); assert.equal(isUnsafeIntegerLiteral("9007199254740992"), true);
  assert.equal(isUnsafeIntegerLiteral("1e400"), true); assert.equal(isUnsafeIntegerLiteral("0e999"), false);
});

test("yaml input: unsafe numbers and v0.2 subset violations are reported with controlled diagnostics in artifact.yaml, seal.yaml and sidecar YAML", () => {
  const { root, dir } = baseline();
  const p = join(dir, "artifact.yaml"), orig = readFileSync(p, "utf8");
  writeFileSync(p, orig.replace(/temperature: .*/, "temperature: 9007199254740993"));
  assert.match(errsOf(root), /artifact\.yaml: numeric literal '9007199254740993' at line \d+, column \d+ is an integer outside the safe range/);
  writeFileSync(p, orig.replace(/temperature: .*/, "temperature: 1e21"));
  assert.match(errsOf(root), /artifact\.yaml: numeric literal '1e21'/);
  writeFileSync(p, orig.replace("spec:\n", "spec: &anchor\n"));
  assert.match(errsOf(root), /artifact\.yaml: anchors are not allowed/);
  writeFileSync(p, orig);
  const sp = join(dir, "seal.yaml"), so = readFileSync(sp, "utf8");
  writeFileSync(sp, so + "extra: 9007199254740993\n");
  assert.match(errsOf(root), /seal\.yaml: numeric literal '9007199254740993'/);
  writeFileSync(sp, so);
  writeFileSync(join(dir, "evals/golden-triage.yaml"), readFileSync(join(dir, "evals/golden-triage.yaml"), "utf8") + "extra: 9007199254740993\n");
  assert.match(errsOf(root), /evals\/golden-triage\.yaml: unparseable YAML: .*outside the safe range/);
});

// ---- 5. case-colliding payload paths
test("payload paths that collide case-insensitively are rejected (files and directories)", () => {
  const { root, dir } = baseline();
  writeFileSync(join(dir, "prompts/A.md"), "a\n"); writeFileSync(join(dir, "prompts/a.md"), "b\n");
  assert.match(errsOf(root), /prompts\/a\.md: case-insensitive path collision with 'prompts\/A\.md'/);
  rmSync(join(dir, "prompts/A.md")); rmSync(join(dir, "prompts/a.md"));
  mkdirSync(join(dir, "prompts/Sub")); mkdirSync(join(dir, "prompts/sub"));
  writeFileSync(join(dir, "prompts/Sub/x.md"), "x\n"); writeFileSync(join(dir, "prompts/sub/y.md"), "y\n");
  assert.match(errsOf(root), /case-insensitive path collision with 'prompts\/Sub'/);
  rmSync(join(dir, "prompts/Sub"), { recursive: true }); rmSync(join(dir, "prompts/sub"), { recursive: true });
  writeFileSync(join(dir, "prompts/notes.md"), "n\n"); writeFileSync(join(dir, "prompts/other.md"), "o\n");
  assert.doesNotMatch(errsOf(root), /collision/); // distinct names do not collide (the extra files only change the seal)
});

// ============================================================================================================
// Protocol v0.2: exit codes, machine-readable diagnostics, vocabulary, digestAlgorithm, synthetic marker, resolution rules
// ============================================================================================================
const node = (args, opts = {}) => spawnSync(process.execPath, args, { cwd: REPO_ROOT, encoding: "utf8", ...opts });
const codes = (root, name) => run(root, name).flatMap((r) => r.errors).map((e) => e.code);

test("exit codes: validate exits 0 when valid and 2 for validation errors or malformed input; --json prints coded diagnostics", () => {
  const good = baseline();
  const ok = node(["scripts/validate.mjs", "--root", good.root, "--name", "production"]);
  assert.equal(ok.status, EXIT.OK);
  writeFileSync(join(good.dir, "artifact.yaml"), "a: [unterminated\n");
  const bad = node(["scripts/validate.mjs", "--root", good.root, "--name", "production", "--json"]);
  assert.equal(bad.status, EXIT.INVALID);
  const out = JSON.parse(bad.stdout);
  assert.equal(out.ok, false);
  const d = out.diagnostics.find((x) => x.code === "yaml-invalid");
  assert.ok(d && d.file === "artifact.yaml" && /invalid YAML/.test(d.message));
  writeFileSync(join(good.dir, "artifact.yaml"), Buffer.from([0xff, 0xfe]));
  const utf = JSON.parse(node(["scripts/validate.mjs", "--root", good.root, "--name", "production", "--json"]).stdout);
  assert.ok(utf.diagnostics.some((x) => x.code === "utf8-invalid" && x.file === "artifact.yaml"));
  assert.equal(node(["scripts/validate.mjs", "--root", good.root, "--name", "production"]).status, EXIT.INVALID);
});

test("exit codes: seal.mjs — 1 when already sealed, 2 for file-policy violations; attest.mjs — 2 for malformed requests", () => {
  const root = emptyDomain();
  mkObject(root, "candidates", "support.cli", "1.0.0", null, false);
  const dir = join(root, "candidates/support.cli/1.0.0");
  assert.equal(node(["scripts/seal.mjs", dir]).status, EXIT.UNSATISFIED); // already sealed: a valid request that cannot be satisfied
  rmSync(join(dir, "seal.yaml"));
  writeFileSync(join(dir, "prompts/run.log"), "x\n");
  const r = node(["scripts/seal.mjs", dir]); assert.equal(r.status, EXIT.INVALID); assert.match(r.stderr, /\[file-extension-not-allowed\]/);
  rmSync(join(dir, "prompts/run.log"));
  assert.equal(node(["scripts/seal.mjs", dir]).status, EXIT.OK);
  assert.equal(node(["scripts/attest.mjs", dir, "--type", "evaluation", "--suite", "golden-triage", "--ref", "evidence://t/x"]).status, EXIT.INVALID); // --result missing
  assert.equal(node(["scripts/attest.mjs", dir, "--type", "evaluation", "--suite", "nope", "--result", "pass", "--ref", "evidence://t/x"]).status, EXIT.INVALID);
});

test("attest.mjs records the v0.2 evaluation shape: suite identity from the sealed suite file, result, subject and seal binding", () => {
  const root = emptyDomain();
  mkObject(root, "candidates", "support.cli", "1.0.0", (a) => { a.attestations = []; }, false);
  const dir = join(root, "candidates/support.cli/1.0.0");
  const r = node(["scripts/attest.mjs", dir, "--type", "evaluation", "--suite", "golden-triage", "--result", "fail", "--ref", "evidence://t/run-1"]);
  assert.equal(r.status, 0, r.stderr);
  const sealObj = rd(join(dir, "seal.yaml")), att = rd(join(dir, "artifact.yaml")).attestations.at(-1);
  assert.deepEqual([att.type, att.result, att.subjectDigest, att.sealDigest], ["evaluation", "fail", sealObj.artifactDigest, sealObj.sealDigest]);
  assert.deepEqual(att.suite, { id: "golden-triage", version: "1.0.0", digest: sealObj.payload.find((p) => p.path === "evals/golden-triage.yaml").sha256 });
  assert.equal(errsOf(root), "");
  // tampering after sealing is refused
  writeFileSync(join(dir, "prompts/system.md"), "x\n");
  assert.equal(node(["scripts/attest.mjs", dir, "--type", "security-review", "--ref", "evidence://t/s"]).status, EXIT.INVALID);
});

test("machine-readable codes: failing cases map to stable codes, never the generic fallback", () => {
  const cases = [
    ["seal-mismatch", () => { const d = baseline(); writeFileSync(join(d.dir, "prompts/system.md"), "x\n"); return [d.root, "production"]; }],
    ["attestation-stale", () => { const d = baseline(); edit(d.dir, (a) => { a.spec.description = "Changed description after sealing the artifact."; }); wr(join(d.dir, "seal.yaml"), computeSeal(rd(join(d.dir, "artifact.yaml")), d.dir)); return [d.root, "production"]; }],
    ["path-case-collision", () => { const d = baseline(); writeFileSync(join(d.dir, "prompts/A.md"), "a\n"); writeFileSync(join(d.dir, "prompts/a.md"), "b\n"); return [d.root, "production"]; }],
    ["symlink-rejected", () => { const d = baseline(); symlinkSync(join(d.dir, "prompts/system.md"), join(d.dir, "prompts/alias.md")); return [d.root, "production"]; }],
    ["endpoint-detected", () => { const d = baseline(); writeFileSync(join(d.dir, "prompts/system.md"), "see https://x.example\n"); return [d.root, "production"]; }],
    ["promotion-evaluation-failed", () => [evalDomain(["fail"]).root, "production"]],
    ["promotion-evaluation-not-passing", () => [evalDomain(["inconclusive"]).root, "production"]],
    ["promotion-evaluation-missing", () => [evalDomain([]).root, "production"]],
    ["synthetic-namespace", () => [prodDomain((a) => { a.metadata.id = "synthetic.support-ticket-triage"; }).root, "production"]],
    ["schema-invalid", () => [prodDomain((a) => { a.surprise = 1; }).root, "production"]],
    ["reference-unresolved", () => [prodDomain((a) => { a.references.push({ registry: "execution-agents", id: "support.missing", version: "1.0.0", digest: "sha256:" + "b".repeat(64), digestAlgorithm: "zeptly-jcs-v1" }); }).root, "production"]],
  ];
  for (const [code, build] of cases) { const [root, name] = build(); const got = codes(root, name); assert.ok(got.includes(code), `${code}: got ${JSON.stringify(got)}`); assert.ok(!got.includes("validation-error") || code === "never", `${code}: generic fallback present in ${JSON.stringify(got)}`); }
  assert.equal(toDiag("anything unexpected").code, "validation-error");
  assert.deepEqual(Object.keys(toDiag("artifact.yaml: /metadata/id must be string").toJSON()).sort(), ["code", "file", "message", "path"]);
});

test("v0.2 vocabulary: origin types, evolution kinds, publication marker", () => {
  for (const type of ["native", "upstream-seed", "discovered", "refined", "evolved"]) assert.ok(v.index({ apiVersion: "registry.zeptly.dev/v1alpha1", kind: "RegistryIndex", registry: "execution-agents", domain: "production", digestAlgorithm: "zeptly-jcs-v1", entries: [{ kind: "ExecutionAgent", registry: "execution-agents", id: "a.b", version: "1.0.0", artifactDigest: "sha256:" + "a".repeat(64), sealDigest: "sha256:" + "b".repeat(64), digestAlgorithm: "zeptly-jcs-v1", maturity: "candidate", lifecycle: "active", origin: { type }, location: "x" }] }), type);
  const ev = (type, kind) => (a) => { a.metadata.origin = { type, evolution: { kind, rationale: "Derived from observed sessions.", proposer: "agent:p", sourceRefs: [{ evidence: "evidence://t/s", role: "motivates", summary: "Observed sessions." }] } }; };
  assert.equal(errsOf(prodDomain(ev("discovered", "discovered")).root), "");
  assert.equal(errsOf(prodDomain(ev("refined", "generalised")).root), "");
  assert.match(errsOf(prodDomain(ev("refined", "invented")).root), /artifact\.yaml: .*evolution\/kind/);
  assert.match(errsOf(prodDomain((a) => { a.metadata.origin = { type: "native", evolution: { kind: "refined", rationale: "Derived from observed sessions.", proposer: "agent:p", sourceRefs: [{ evidence: "evidence://t/s", role: "motivates", summary: "Observed sessions." }] } }; }).root), /origin\.evolution is only valid for origin\.type/);
  assert.match(errsOf(prodDomain((a) => { a.metadata.lifecycle = "deprecated"; }).root), /metadata\.lifecycle is a publication marker and must be 'active'/);
  assert.match(errsOf(prodDomain((a) => { a.metadata.lifecycle = "retired"; }).root), /artifact\.yaml: .*lifecycle/);
});

test("digestAlgorithm: required alongside every digest in references, seals, overlays and indexes; only zeptly-jcs-v1 is accepted", () => {
  const d = baseline();
  edit(d.dir, (a) => { delete a.references[0].digestAlgorithm; });
  assert.match(errsOf(d.root), /artifact\.yaml: .*references\/0 .*(digestAlgorithm|then)/);
  const e = baseline();
  edit(e.dir, (a) => { a.references[0].digestAlgorithm = "zeptly-jcs-v2"; });
  assert.match(errsOf(e.root), /artifact\.yaml: .*references\/0\/digestAlgorithm/);
  const f = baseline();
  const sp = join(f.dir, "seal.yaml"), so = rd(sp); so.digestAlgorithm = "sha256"; wr(sp, so);
  assert.ok(codes(f.root, "production").includes("digest-algorithm-unsupported"));
  const g = baseline();
  writeOverlay(g.root, PID, [lifeEvent("1.0.0", g.digest, "deprecated")]);
  const ov = join(g.root, "lifecycle", `${PID}.yaml`), o = rd(ov); delete o.digestAlgorithm; wr(ov, o);
  assert.match(errsOf(g.root), /digestAlgorithm/);
  assert.equal(rd(join(SYN, TRIAGE.split("synthetic/")[1], "seal.yaml")).digestAlgorithm, "zeptly-jcs-v1");
});

test("synthetic marker: explicit provenance.synthetic is required in the synthetic domain and forbidden in production", () => {
  const syn = join(tmp(), "synthetic"); cpSync(SYN, syn, { recursive: true });
  const dir = join(syn, "canonical/synthetic.support-ticket-triage/1.0.0");
  edit(dir, (a) => { delete a.provenance.synthetic; });
  const out = errsOf(syn, "synthetic");
  assert.match(out, /explicit synthetic marker provenance\.synthetic: true/);
  assert.ok(codes(syn, "synthetic").includes("artifact-digest-mismatch") || codes(syn, "synthetic").includes("seal-mismatch")); // the marker is digest-covered provenance
  const prod = baseline();
  edit(prod.dir, (a) => { a.provenance.synthetic = true; });
  assert.match(errsOf(prod.root), /production artifacts cannot carry a synthetic marker/);
  for (const d of ["canonical/synthetic.support-ticket-triage/1.0.0", "candidates/synthetic.contract-clause-extractor/0.1.0"]) assert.equal(rd(join(SYN, d, "artifact.yaml")).provenance.synthetic, true);
});

test("resolution rules: prereleases resolve only when the range names a prerelease; malformed ranges are invalid-range", () => {
  assert.equal(satisfies("1.3.0-rc.1", "^1.2.0"), false);
  assert.equal(satisfies("1.3.0", "^1.2.0"), true);
  assert.equal(satisfies("1.3.0-rc.2", "^1.3.0-rc.1"), true);
  assert.equal(satisfies("1.2.0-rc.1", "~1.2.0-rc.1"), true);
  assert.equal(satisfies("1.0.0-rc.1", "1.0.0-rc.1"), true);
  for (const bad of ["*", ">=1.0.0", "1.x", "^1.0", "latest", "", "^", "1.0.0+build", "^^1.0.0"])
    assert.throws(() => satisfies("1.0.0", bad), (e) => e.code === "invalid-range", bad);
  // a canonical dependency range is refused by the schema/pin rules; a candidate's malformed range is a controlled error
  const root = emptyDomain();
  mkObject(root, "candidates", "support.app", "1.0.0", (a) => { a.references.push({ registry: "execution-agents", id: "support.dep", version: "^1.0", digest: null }); }, false);
  assert.match(errsOf(root), /artifact\.yaml: .*references\/\d+\/version/);
});

test("prerelease dependencies: a candidate range naming a prerelease selects canonical prerelease versions only", () => {
  const root = emptyDomain();
  mkObject(root, "canonical", "support.dep", "1.0.0-rc.1");
  mkObject(root, "candidates", "support.app", "1.0.0", dep("support.dep", "^1.0.0"), false);
  assert.match(errsOf(root), /unresolved local reference execution-agents\/support\.dep@\^1\.0\.0/); // a stable range does not see the prerelease
  rmSync(join(root, "candidates/support.app"), { recursive: true });
  mkObject(root, "candidates", "support.app", "1.0.0", dep("support.dep", "^1.0.0-rc.1"), false);
  assert.equal(errsOf(root), "");
});

test("index consumability for a RuntimeLock: entries carry every field a lock subject and pin check need; an unresolved entry is explicit", () => {
  const idx = buildIndex(loadDomain(SYN), "synthetic");
  for (const e of idx.entries) {
    const subject = { registry: e.registry, id: e.id, version: e.version, digest: e.artifactDigest };
    assert.ok(Object.values(subject).every((x) => typeof x === "string" && x.length), e.id);
    assert.equal(e.digestAlgorithm, idx.digestAlgorithm); assert.ok(["production", "synthetic"].includes(idx.domain));
  }
  // shape from the amendment: an unresolved reference is explicit and complete=false (runtime-owned; no resolver here)
  const lock = { apiVersion: "registry.zeptly.dev/v1alpha1", kind: "RuntimeLock", digestAlgorithm: idx.digestAlgorithm, domain: idx.domain,
    subject: { registry: idx.entries[0].registry, id: idx.entries[0].id, version: idx.entries[0].version, digest: idx.entries[0].artifactDigest }, complete: false,
    entries: rd(join(SYN, "canonical/synthetic.support-ticket-triage/1.0.0/artifact.yaml")).references.map((r) => ({ requested: { registry: r.registry, id: r.id, version: r.version }, status: "unresolved", unresolved: { code: "no-peer-index", message: "peer index was not supplied" } })) };
  assert.equal(lock.entries.length, rd(join(SYN, "canonical/synthetic.support-ticket-triage/1.0.0/artifact.yaml")).references.length); // every declared reference appears
  assert.ok(lock.entries.every((x) => x.status === "unresolved" && x.unresolved.code === "no-peer-index") && lock.complete === false);
});

test("indexes: code-point ordering of ids is separate from JCS (UTF-16) key ordering", () => {
  assert.deepEqual(["😀", "דּ"].sort(compareCodePoints), ["דּ", "😀"]);          // code-point order (indexes)
  assert.deepEqual(["😀", "דּ"].sort(), ["😀", "דּ"]);                               // UTF-16 code-unit order (JCS keys)
  assert.equal(canonicalJson({ "דּ": 1, "😀": 2 }), '{"😀":2,"דּ":1}');
});

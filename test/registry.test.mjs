import test from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, renameSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { stringify, parse } from "yaml";
import { REPO_ROOT, makeValidators, loadDomain, computeSeal, DOMAINS } from "../scripts/lib/core.mjs";
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
  assert.match(errsOf(a.root), /http\(s\) URL/);
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

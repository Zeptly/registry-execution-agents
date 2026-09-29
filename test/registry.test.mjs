import test from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { stringify, parse } from "yaml";
import { REPO_ROOT, makeValidators, loadAgent, definitionDigest } from "../scripts/lib/registry.mjs";
import { validateAgent, validateRegistry } from "../scripts/lib/semantic.mjs";
import { checkAgentChange } from "../scripts/lib/changes.mjs";
import { compare, satisfies, bumpKind } from "../scripts/lib/semver.mjs";

const v = makeValidators();
const SRC = join(REPO_ROOT, "agents/support-ticket-triage");

function copy() {
  const dir = join(mkdtempSync(join(tmpdir(), "reg-test-")), "support-ticket-triage");
  cpSync(SRC, dir, { recursive: true });
  return dir;
}
function mutate(dir, fn) {
  const p = join(dir, "agent.yaml");
  const m = parse(readFileSync(p, "utf8"));
  fn(m);
  writeFileSync(p, stringify(m));
  return loadAgent(dir);
}

test("shipped registry is valid", () => {
  const bad = validateRegistry(join(REPO_ROOT, "agents"), v, { forbidCandidates: true }).filter((r) => r.errors.length);
  assert.deepEqual(bad, []);
});

test("candidate example is valid but not mergeable", () => {
  const dir = join(REPO_ROOT, "examples/candidates");
  assert.equal(validateRegistry(dir, v).filter((r) => r.errors.length).length, 0);
  const forbidden = validateRegistry(dir, v, { forbidCandidates: true });
  assert.match(forbidden[0].errors.join("\n"), /cannot be merged/);
});

test("schema rejects unknown fields and bad ids", () => {
  const a = mutate(copy(), (m) => { m.surprise = 1; });
  assert.ok(validateAgent(a, v).length);
  const b = mutate(copy(), (m) => { m.id = "Exec.Bad"; });
  assert.ok(validateAgent(b, v).length);
});

test("hard-coded endpoints and credentials are rejected", () => {
  const a = mutate(copy(), (m) => { m.description = "Calls https://api.example.com to classify tickets."; });
  assert.match(validateAgent(a, v).join("\n"), /http\(s\) URL/);
  const b = mutate(copy(), (m) => { m.purpose.summary = "key sk-abcdefghijklmnopqrstuvwx used here"; });
  assert.match(validateAgent(b, v).join("\n"), /credential/);
});

test("active agents require exact dependency pins", () => {
  const a = mutate(copy(), (m) => { m.skills[0].version = "^1.2.0"; });
  assert.match(validateAgent(a, v).join("\n"), /exact version/);
});

test("released definition cannot change without a version bump", () => {
  const a = mutate(copy(), (m) => { m.description = "A different description of the same agent."; });
  assert.match(validateAgent(a, v).join("\n"), /already released/);
});

test("status change does not alter digest", () => {
  const dir = copy();
  const before = definitionDigest(loadAgent(dir).manifest, dir);
  const a = mutate(dir, (m) => { m.status = "deprecated"; m.lifecycle = { status_reason: "superseded" }; });
  assert.equal(definitionDigest(a.manifest, dir), before);
  assert.deepEqual(validateAgent(a, v), []);
});

test("irreversible tools need approval; side-effect coupling", () => {
  const a = mutate(copy(), (m) => { m.tools[0].side_effects = "irreversible"; });
  const out = validateAgent(a, v).join("\n");
  assert.match(out, /requires_approval/);
  assert.match(out, /permissions.side_effects is lower/);
});

test("restricted classification needs review and HITL", () => {
  const a = mutate(copy(), (m) => { m.security.classification = "restricted"; });
  const out = validateAgent(a, v).join("\n");
  assert.match(out, /security_review_required/);
  assert.match(out, /human_in_the_loop/);
});

test("missing release entry for active agent fails", () => {
  const dir = copy();
  writeFileSync(join(dir, "releases.yaml"), stringify({ schema_version: "1.0", agent: "exec.support-ticket-triage", releases: [] }));
  assert.match(validateAgent(loadAgent(dir), v).join("\n"), /requires a releases.yaml entry/);
});

// ---- change rules
test("change check: same version + changed content fails", () => {
  const b = loadAgent(copy());
  const h = mutate(copy(), (m) => { m.description = "Changed description text for the agent."; });
  assert.match(checkAgentChange(b, h).join("\n"), /without a version bump/);
});

test("change check: permission expansion needs minor bump and security review", () => {
  const b = loadAgent(copy());
  const h = mutate(copy(), (m) => { m.version = "1.0.1"; m.permissions.scopes.push("tickets:write"); });
  const out = checkAgentChange(b, h).join("\n");
  assert.match(out, /at least minor/);
  assert.match(out, /security_review_required/);
});

test("change check: removed output property demands major", () => {
  const b = loadAgent(copy());
  const dir = copy();
  const p = join(dir, "contracts/output.schema.json");
  const s = JSON.parse(readFileSync(p, "utf8"));
  delete s.properties.known_issue_ref;
  writeFileSync(p, JSON.stringify(s));
  const h = mutate(dir, (m) => { m.version = "1.1.0"; });
  assert.match(checkAgentChange(b, h).join("\n"), /at least major/);
});

test("change check: patch bump for prompt-only change is accepted", () => {
  const b = loadAgent(copy());
  const dir = copy();
  writeFileSync(join(dir, "prompts/system.md"), readFileSync(join(dir, "prompts/system.md"), "utf8") + "\nBe brief.\n");
  const h = mutate(dir, (m) => { m.version = "1.0.1"; });
  assert.deepEqual(checkAgentChange(b, h), []);
});

test("change check: illegal transition and ledger tampering", () => {
  const b = loadAgent(copy());
  const dir = copy();
  const h = mutate(dir, (m) => { m.status = "draft"; });
  assert.match(checkAgentChange(b, h).join("\n"), /illegal status transition/);
  const led = parse(readFileSync(join(dir, "releases.yaml"), "utf8"));
  led.releases[0].digest = "sha256:" + "a".repeat(64);
  writeFileSync(join(dir, "releases.yaml"), stringify(led));
  assert.match(checkAgentChange(b, loadAgent(dir)).join("\n"), /append-only/);
});

test("semver helpers", () => {
  assert.equal(compare("1.2.3", "1.10.0"), -1);
  assert.equal(compare("1.0.0-rc.1", "1.0.0"), -1);
  assert.ok(satisfies("1.4.0", "^1.2.0"));
  assert.ok(!satisfies("2.0.0", "^1.2.0"));
  assert.ok(satisfies("0.1.5", "^0.1.0"));
  assert.ok(!satisfies("0.2.0", "^0.1.0"));
  assert.equal(bumpKind("1.0.0", "1.1.0"), "minor");
});

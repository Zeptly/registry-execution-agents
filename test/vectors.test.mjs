// Runs the language-neutral golden vectors (test/vectors/*.json, generated independently by generate_vectors.py)
// against the production implementation, and cross-checks the canonicalization vectors with the RFC 8785 reference implementation.
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import canonicalize from "canonicalize";
import { canonicalJson, computeSeal, artifactProjection, DIGEST_ALGORITHM } from "../scripts/lib/core.mjs";
import { parseYamlStrict, decodeTextStrict } from "../scripts/lib/yaml.mjs";
import { scanPayloadContent } from "../scripts/lib/files.mjs";
import { toDiag } from "../scripts/lib/diag.mjs";

const VEC = join(resolve(dirname(fileURLToPath(import.meta.url))), "vectors");
const load = (n) => JSON.parse(readFileSync(join(VEC, n), "utf8"));
const H = (s) => "sha256:" + createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex");
const codesOf = (fn) => { try { fn(); return null; } catch (e) { return e.problems?.map((p) => p.code) ?? [`other:${e.message}`]; } };

test("vectors declare the versioned hash contract", () => {
  assert.equal(DIGEST_ALGORITHM, "zeptly-jcs-v1");
  for (const f of ["parser.json", "canonicalization.json", "digest.json"]) assert.equal(load(f).digestAlgorithm, "zeptly-jcs-v1", f);
});

test("parser vectors: JSON-compatible YAML subset (accepts, parsed values, machine-readable rejection codes)", () => {
  const { cases } = load("parser.json");
  assert.ok(cases.length >= 40);
  for (const c of cases) {
    const bytes = c.bytesHex !== undefined ? Buffer.from(c.bytesHex, "hex") : Buffer.from(c.yaml, "utf8");
    if (c.valid) {
      const v = parseYamlStrict(decodeTextStrict(bytes));
      assert.deepEqual(v, c.value, c.name);
      assert.equal(canonicalJson(v), c.canonical, c.name);
    } else {
      const codes = codesOf(() => parseYamlStrict(decodeTextStrict(bytes)));
      assert.ok(codes?.includes(c.code), `${c.name}: expected ${c.code}, got ${JSON.stringify(codes)}`);
    }
  }
});

test("canonicalization vectors: RFC 8785 JCS (production wrapper and the reference implementation agree with every vector)", () => {
  const { accept, reject } = load("canonicalization.json");
  for (const c of accept) {
    const v = JSON.parse(c.json);
    assert.equal(canonicalJson(v), c.canonical, c.name);
    assert.equal(canonicalize(v), c.canonical, `${c.name} (reference implementation)`);
    assert.equal(Buffer.from(c.canonical, "utf8").toString("hex"), c.canonicalUtf8Hex, c.name);
    assert.equal(H(c.canonical), c.sha256, c.name);
  }
  for (const c of reject) assert.ok(codesOf(() => canonicalJson(JSON.parse(c.json)))?.includes(c.code), c.name);
});

const DV = load("digest.json");
function materialize(payload) {
  const dir = mkdtempSync(join(tmpdir(), "vec-"));
  for (const [p, content] of Object.entries(payload)) { mkdirSync(join(dir, p, ".."), { recursive: true }); writeFileSync(join(dir, p), content); }
  return dir;
}
function applyMutation(artifact, payload, spec) {
  const a = structuredClone(artifact), p = { ...payload };
  if (spec.set) { let d = a; for (const k of spec.set.path.slice(0, -1)) d = d[k]; d[spec.set.path.at(-1)] = spec.set.value; }
  else if (spec.append) { let d = a; for (const k of spec.append.path) d = d[k]; d.push(spec.append.value); }
  else if (spec.payloadSet) p[spec.payloadSet.path] = spec.payloadSet.content;
  else if (spec.payloadDelete) delete p[spec.payloadDelete];
  return [a, p];
}

test("digest vectors: artifact digest and directory seal reproduce the expected values exactly", () => {
  const e = DV.expected, seal = computeSeal(DV.artifact, materialize(DV.payload));
  assert.equal(canonicalJson(artifactProjection(DV.artifact)), e.projectionCanonical);
  assert.equal(seal.artifactDigest, e.artifactDigest);
  assert.deepEqual(seal.payload, e.payloadEntries);
  assert.equal(canonicalJson({ registry: seal.subject.registry, id: seal.subject.id, version: seal.subject.version, payload: seal.payload }), e.sealInputCanonical);
  assert.equal(seal.sealDigest, e.sealDigest);
  assert.equal(seal.digestAlgorithm, "zeptly-jcs-v1");
});

test("digest vectors: excluded fields, included fields, version-only and payload mutations", () => {
  for (const v of DV.variants) {
    const [a, p] = applyMutation(DV.artifact, DV.payload, v.mutation);
    const s = computeSeal(a, materialize(p));
    assert.equal(s.artifactDigest, v.artifactDigest, `${v.name} artifactDigest`);
    assert.equal(s.sealDigest, v.sealDigest, `${v.name} sealDigest`);
    assert.equal(s.artifactDigest !== DV.expected.artifactDigest, v.artifactDigestChanges, `${v.name}: artifact digest change expectation`);
    assert.equal(s.sealDigest !== DV.expected.sealDigest, v.sealDigestChanges, `${v.name}: seal digest change expectation`);
  }
  const by = Object.fromEntries(DV.variants.map((v) => [v.name, v]));
  for (const n of ["version-only", "maturity", "lifecycle-marker", "attestation-appended", "governance-approval-appended"]) assert.equal(by[n].artifactDigestChanges, false, n);
  for (const n of ["identity-id", "origin", "spec-value", "runtime-approval-requirement", "references", "provenance", "classification", "capabilities"]) assert.equal(by[n].artifactDigestChanges, true, n);
  for (const n of ["payload-mutation", "payload-deletion", "payload-added", "version-only"]) assert.equal(by[n].sealDigestChanges, true, n);
  for (const n of ["payload-mutation", "payload-deletion", "payload-added"]) assert.equal(by[n].artifactDigestChanges, false, `${n}: payload is outside the artifact digest`);
});

test("digest vectors: CRLF and lone CR in payload text are rejected, never normalized", () => {
  for (const r of DV.lineEndingRejections) {
    const dir = mkdtempSync(join(tmpdir(), "vec-"));
    mkdirSync(join(dir, "prompts"));
    writeFileSync(join(dir, r.path), Buffer.from(r.bytesHex, "hex"));
    const errs = scanPayloadContent(dir, [r.path]);
    assert.ok(errs.some((x) => toDiag(x).code === r.code), r.name);
  }
});

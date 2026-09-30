#!/usr/bin/env node
// Append a digest-bound attestation or governed approval to a sealed artifact (append-only).
// usage: node scripts/attest.mjs <dir> --type evaluation --suite <id> --result pass|fail|inconclusive --ref evidence://... [--attestor github:x]
//        node scripts/attest.mjs <dir> --type security-review|provenance --ref evidence://... [--attestor github:x]
//        node scripts/attest.mjs <dir> --approval security-review|promotion --approver github:x [--ref evidence://...]
// Records bind to the artifact digest (subjectDigest) and the directory seal (sealDigest). Evaluation records carry the suite identity
// (id, version, digest of the sealed suite file). exit: 0 recorded · 2 malformed input
import { writeFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { stringify } from "yaml";
import { tryReadYaml, computeSeal, ARTIFACT_FILE, SEAL_FILE, readYaml } from "./lib/core.mjs";
import { EXIT } from "./lib/diag.mjs";

const args = process.argv.slice(2);
const dir = resolve(args[0] ?? "");
const opt = (n) => (args.includes(n) ? args[args.indexOf(n) + 1] : undefined);
const fail = (msg) => { console.error(msg); process.exit(EXIT.INVALID); };
if (!existsSync(join(dir, SEAL_FILE))) fail("artifact is not sealed; run seal.mjs first");
const a = tryReadYaml(join(dir, ARTIFACT_FILE), ARTIFACT_FILE);
const s = tryReadYaml(join(dir, SEAL_FILE), SEAL_FILE);
if (a.errors.length || s.errors.length) fail([...a.errors, ...s.errors].map((e) => `[${e.code}] ${e}`).join("\n"));
const artifact = a.value, seal = s.value;
const actual = computeSeal(artifact, dir);
if (actual.artifactDigest !== seal.artifactDigest || actual.sealDigest !== seal.sealDigest) fail("[seal-mismatch] the artifact or its payload changed after sealing; refusing to attest");
const now = new Date().toISOString();
const bind = { subjectDigest: seal.artifactDigest, sealDigest: seal.sealDigest };
if (opt("--approval")) {
  const r = { type: opt("--approval"), approver: opt("--approver"), approvedAt: now, ...bind };
  if (opt("--ref")) r.ref = opt("--ref");
  artifact.security.approvals.push(r);
} else {
  const r = { type: opt("--type"), ref: opt("--ref"), ...bind, issuedAt: now };
  if (r.type === "evaluation") {
    const su = artifact.spec.evaluation.suites.find((x) => x.id === opt("--suite"));
    if (!su) fail(`evaluation attestations require --suite <id> naming a declared suite (declared: ${artifact.spec.evaluation.suites.map((x) => x.id).join(", ")})`);
    if (!["pass", "fail", "inconclusive"].includes(opt("--result"))) fail("evaluation attestations require --result pass|fail|inconclusive");
    const file = seal.payload.find((p) => p.path === su.file);
    r.suite = { id: su.id, version: readYaml(join(dir, su.file)).version, digest: file.sha256 };
    r.result = opt("--result");
  } else if (opt("--suite") || opt("--result")) fail("--suite/--result are only valid with --type evaluation");
  if (opt("--attestor")) r.attestor = opt("--attestor");
  artifact.attestations.push(r);
}
writeFileSync(join(dir, ARTIFACT_FILE), stringify(artifact));
console.log(`recorded against artifact ${seal.artifactDigest} / seal ${seal.sealDigest}`);

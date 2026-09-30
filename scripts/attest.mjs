#!/usr/bin/env node
// Append a digest-bound attestation or governed approval to a sealed artifact (append-only).
// usage: node scripts/attest.mjs <artifact-dir> --type evaluation|security-review|provenance --ref evidence://... [--suite id] [--attestor github:x]
// evaluation attestations require --result pass|fail|inconclusive
//        node scripts/attest.mjs <artifact-dir> --approval security-review|promotion --approver github:x [--ref evidence://...]
import { writeFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { stringify } from "yaml";
import { readYaml, ARTIFACT_FILE, SEAL_FILE } from "./lib/core.mjs";

const args = process.argv.slice(2);
const dir = resolve(args[0] ?? "");
const opt = (n) => (args.includes(n) ? args[args.indexOf(n) + 1] : undefined);
if (!existsSync(join(dir, SEAL_FILE))) { console.error("artifact is not sealed; run seal.mjs first"); process.exit(2); }
const artifact = readYaml(join(dir, ARTIFACT_FILE));
const seal = readYaml(join(dir, SEAL_FILE));
const now = new Date().toISOString();
if (opt("--approval")) {
  const a = { type: opt("--approval"), approver: opt("--approver"), approvedAt: now, subjectDigest: seal.digest };
  if (opt("--ref")) a.ref = opt("--ref");
  artifact.security.approvals.push(a);
} else {
  const a = { type: opt("--type"), ref: opt("--ref"), subjectDigest: seal.digest, issuedAt: now };
  if (opt("--suite")) a.suite = opt("--suite");
  if (a.type === "evaluation") {
    if (!["pass", "fail", "inconclusive"].includes(opt("--result"))) { console.error("evaluation attestations require --result pass|fail|inconclusive"); process.exit(2); }
    a.result = opt("--result");
  } else if (opt("--result")) { console.error("--result is only valid with --type evaluation"); process.exit(2); }
  if (opt("--attestor")) a.attestor = opt("--attestor");
  artifact.attestations.push(a);
}
writeFileSync(join(dir, ARTIFACT_FILE), stringify(artifact));
console.log(`recorded against ${seal.digest}`);

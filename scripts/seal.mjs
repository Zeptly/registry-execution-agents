#!/usr/bin/env node
// Seal an artifact directory: writes seal.yaml (artifact digest + directory seal, digestAlgorithm zeptly-jcs-v1).
// usage: node scripts/seal.mjs <artifact-dir> [--force]
// exit: 0 sealed · 1 already sealed (published versions are immutable) · 2 malformed input or file-policy violations
import { writeFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { stringify } from "yaml";
import { tryReadYaml, computeSeal, makeValidators, fmtErrors, ARTIFACT_FILE, SEAL_FILE } from "./lib/core.mjs";
import { scanVersionDir, scanPayloadContent } from "./lib/files.mjs";
import { EXIT, toDiag } from "./lib/diag.mjs";

const [dirArg, ...rest] = process.argv.slice(2);
if (!dirArg) { console.error("usage: seal.mjs <artifact-dir> [--force]"); process.exit(EXIT.INVALID); }
const dir = resolve(dirArg);
if (!existsSync(join(dir, ARTIFACT_FILE))) { console.error(`[file-not-allowed] no ${ARTIFACT_FILE} in ${dir}`); process.exit(EXIT.INVALID); }
if (existsSync(join(dir, SEAL_FILE)) && !rest.includes("--force")) {
  console.error(`[already-sealed] ${SEAL_FILE} already exists: published versions are immutable. Create a new version instead.`); process.exit(EXIT.UNSATISFIED);
}
const a = tryReadYaml(join(dir, ARTIFACT_FILE), ARTIFACT_FILE);
const v = makeValidators();
const problems = [...a.errors, ...(a.value && !v.artifact(a.value) ? fmtErrors(v.artifact.errors).map((e) => `${ARTIFACT_FILE}: ${e}`) : [])];
if (!problems.length) {
  const scan = scanVersionDir(dir);
  problems.push(...scan.errors, ...scanPayloadContent(dir, scan.files.filter((f) => f !== ARTIFACT_FILE && f !== SEAL_FILE)));
}
if (problems.length) { console.error("refusing to seal:\n" + problems.map((e) => { const d = toDiag(e); return `  - [${d.code}] ${d}`; }).join("\n")); process.exit(EXIT.INVALID); }
const seal = computeSeal(a.value, dir);
writeFileSync(join(dir, SEAL_FILE), stringify(seal));
console.log(`sealed ${seal.subject.id}@${seal.subject.version} artifact=${seal.artifactDigest} seal=${seal.sealDigest}`);

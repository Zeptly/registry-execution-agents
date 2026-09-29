#!/usr/bin/env node
// Seal an artifact directory: writes seal.yaml with the content digest.
// usage: node scripts/seal.mjs <artifact-dir> [--check]
import { writeFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { stringify } from "yaml";
import { readYaml, computeSeal, ARTIFACT_FILE, SEAL_FILE } from "./lib/core.mjs";
import { scanVersionDir, scanPayloadContent } from "./lib/files.mjs";

const [dirArg, ...rest] = process.argv.slice(2);
if (!dirArg) { console.error("usage: seal.mjs <artifact-dir> [--check]"); process.exit(2); }
const dir = resolve(dirArg);
if (!existsSync(join(dir, ARTIFACT_FILE))) { console.error(`no ${ARTIFACT_FILE} in ${dir}`); process.exit(2); }
if (existsSync(join(dir, SEAL_FILE)) && !rest.includes("--force")) {
  console.error(`${SEAL_FILE} already exists: published versions are immutable. Create a new version instead.`); process.exit(1);
}
const scan = scanVersionDir(dir);
const problems = [...scan.errors, ...scanPayloadContent(dir, scan.files.filter((f) => f !== ARTIFACT_FILE && f !== SEAL_FILE))];
if (problems.length) { console.error("refusing to seal; file policy violations:\n" + problems.map((e) => `  - ${e}`).join("\n")); process.exit(1); }
const seal = computeSeal(readYaml(join(dir, ARTIFACT_FILE)), dir);
writeFileSync(join(dir, SEAL_FILE), stringify(seal));
console.log(`sealed ${seal.subject.id}@${seal.subject.version} ${seal.digest}`);

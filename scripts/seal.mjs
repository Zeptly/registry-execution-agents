#!/usr/bin/env node
// Seal an artifact directory: writes seal.yaml with the content digest.
// usage: node scripts/seal.mjs <artifact-dir> [--check]
import { writeFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { stringify } from "yaml";
import { readYaml, computeSeal, ARTIFACT_FILE, SEAL_FILE } from "./lib/core.mjs";

const [dirArg, ...rest] = process.argv.slice(2);
if (!dirArg) { console.error("usage: seal.mjs <artifact-dir> [--check]"); process.exit(2); }
const dir = resolve(dirArg);
if (!existsSync(join(dir, ARTIFACT_FILE))) { console.error(`no ${ARTIFACT_FILE} in ${dir}`); process.exit(2); }
if (existsSync(join(dir, SEAL_FILE)) && !rest.includes("--force")) {
  console.error(`${SEAL_FILE} already exists: published versions are immutable. Create a new version instead.`); process.exit(1);
}
const seal = computeSeal(readYaml(join(dir, ARTIFACT_FILE)), dir);
writeFileSync(join(dir, SEAL_FILE), stringify(seal));
console.log(`sealed ${seal.subject.id}@${seal.subject.version} ${seal.digest}`);

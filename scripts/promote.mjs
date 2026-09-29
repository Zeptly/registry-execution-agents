#!/usr/bin/env node
// Promote a candidate to canonical: moves the sealed object (digest unchanged) and flips metadata.maturity.
// Refuses unless all promotion gates pass on the promoted result.  usage: node scripts/promote.mjs <id> <version> [--domain synthetic]
import { renameSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { stringify } from "yaml";
import { makeValidators, loadDomain, readYaml, DOMAINS, TREES, REPO_ROOT, ARTIFACT_FILE } from "./lib/core.mjs";
import { validateDomain } from "./lib/rules.mjs";

const args = process.argv.slice(2);
const [id, version] = args;
const name = args.includes("--domain") ? args[args.indexOf("--domain") + 1] : "production";
const root = join(REPO_ROOT, DOMAINS[name]);
const from = join(root, TREES.candidate, id, version), to = join(root, TREES.canonical, id, version);
if (!existsSync(from)) { console.error(`no candidate ${id}@${version} in ${name} domain`); process.exit(2); }
if (existsSync(to)) { console.error(`canonical ${id}@${version} already exists`); process.exit(1); }

const a = readYaml(join(from, ARTIFACT_FILE));
a.metadata.maturity = "canonical";
mkdirSync(join(root, TREES.canonical, id), { recursive: true });
renameSync(from, to);
writeFileSync(join(to, ARTIFACT_FILE), stringify(a));
const bad = validateDomain(loadDomain(root), name, makeValidators()).filter((r) => r.errors.length && r.path.startsWith(to));
if (bad.length) {
  // roll the move back: nothing is promoted unless every gate passes
  a.metadata.maturity = "candidate";
  writeFileSync(join(to, ARTIFACT_FILE), stringify(a));
  renameSync(to, from);
  console.error(`promotion refused:\n` + bad.flatMap((r) => r.errors).map((e) => `  - ${e}`).join("\n"));
  process.exit(1);
}
console.log(`promoted ${id}@${version} to canonical (digest unchanged)`);

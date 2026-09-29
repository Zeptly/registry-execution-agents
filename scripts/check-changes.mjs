#!/usr/bin/env node
// Compare the working tree against a base git ref and enforce immutability, semver and lifecycle rules.
// usage: node scripts/check-changes.mjs --base origin/main
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { REPO_ROOT, listAgentDirs, loadAgent } from "./lib/registry.mjs";
import { checkAgentChange } from "./lib/changes.mjs";

const args = process.argv.slice(2);
const base = args.includes("--base") ? args[args.indexOf("--base") + 1] : "origin/main";
const git = (...a) => execFileSync("git", a, { cwd: REPO_ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

try { git("rev-parse", "--verify", `${base}^{commit}`); }
catch { console.log(`base ref '${base}' not found (first commit?); skipping change checks`); process.exit(0); }

// Materialise the base tree's agents/ into a temp dir so the same loaders/digest code can run on it.
const tmp = mkdtempSync(join(tmpdir(), "registry-base-"));
const baseAgents = join(tmp, "agents");
mkdirSync(baseAgents);
let baseFiles = [];
try { baseFiles = git("ls-tree", "-r", "--name-only", base, "agents/").split("\n").filter(Boolean); } catch {}
for (const f of baseFiles) {
  const dest = join(tmp, f);
  mkdirSync(join(dest, ".."), { recursive: true });
  writeFileSync(dest, execFileSync("git", ["show", `${base}:${f}`], { cwd: REPO_ROOT, maxBuffer: 1 << 26 }));
}

const headDirs = listAgentDirs(join(REPO_ROOT, "agents"));
const baseDirs = listAgentDirs(baseAgents);
const slug = (d) => d.split("/").pop();
const errors = [];
const headSlugs = new Set(headDirs.map(slug));
for (const b of baseDirs) if (!headSlugs.has(slug(b))) errors.push([slug(b), ["agent removed; agents are never deleted, set status: retired instead"]]);
for (const h of headDirs) {
  const b = baseDirs.find((x) => slug(x) === slug(h));
  if (!b) continue;
  const errs = checkAgentChange(loadAgent(b), loadAgent(h));
  if (errs.length) errors.push([slug(h), errs]);
}
rmSync(tmp, { recursive: true, force: true });

if (errors.length) {
  for (const [s, es] of errors) { console.error(`FAIL ${s}`); es.forEach((e) => console.error(`  - ${e}`)); }
  process.exit(1);
}
console.log(`change checks passed against ${base} (${headDirs.length} agents)`);

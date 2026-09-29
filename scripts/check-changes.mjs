#!/usr/bin/env node
// Enforce immutability against a base git ref.  usage: node scripts/check-changes.mjs --base origin/main
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { REPO_ROOT, DOMAINS, loadDomain } from "./lib/core.mjs";
import { checkDomainChange } from "./lib/changes.mjs";

const args = process.argv.slice(2);
const base = args.includes("--base") ? args[args.indexOf("--base") + 1] : "origin/main";
const git = (a, o = {}) => execFileSync("git", a, { cwd: REPO_ROOT, maxBuffer: 1 << 27, ...o });
try { git(["rev-parse", "--verify", `${base}^{commit}`], { stdio: "ignore" }); }
catch { console.log(`base ref '${base}' not found; skipping change checks`); process.exit(0); }

const tmp = mkdtempSync(join(tmpdir(), "registry-base-"));
let failed = false;
try {
  for (const [name, dir] of Object.entries(DOMAINS)) {
    let files = [];
    try { files = git(["ls-tree", "-r", "--name-only", base, `${dir}/`], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).split("\n").filter(Boolean); } catch {}
    for (const f of files) { const dest = join(tmp, f); mkdirSync(join(dest, ".."), { recursive: true }); writeFileSync(dest, git(["show", `${base}:${f}`])); }
    const errs = checkDomainChange(loadDomain(join(tmp, dir)), loadDomain(join(REPO_ROOT, dir)));
    if (errs.length) { failed = true; console.error(`FAIL ${name}`); errs.forEach((e) => console.error(`  - ${e}`)); }
    else console.log(`ok   ${name}: immutability preserved vs ${base}`);
  }
} finally { rmSync(tmp, { recursive: true, force: true }); }
if (failed) process.exit(1);

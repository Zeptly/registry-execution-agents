#!/usr/bin/env node
// Build deterministic indexes: registry/index.json (production) and synthetic/index.json (synthetic).
// usage: node scripts/build-index.mjs [--check]   (--check fails if committed indexes differ or are non-deterministic)
import { writeFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { makeValidators, loadDomain, fmtErrors, DOMAINS, REPO_ROOT } from "./lib/core.mjs";
import { buildIndex } from "./lib/index.mjs";

const check = process.argv.includes("--check");
const v = makeValidators();
let failed = false;
for (const [name, dir] of Object.entries(DOMAINS)) {
  const domain = loadDomain(join(REPO_ROOT, dir));
  const idx = buildIndex(domain, name);
  const again = buildIndex(loadDomain(join(REPO_ROOT, dir)), name);
  const text = JSON.stringify(idx, null, 2) + "\n";
  if (text !== JSON.stringify(again, null, 2) + "\n") { console.error(`${name}: index is not deterministic`); failed = true; }
  if (!v.index(idx)) { console.error(`${name}: index invalid: ${fmtErrors(v.index.errors).join("; ")}`); failed = true; }
  if (name === "production" && idx.entries.some((e) => e.id.startsWith("synthetic."))) { console.error("production index contains synthetic entries"); failed = true; }
  const path = join(REPO_ROOT, dir, "index.json");
  if (check) {
    if (!existsSync(path) || readFileSync(path, "utf8") !== text) { console.error(`${dir}/index.json is out of date; run: npm run build:index`); failed = true; }
    else console.log(`ok   ${dir}/index.json (${idx.entries.length} entries)`);
  } else { writeFileSync(path, text); console.log(`wrote ${dir}/index.json (${idx.entries.length} entries)`); }
}
if (failed) process.exit(1);

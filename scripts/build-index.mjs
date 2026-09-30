#!/usr/bin/env node
// Build deterministic indexes: registry/index.json (production) and synthetic/index.json (synthetic).
// usage: node scripts/build-index.mjs [--check]   exit: 0 ok · 2 invalid, non-deterministic, or (with --check) out of date
import { writeFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { makeValidators, loadDomain, fmtErrors, DOMAINS, REPO_ROOT } from "./lib/core.mjs";
import { buildIndex } from "./lib/index.mjs";
import { EXIT } from "./lib/diag.mjs";

const check = process.argv.includes("--check");
let failed = false;
try {
  const v = makeValidators();
  for (const [name, dir] of Object.entries(DOMAINS)) {
    const domain = loadDomain(join(REPO_ROOT, dir));
    let idx; try { idx = buildIndex(domain, name); } catch (e) { console.error(`[index-unreadable] ${name}: ${e.message}`); failed = true; continue; }
    const again = buildIndex(loadDomain(join(REPO_ROOT, dir)), name);
    const text = JSON.stringify(idx, null, 2) + "\n";
    if (text !== JSON.stringify(again, null, 2) + "\n") { console.error(`[index-nondeterministic] ${name}: index is not deterministic`); failed = true; }
    if (!v.index(idx)) { console.error(`[schema-invalid] ${name}: index invalid: ${fmtErrors(v.index.errors).join("; ")}`); failed = true; }
    if (name === "production" && idx.entries.some((e) => e.id.startsWith("synthetic."))) { console.error("[synthetic-namespace] production index contains synthetic entries"); failed = true; }
    const path = join(REPO_ROOT, dir, "index.json");
    if (check) {
      if (!existsSync(path) || readFileSync(path, "utf8") !== text) { console.error(`[index-stale] ${dir}/index.json is out of date; run: npm run build:index`); failed = true; }
      else console.log(`ok   ${dir}/index.json (${idx.entries.length} entries)`);
    } else { writeFileSync(path, text); console.log(`wrote ${dir}/index.json (${idx.entries.length} entries)`); }
  }
} catch (e) { console.error(`[internal-error] ${e.message}`); failed = true; }
process.exit(failed ? EXIT.INVALID : EXIT.OK);

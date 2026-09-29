#!/usr/bin/env node
// Validate schemas + semantic rules for both isolated domains (production: registry/, synthetic: synthetic/).
// usage: node scripts/validate.mjs [--domain production|synthetic] [--root <dir> --name <production|synthetic>]
import { join, relative, isAbsolute } from "node:path";
import { makeValidators, loadDomain, DOMAINS, REPO_ROOT } from "./lib/core.mjs";
import { validateDomain } from "./lib/rules.mjs";

const args = process.argv.slice(2);
const opt = (n) => (args.includes(n) ? args[args.indexOf(n) + 1] : undefined);
const v = makeValidators();
const targets = opt("--root")
  ? [[opt("--name") ?? "production", isAbsolute(opt("--root")) ? opt("--root") : join(REPO_ROOT, opt("--root"))]]
  : Object.entries(DOMAINS).filter(([n]) => !opt("--domain") || n === opt("--domain")).map(([n, d]) => [n, join(REPO_ROOT, d)]);

let bad = 0, total = 0;
for (const [name, root] of targets) {
  console.log(`# domain: ${name} (${relative(REPO_ROOT, root) || "."})`);
  const results = validateDomain(loadDomain(root), name, v);
  for (const r of results) {
    total++;
    const rel = relative(REPO_ROOT, r.path);
    if (r.errors.length) { bad++; console.error(`FAIL ${rel}`); r.errors.forEach((e) => console.error(`  - ${e}`)); }
    else console.log(`ok   ${rel}`);
  }
  if (!results.length) console.log("(no objects)");
}
if (bad) { console.error(`\n${bad} of ${total} item(s) failed validation`); process.exit(1); }
console.log(`\n${total} item(s) valid`);

#!/usr/bin/env node
import { makeValidators, REPO_ROOT } from "./lib/registry.mjs";
import { validateRegistry } from "./lib/semantic.mjs";
import { join, relative, isAbsolute } from "node:path";

const args = process.argv.slice(2);
const flag = (n) => args.includes(n);
const opt = (n, d) => (args.includes(n) ? args[args.indexOf(n) + 1] : d);
const dirArg = opt("--agents-dir", "agents");
const agentsDir = isAbsolute(dirArg) ? dirArg : join(REPO_ROOT, dirArg);

const results = validateRegistry(agentsDir, makeValidators(), { forbidCandidates: flag("--forbid-candidates") });
let bad = 0;
for (const r of results) {
  const rel = relative(REPO_ROOT, r.dir);
  if (r.errors.length) { bad++; console.error(`FAIL ${rel}`); r.errors.forEach((e) => console.error(`  - ${e}`)); }
  else console.log(`ok   ${rel}`);
}
if (!results.length) console.log(`(no agents found in ${dirArg})`);
if (bad) { console.error(`\n${bad} agent(s) failed validation`); process.exit(1); }
console.log(`\n${results.length} agent(s) valid`);

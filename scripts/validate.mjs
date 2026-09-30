#!/usr/bin/env node
// Validate schemas + semantic rules for both isolated domains (production: registry/, synthetic: synthetic/).
// usage: node scripts/validate.mjs [--domain production|synthetic] [--root <dir> --name <production|synthetic>] [--json]
// exit: 0 valid · 2 malformed input or validation errors (Protocol v0.2 §9). --json prints machine-readable diagnostics {code,file,path,line,column,message}.
import { join, relative, isAbsolute } from "node:path";
import { makeValidators, loadDomain, DOMAINS, REPO_ROOT } from "./lib/core.mjs";
import { validateDomain } from "./lib/rules.mjs";
import { EXIT, Diag } from "./lib/diag.mjs";

const args = process.argv.slice(2);
const opt = (n) => (args.includes(n) ? args[args.indexOf(n) + 1] : undefined);
const json = args.includes("--json");
try {
  const v = makeValidators();
  const targets = opt("--root")
    ? [[opt("--name") ?? "production", isAbsolute(opt("--root")) ? opt("--root") : join(REPO_ROOT, opt("--root"))]]
    : Object.entries(DOMAINS).filter(([n]) => !opt("--domain") || n === opt("--domain")).map(([n, d]) => [n, join(REPO_ROOT, d)]);
  let bad = 0, total = 0;
  const diagnostics = [];
  for (const [name, root] of targets) {
    if (!json) console.log(`# domain: ${name} (${relative(REPO_ROOT, root) || "."})`);
    const results = validateDomain(loadDomain(root), name, v);
    for (const r of results) {
      total++;
      const rel = relative(REPO_ROOT, r.path);
      if (r.errors.length) { bad++; diagnostics.push(...r.errors.map((e) => ({ domain: name, ...e.toJSON() }))); if (!json) { console.error(`FAIL ${rel}`); r.errors.forEach((e) => console.error(`  - [${e.code}] ${e}`)); } }
      else if (!json) console.log(`ok   ${rel}`);
    }
    if (!results.length && !json) console.log("(no objects)");
  }
  if (json) console.log(JSON.stringify({ ok: bad === 0, checked: total, diagnostics }, null, 2));
  else console.log(bad ? `\n${bad} of ${total} item(s) failed validation` : `\n${total} item(s) valid`);
  process.exit(bad ? EXIT.INVALID : EXIT.OK);
} catch (e) {
  const d = new Diag("internal-error", `unexpected failure: ${e.message}`);
  if (json) console.log(JSON.stringify({ ok: false, diagnostics: [d.toJSON()] })); else console.error(`[${d.code}] ${d.message}`);
  process.exit(EXIT.INVALID);
}

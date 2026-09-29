#!/usr/bin/env node
// Append a release entry for an agent's current version to its releases.yaml ledger.
// usage: npm run release -- exec.<slug> --change-ref github:Zeptly/registry-execution-agents#12 [--approved-by github:alice]
import { writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { stringify } from "yaml";
import { REPO_ROOT, loadAgent, definitionDigest, makeValidators, fmtErrors } from "./lib/registry.mjs";

const args = process.argv.slice(2);
const id = args[0];
const opt = (n) => (args.includes(n) ? args[args.indexOf(n) + 1] : undefined);
if (!id?.startsWith("exec.")) { console.error("usage: release exec.<slug> --change-ref <ref> [--approved-by <principal>]"); process.exit(2); }
const dir = join(REPO_ROOT, "agents", id.slice(5));
if (!existsSync(join(dir, "agent.yaml"))) { console.error(`no such agent: ${id}`); process.exit(2); }

const v = makeValidators();
const { manifest: m, releases } = loadAgent(dir);
if (!v.agent(m)) { console.error("agent.yaml invalid:\n" + fmtErrors(v.agent.errors).join("\n")); process.exit(1); }
const ledger = releases ?? { schema_version: "1.0", agent: m.id, releases: [] };
if (ledger.releases.some((r) => r.version === m.version)) {
  console.error(`${m.id}@${m.version} is already released; bump the version first (releases are immutable)`); process.exit(1);
}
const entry = {
  version: m.version,
  digest: definitionDigest(m, dir),
  released_at: new Date().toISOString().slice(0, 10),
  change_ref: opt("--change-ref") ?? m.provenance.change_ref,
  git_tag: `${m.id}@${m.version}`,
};
if (opt("--approved-by")) entry.approved_by = [opt("--approved-by")];
ledger.releases.push(entry);
writeFileSync(join(dir, "releases.yaml"), stringify(ledger));
console.log(`recorded ${entry.git_tag} ${entry.digest}`);

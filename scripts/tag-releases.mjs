#!/usr/bin/env node
// Create immutable git tags '<agent-id>@<version>' for every release-ledger entry that lacks one.
// Dry run by default; pass --apply to create tags at HEAD (CI then pushes them).
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { REPO_ROOT, listAgentDirs, loadAgent } from "./lib/registry.mjs";

const apply = process.argv.includes("--apply");
const git = (...a) => execFileSync("git", a, { cwd: REPO_ROOT, encoding: "utf8" }).trim();
const existing = new Set(git("tag", "--list", "exec.*@*").split("\n").filter(Boolean));
let n = 0;
for (const dir of listAgentDirs(join(REPO_ROOT, "agents"))) {
  for (const r of loadAgent(dir).releases?.releases ?? []) {
    if (existing.has(r.git_tag)) continue;
    n++;
    console.log(`${apply ? "tagging" : "would tag"} ${r.git_tag}`);
    if (apply) git("tag", "-a", r.git_tag, "-m", `Release ${r.git_tag} (${r.digest})`);
  }
}
if (!n) console.log("all releases already tagged");

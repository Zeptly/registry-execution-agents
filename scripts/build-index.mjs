#!/usr/bin/env node
// Emit dist/registry-index.json: a generated, machine-readable catalogue for runtimes. Not committed.
import { mkdirSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { REPO_ROOT, listAgentDirs, loadAgent, definitionDigest } from "./lib/registry.mjs";
import { compare } from "./lib/semver.mjs";

const agents = listAgentDirs(join(REPO_ROOT, "agents")).map((dir) => {
  const { manifest: m, releases } = loadAgent(dir);
  return {
    id: m.id, name: m.name, description: m.description, status: m.status, version: m.version,
    digest: definitionDigest(m, dir),
    resolvable: ["active", "deprecated"].includes(m.status),
    path: relative(REPO_ROOT, dir),
    classification: m.security.classification,
    runtime_contract: m.compatibility.runtime_contract,
    skills: (m.skills ?? []).map(({ id, version }) => ({ id, version })),
    capabilities: (m.capabilities ?? []).map(({ id, version }) => ({ id, ...(version && { version }) })),
    tools: (m.tools ?? []).map(({ id, version }) => ({ id, version })),
    replaced_by: m.lifecycle?.replaced_by ?? null,
    releases: (releases?.releases ?? []).map(({ version, digest, git_tag }) => ({ version, digest, git_tag }))
      .sort((a, b) => compare(a.version, b.version)),
  };
}).sort((a, b) => a.id.localeCompare(b.id));

mkdirSync(join(REPO_ROOT, "dist"), { recursive: true });
writeFileSync(join(REPO_ROOT, "dist/registry-index.json"), JSON.stringify({ schema_version: "1.0", agents }, null, 2) + "\n");
console.log(`wrote dist/registry-index.json (${agents.length} agents)`);

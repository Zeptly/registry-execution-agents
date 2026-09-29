import { createHash } from "node:crypto";
import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
export const SCHEMA_BASE = "https://schemas.zeptly.dev/registry-execution-agents/1.0/";
// Fields that may change without creating a new version (status transitions, deprecation metadata).
export const DIGEST_EXCLUDED = ["status", "lifecycle"];

export const readYaml = (p) => parseYaml(readFileSync(p, "utf8"));
export const readJson = (p) => JSON.parse(readFileSync(p, "utf8"));
export const sha256 = (buf) => "sha256:" + createHash("sha256").update(buf).digest("hex");

export function canonicalJson(v) {
  if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
  if (v && typeof v === "object")
    return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalJson(v[k])).join(",") + "}";
  return JSON.stringify(v);
}

export function makeValidators() {
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  addFormats(ajv);
  const load = (f) => ajv.addSchema(readJson(join(REPO_ROOT, "schemas", f)));
  load("execution-agent.schema.json");
  load("releases.schema.json");
  load("eval-suite.schema.json");
  const get = (f) => ajv.getSchema(SCHEMA_BASE + f);
  return {
    agent: get("execution-agent.schema.json"),
    releases: get("releases.schema.json"),
    evalSuite: get("eval-suite.schema.json"),
  };
}

export const fmtErrors = (errs) =>
  (errs || []).map((e) => `${e.instancePath || "/"} ${e.message}${e.params?.additionalProperty ? ` (${e.params.additionalProperty})` : ""}`);

/** Resolve a contract schema (inline or file) to a plain object. */
export function resolveSchema(src, dir) {
  if (src.schema) return src.schema;
  const p = join(dir, src.schema_file);
  return p.endsWith(".json") ? readJson(p) : readYaml(p);
}

/** Files that are part of an agent's definition and therefore hashed. */
export function definitionFiles(m) {
  const files = new Set([m.instructions?.file]);
  for (const k of ["input", "output"]) if (m.contract?.[k]?.schema_file) files.add(m.contract[k].schema_file);
  for (const s of m.evaluation?.suites ?? []) files.add(s.file);
  return [...files].filter(Boolean).sort();
}

/** Content digest of a definition: manifest (minus mutable lifecycle fields) + referenced file bytes. */
export function definitionDigest(manifest, dir) {
  const body = Object.fromEntries(Object.entries(manifest).filter(([k]) => !DIGEST_EXCLUDED.includes(k)));
  const files = {};
  for (const f of definitionFiles(manifest)) {
    const p = join(dir, f);
    if (existsSync(p)) files[f] = sha256(readFileSync(p));
  }
  return sha256(canonicalJson({ manifest: body, files }));
}

/** Enumerate agent directories under agentsDir. */
export function listAgentDirs(agentsDir) {
  if (!existsSync(agentsDir)) return [];
  return readdirSync(agentsDir)
    .map((n) => join(agentsDir, n))
    .filter((p) => statSync(p).isDirectory())
    .sort();
}

export function loadAgent(dir) {
  const manifestPath = join(dir, "agent.yaml");
  const releasesPath = join(dir, "releases.yaml");
  return {
    dir,
    manifest: existsSync(manifestPath) ? readYaml(manifestPath) : null,
    releases: existsSync(releasesPath) ? readYaml(releasesPath) : null,
  };
}

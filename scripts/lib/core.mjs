import { createHash } from "node:crypto";
import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join, dirname, resolve, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
export const API_VERSION = "registry.zeptly.dev/v1alpha1";
export const REGISTRY = "execution-agents";
export const KIND = "ExecutionAgent";
export const SCHEMA_ID = (n) =>
  n === "execution-agent" || n === "eval-suite"
    ? `https://schemas.zeptly.dev/registry-execution-agents/v1alpha1/${n}.schema.json`
    : `https://schemas.zeptly.dev/registry/v1alpha1/${n}.schema.json`;

/** The two isolated domains. Synthetic content can never appear in the production domain. */
export const DOMAINS = { production: "registry", synthetic: "synthetic" };
export const TREES = { canonical: "canonical", candidate: "candidates" };

/** Fields that are governance state or bound to the digest, and therefore NOT part of the content digest. */
export const EXCLUDED_FIELDS = ["metadata.maturity", "attestations", "security.approvals"];
export const SEAL_FILE = "seal.yaml";
export const ARTIFACT_FILE = "artifact.yaml";

export const readYaml = (p) => parseYaml(readFileSync(p, "utf8"));
export const readJson = (p) => JSON.parse(readFileSync(p, "utf8"));
export const sha256 = (buf) => "sha256:" + createHash("sha256").update(buf).digest("hex");
export const toPosix = (p) => p.split(sep).join("/");

export function canonicalJson(v) {
  if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
  if (v && typeof v === "object")
    return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalJson(v[k])).join(",") + "}";
  return JSON.stringify(v);
}

export function makeValidators() {
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  addFormats(ajv);
  for (const n of ["common", "seal", "lifecycle", "index", "eval-suite", "execution-agent"])
    ajv.addSchema(readJson(join(REPO_ROOT, "schemas", `${n}.schema.json`)));
  const get = (n) => ajv.getSchema(SCHEMA_ID(n));
  return { artifact: get("execution-agent"), seal: get("seal"), lifecycle: get("lifecycle"), index: get("index"), evalSuite: get("eval-suite") };
}

export const fmtErrors = (errs) =>
  (errs || []).map((e) => `${e.instancePath || "/"} ${e.message}${e.params?.additionalProperty ? ` (${e.params.additionalProperty})` : ""}`);

export function resolveSchema(src, dir) {
  if (src.schema) return src.schema;
  const p = join(dir, src.schemaFile);
  return p.endsWith(".json") ? readJson(p) : readYaml(p);
}

function stripPath(obj, path) {
  const parts = path.split(".");
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) { cur = cur?.[parts[i]]; if (!cur || typeof cur !== "object") return; }
  delete cur[parts[parts.length - 1]];
}

/** All payload files of an artifact directory (everything except artifact.yaml and seal.yaml), sorted. */
export function payloadFiles(dir) {
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile())
    .map((e) => toPosix(relative(dir, join(e.parentPath ?? e.path, e.name))))
    .filter((f) => f !== ARTIFACT_FILE && f !== SEAL_FILE)
    .sort();
}

/**
 * Content digest of a published version: canonical JSON of the artifact (minus governance/attestation
 * fields) plus the hash of every payload file. Independent of YAML formatting and of maturity, so a
 * promotion moves the object without changing its identity.
 */
export function computeSeal(artifact, dir) {
  const body = JSON.parse(JSON.stringify(artifact));
  for (const p of EXCLUDED_FIELDS) stripPath(body, p);
  const files = {};
  for (const f of payloadFiles(dir)) files[f] = sha256(readFileSync(join(dir, f)));
  const artifactDigest = sha256(canonicalJson(body));
  const digest = sha256(canonicalJson({ artifact: artifactDigest, files }));
  return {
    apiVersion: API_VERSION,
    kind: "Seal",
    subject: { registry: artifact.metadata.registry, id: artifact.metadata.id, version: artifact.metadata.version },
    algorithm: "sha256",
    digest,
    artifactDigest,
    excludedFields: [...EXCLUDED_FIELDS],
    files,
  };
}

/** Enumerate objects in one domain root: { tree, dir, path }. */
export function listObjects(domainRoot) {
  const out = [];
  for (const tree of Object.values(TREES)) {
    const t = join(domainRoot, tree);
    if (!existsSync(t)) continue;
    for (const idDir of readdirSync(t).sort()) {
      const idPath = join(t, idDir);
      if (!statSync(idPath).isDirectory()) continue;
      for (const ver of readdirSync(idPath).sort()) {
        const dir = join(idPath, ver);
        if (statSync(dir).isDirectory()) out.push({ tree, dir, idDir, verDir: ver });
      }
    }
  }
  return out;
}

export function loadObject(o) {
  const ap = join(o.dir, ARTIFACT_FILE), sp = join(o.dir, SEAL_FILE);
  return { ...o, artifact: existsSync(ap) ? readYaml(ap) : null, seal: existsSync(sp) ? readYaml(sp) : null };
}

export function loadOverlays(domainRoot) {
  const d = join(domainRoot, "lifecycle");
  if (!existsSync(d)) return [];
  return readdirSync(d).filter((f) => f.endsWith(".yaml")).sort().map((f) => ({ file: join(d, f), name: f, overlay: readYaml(join(d, f)) }));
}

export function loadDomain(domainRoot) {
  return { root: domainRoot, objects: listObjects(domainRoot).map(loadObject), overlays: loadOverlays(domainRoot) };
}

/** Effective lifecycle for (id, version, digest) from an overlay: last event wins; default active. */
export function effectiveLifecycle(overlays, id, version, digest) {
  const ov = overlays.find((o) => o.overlay?.subject?.id === id);
  const evs = (ov?.overlay?.events ?? []).filter((e) => e.version === version && e.digest === digest);
  return evs.length ? evs[evs.length - 1].state : "active";
}

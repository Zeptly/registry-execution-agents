import { createHash } from "node:crypto";
import { readFileSync, readdirSync, existsSync, lstatSync } from "node:fs";
import { join, dirname, resolve, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { scanVersionDir } from "./files.mjs";

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

/**
 * Artifact digest scope. INCLUDED: apiVersion, kind, metadata.id, metadata.registry, metadata.origin, spec, references,
 * provenance, security.classification, security.capabilities. EXCLUDED (governance state or bound to the digest):
 * metadata.version, metadata.maturity, metadata.lifecycle (publication marker; the effective lifecycle is the overlay),
 * attestations, security.approvals. Lifecycle overlays are separate files and are never part of any digest.
 */
export const EXCLUDED_FIELDS = ["metadata.version", "metadata.maturity", "metadata.lifecycle", "attestations", "security.approvals"];
export const SEAL_FILE = "seal.yaml";
export const ARTIFACT_FILE = "artifact.yaml";

export const readYaml = (p) => parseYaml(readFileSync(p, "utf8"));
export const readJson = (p) => JSON.parse(readFileSync(p, "utf8"));
export const sha256 = (buf) => "sha256:" + createHash("sha256").update(buf).digest("hex");
export const toPosix = (p) => p.split(sep).join("/");

/**
 * Canonical JSON policy (one policy for every digest in this registry): RFC 8785 (JCS) over the parsed value.
 * Object keys sorted by UTF-16 code units, no insignificant whitespace, ECMAScript number and string
 * serialization. Values that JCS cannot represent are REJECTED, not coerced: undefined, functions, NaN/Infinity,
 * lone surrogates, non-plain objects. Numbers are IEEE-754 doubles.
 */
export function canonicalJson(v) {
  if (v === null) return "null";
  switch (typeof v) {
    case "boolean": return v ? "true" : "false";
    case "number":
      if (!Number.isFinite(v)) throw new Error("canonicalJson: non-finite number");
      return JSON.stringify(v);
    case "string":
      if (!isWellFormed(v)) throw new Error("canonicalJson: string contains a lone surrogate");
      return JSON.stringify(v);
    case "object": {
      if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
      const proto = Object.getPrototypeOf(v);
      if (proto !== Object.prototype && proto !== null) throw new Error("canonicalJson: non-plain object");
      return "{" + Object.keys(v).sort().map((k) => canonicalJson(k) + ":" + canonicalJson(v[k])).join(",") + "}";
    }
    default: throw new Error(`canonicalJson: unsupported type ${typeof v}`);
  }
}
const isWellFormed = (s) => (typeof s.isWellFormed === "function" ? s.isWellFormed() : !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s));

/**
 * Portable code-point comparator (locale-independent) used for every ordering in indexes and listings.
 * Compares Unicode code points, not UTF-16 code units and never locale collation.
 */
export function compareCodePoints(a, b) {
  const x = Array.from(a), y = Array.from(b);
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) {
    const p = x[i].codePointAt(0), q = y[i].codePointAt(0);
    if (p !== q) return p < q ? -1 : 1;
  }
  return x.length === y.length ? 0 : x.length < y.length ? -1 : 1;
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

/** Payload files (everything except artifact.yaml/seal.yaml) that pass the file policy, in code-point order. */
export function payloadFiles(dir) {
  return scanVersionDir(dir).files.filter((f) => f !== ARTIFACT_FILE && f !== SEAL_FILE);
}

/**
 * Two digests (see docs/sealing-and-versioning.md):
 *  - artifactDigest: sha256(JCS(artifact minus EXCLUDED_FIELDS))  — the artifact-content scope;
 *  - digest (directory seal): sha256(JCS({artifact: artifactDigest, files})) where files maps every allowed payload
 *    file to sha256(raw bytes). `digest` is the addressing digest used by indexes, references, attestations,
 *    approvals and lifecycle events. Neither includes the version, so identical content has one digest.
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

/** Enumerate objects in one domain root: { tree, dir, idDir, verDir }. Never follows symlinks; records structural issues. */
export function listObjects(domainRoot, issues = []) {
  const out = [];
  const ls = (p) => readdirSync(p).sort(compareCodePoints);
  const kind = (p) => { const st = lstatSync(p); return st.isSymbolicLink() ? "symlink" : st.isDirectory() ? "dir" : st.isFile() ? "file" : "other"; };
  const rel = (p) => toPosix(relative(REPO_ROOT, p));
  if (existsSync(domainRoot))
    for (const n of ls(domainRoot)) {
      const k = kind(join(domainRoot, n));
      if (["canonical", "candidates", "lifecycle"].includes(n)) { if (k !== "dir") issues.push(`${rel(join(domainRoot, n))}: must be a real directory (${k})`); }
      else if (!(n === "index.json" && k === "file")) issues.push(`${rel(join(domainRoot, n))}: unexpected entry at domain root`);
    }
  for (const tree of Object.values(TREES)) {
    const t = join(domainRoot, tree);
    if (!existsSync(t) || kind(t) !== "dir") continue;
    for (const idDir of ls(t)) {
      const idPath = join(t, idDir), ik = kind(idPath);
      if (ik !== "dir") { if (!(idDir === ".gitkeep" && ik === "file")) issues.push(`${rel(idPath)}: only identity directories are allowed here (${ik})`); continue; }
      for (const ver of ls(idPath)) {
        const dir = join(idPath, ver), vk = kind(dir);
        if (vk === "dir") out.push({ tree, dir, idDir, verDir: ver });
        else issues.push(`${rel(dir)}: only version directories are allowed here (${vk})`);
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
  return readdirSync(d).filter((f) => f.endsWith(".yaml") && lstatSync(join(d, f)).isFile()).sort(compareCodePoints).map((f) => ({ file: join(d, f), name: f, overlay: readYaml(join(d, f)) }));
}

export function loadDomain(domainRoot) {
  const issues = [];
  return { root: domainRoot, objects: listObjects(domainRoot, issues).map(loadObject), overlays: loadOverlays(domainRoot), issues };
}

/** Effective lifecycle for (id, version, digest) from an overlay: last event wins; default active. */
export function effectiveLifecycle(overlays, id, version, digest) {
  const ov = overlays.find((o) => o.overlay?.subject?.id === id);
  const evs = (ov?.overlay?.events ?? []).filter((e) => e.version === version && e.digest === digest);
  return evs.length ? evs[evs.length - 1].state : "active";
}

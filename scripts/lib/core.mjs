import { createHash } from "node:crypto";
import { readFileSync, readdirSync, existsSync, lstatSync } from "node:fs";
import { join, dirname, resolve, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { readYamlStrict } from "./yaml.mjs";
import { canonicalJson } from "./jcs.mjs";
import { Diag, InputError } from "./diag.mjs";
export { canonicalJson };
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

/** The one digest contract in this registry (Protocol v0.2). Changing any rule below requires a new identifier and new vectors. */
export const DIGEST_ALGORITHM = "zeptly-jcs-v1";
/**
 * Artifact digest = sha256(JCS(artifactProjection)). INCLUDED: apiVersion, kind (identity), metadata.id, metadata.registry,
 * metadata.origin, spec (incl. runtime approval requirements), references, manifest provenance, security.classification,
 * security.capabilities. EXCLUDED: metadata.version, metadata.maturity, metadata.lifecycle (publication marker; the effective
 * lifecycle is the overlay), attestations, security.approvals (governance approvals), and every sidecar payload file.
 */
export const EXCLUDED_FIELDS = ["metadata.version", "metadata.maturity", "metadata.lifecycle", "attestations", "security.approvals"];
export function artifactProjection(a) {
  return {
    apiVersion: a.apiVersion, kind: a.kind,
    metadata: { id: a.metadata.id, registry: a.metadata.registry, origin: a.metadata.origin },
    spec: a.spec, references: a.references, provenance: a.provenance,
    security: { classification: a.security.classification, capabilities: a.security.capabilities },
  };
}
export const SEAL_FILE = "seal.yaml";
export const ARTIFACT_FILE = "artifact.yaml";

export const readYaml = readYamlStrict; // fatal UTF-8, no BOM, strict numbers, duplicate keys rejected (see lib/yaml.mjs)
export const readJson = (p) => JSON.parse(readFileSync(p, "utf8"));
export const sha256 = (buf) => "sha256:" + createHash("sha256").update(buf).digest("hex");
export const toPosix = (p) => p.split(sep).join("/");

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

/** Payload files (everything except artifact.yaml/seal.yaml) that pass the file policy, in code-point order. */
export function payloadFiles(dir) {
  return scanVersionDir(dir).files.filter((f) => f !== ARTIFACT_FILE && f !== SEAL_FILE);
}

/**
 * Digests (Protocol v0.2, `digestAlgorithm: zeptly-jcs-v1`; see docs/sealing-and-versioning.md):
 *  - artifactDigest = sha256(JCS(artifactProjection))            — identity, origin, spec, references, provenance, classification, capabilities;
 *  - sealDigest     = sha256(JCS({registry, id, version, payload[]})) — payload[] = every permitted payload file as {path, sha256},
 *                     ordered by normalized POSIX path (code-point order), sha256 over the raw file bytes.
 * `artifactDigest` is the pin used by references, index entries and attestation/approval `subjectDigest`; `sealDigest` covers the payload
 * (prompts, contracts, evals) and the version. The artifact metadata file and seal.yaml are never payload.
 */
export function computeSeal(artifact, dir) {
  const { registry, id, version } = artifact.metadata;
  const payload = payloadFiles(dir).map((path) => ({ path, sha256: sha256(readFileSync(join(dir, path))) }));
  const artifactDigest = sha256(Buffer.from(canonicalJson(artifactProjection(artifact)), "utf8"));
  const sealDigest = sha256(Buffer.from(canonicalJson({ registry, id, version, payload }), "utf8"));
  return { apiVersion: API_VERSION, kind: "Seal", digestAlgorithm: DIGEST_ALGORITHM, subject: { registry, id, version }, artifactDigest, sealDigest, payload };
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

/** Read a YAML file without throwing: { value, errors: Diag[] } with coded, file-labelled diagnostics. */
export function tryReadYaml(path, label) {
  if (!existsSync(path)) return { value: null, errors: [], missing: true };
  try { return { value: readYaml(path), errors: [] }; }
  catch (e) {
    const problems = e instanceof InputError ? e.problems : [{ code: "yaml-invalid", message: e.message }];
    return { value: null, errors: problems.map((p) => new Diag(p.code, `${label}: ${p.message}`, { file: label, line: p.line, column: p.column })) };
  }
}

export function loadObject(o) {
  const a = tryReadYaml(join(o.dir, ARTIFACT_FILE), ARTIFACT_FILE);
  const s = tryReadYaml(join(o.dir, SEAL_FILE), SEAL_FILE);
  return { ...o, artifact: a.value, seal: s.value, loadErrors: [...a.errors, ...s.errors] };
}

export function loadOverlays(domainRoot) {
  const d = join(domainRoot, "lifecycle");
  if (!existsSync(d)) return [];
  return readdirSync(d).filter((f) => f.endsWith(".yaml") && lstatSync(join(d, f)).isFile()).sort(compareCodePoints).map((f) => {
    const r = tryReadYaml(join(d, f), f);
    return { file: join(d, f), name: f, overlay: r.value, loadErrors: r.errors };
  });
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

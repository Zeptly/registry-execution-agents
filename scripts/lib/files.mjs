import { readdirSync, lstatSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { parseYamlStrict } from "./yaml.mjs";

/**
 * Version-directory file policy (docs/sealing-and-versioning.md). Everything not explicitly allowed is rejected.
 * Text files must be UTF-8 without BOM, LF-only, no NUL bytes; digests are computed over the raw bytes.
 */
export const LIMITS = { maxFiles: 64, maxFileBytes: 262144, maxTotalBytes: 1048576, maxDepth: 3, maxSegmentLength: 64 };
export const ROOT_FILES = ["artifact.yaml", "seal.yaml"];
export const ALLOWED_DIRS = { prompts: [".md", ".txt"], contracts: [".json", ".yaml", ".yml"], evals: [".yaml", ".yml", ".json"] };
const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
/** File/dir names that indicate raw runtime records (tapes, traces, transcripts, trajectories, spans). */
export const RUNTIME_NAME = /(^|[^a-z])(tapes?|traces?|transcripts?|trajector(?:y|ies)|spans?|chatlogs?)([^a-z]|$)/i;
/** Keys that only appear in raw runtime records. */
export const RUNTIME_KEYS = new Set(["span_id", "parent_span_id", "trace_id", "traceparent", "tool_call_id", "tool_calls", "transcript", "trajectory", "tape", "spans"]);

const posix = (p) => p.split(sep).join("/");

/** Scan a version directory. Never follows symlinks. Returns { files (sorted, posix), errors }. */
export function scanVersionDir(dir) {
  const errors = [], files = [];
  let total = 0;
  const seen = new Map(); // lower-cased path -> original, for files and directories
  const walk = (abs, depth) => {
    let names;
    try { names = readdirSync(abs).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)); } catch (e) { errors.push(`cannot read directory: ${e.message}`); return; }
    for (const name of names) {
      const p = join(abs, name), rel = posix(relative(dir, p));
      const st = lstatSync(p);
      if (st.isSymbolicLink()) { errors.push(`${rel}: symlinks are not allowed`); continue; }
      if (!SEGMENT.test(name) || name.length > LIMITS.maxSegmentLength) { errors.push(`${rel}: file/directory name not allowed (pattern ${SEGMENT}, max ${LIMITS.maxSegmentLength})`); continue; }
      const lower = rel.toLowerCase();
      if (seen.has(lower)) { errors.push(`${rel}: case-insensitive path collision with '${seen.get(lower)}'; bundles must be portable between case-sensitive and case-insensitive filesystems`); continue; }
      seen.set(lower, rel);
      if (st.isDirectory()) {
        if (depth === 0 && !(name in ALLOWED_DIRS)) { errors.push(`${rel}/: directory not in allow-list (${Object.keys(ALLOWED_DIRS).join(", ")})`); continue; }
        if (depth + 1 >= LIMITS.maxDepth) { errors.push(`${rel}/: exceeds maximum depth ${LIMITS.maxDepth}`); continue; }
        if (RUNTIME_NAME.test(name)) { errors.push(`${rel}/: name indicates a raw runtime record (tape/trace/transcript)`); continue; }
        walk(p, depth + 1);
        continue;
      }
      if (!st.isFile()) { errors.push(`${rel}: not a regular file`); continue; }
      if (depth === 0) { if (!ROOT_FILES.includes(name)) { errors.push(`${rel}: file not allowed at version-directory root (only ${ROOT_FILES.join(", ")})`); continue; } }
      else {
        const top = rel.split("/")[0], ext = name.includes(".") ? name.slice(name.lastIndexOf(".")).toLowerCase() : "";
        if (!ALLOWED_DIRS[top].includes(ext)) { errors.push(`${rel}: extension '${ext}' not allowed in ${top}/ (allowed: ${ALLOWED_DIRS[top].join(", ")})`); continue; }
        if (RUNTIME_NAME.test(name)) { errors.push(`${rel}: name indicates a raw runtime record (tape/trace/transcript)`); continue; }
      }
      if (st.size > LIMITS.maxFileBytes) { errors.push(`${rel}: ${st.size} bytes exceeds the ${LIMITS.maxFileBytes}-byte file limit`); continue; }
      total += st.size;
      files.push(rel);
    }
  };
  walk(dir, 0);
  if (files.length > LIMITS.maxFiles) errors.push(`${files.length} files exceeds the limit of ${LIMITS.maxFiles}`);
  if (total > LIMITS.maxTotalBytes) errors.push(`total size ${total} bytes exceeds the ${LIMITS.maxTotalBytes}-byte limit`);
  files.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return { files, errors };
}

const URL_RE = /\b(?:https?|wss?|ftp|sftp|s3|gs|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?):\/\//i;
const HOSTPORT_RE = /\b(?:localhost|\d{1,3}(?:\.\d{1,3}){3}):\d{2,5}\b/i;
const SECRET_RE = /(sk-[A-Za-z0-9]{16,}|-----BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{10,})/;
const META_SCHEMAS = new Set([
  "https://json-schema.org/draft/2020-12/schema", "https://json-schema.org/draft/2019-09/schema", "http://json-schema.org/draft-07/schema#", "https://json-schema.org/draft-07/schema",
]);

/** Endpoint/credential findings for one string. JSON Schema meta-schema identifiers under `$schema` are the only allowed URLs. */
export function stringFindings(val, path) {
  const out = [];
  const isMeta = path.endsWith(".$schema") && META_SCHEMAS.has(val);
  if (!isMeta && (URL_RE.test(val) || HOSTPORT_RE.test(val))) out.push(`${path}: contains an endpoint (URL or host:port); artifacts must not hard-code endpoints`);
  if (SECRET_RE.test(val)) out.push(`${path}: looks like a credential`);
  return out;
}

function walk(v, path, fn) {
  fn(v, path);
  if (Array.isArray(v)) v.forEach((x, i) => walk(x, `${path}[${i}]`, fn));
  else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) walk(x, `${path}.${k}`, fn);
}

const ROLES = new Set(["user", "assistant", "system", "tool", "human", "ai"]);
const isMessage = (o) => o && typeof o === "object" && !Array.isArray(o) && typeof o.role === "string" && ROLES.has(o.role.toLowerCase()) && "content" in o;

/** Heuristics for raw runtime records inside structured payload (tool-call/span keys, long chat transcripts). */
export function runtimeRecordFindings(value, label) {
  const out = [];
  walk(value, label, (v, path) => {
    if (v && typeof v === "object" && !Array.isArray(v)) for (const k of Object.keys(v)) if (RUNTIME_KEYS.has(k)) out.push(`${path}.${k}: key only occurs in raw runtime records (tape/trace/transcript)`);
    if (Array.isArray(v)) {
      const msgs = v.filter(isMessage);
      if (msgs.length >= 4 && new Set(msgs.map((m) => m.role.toLowerCase())).size >= 2) out.push(`${path}: looks like a conversation transcript (${msgs.length} role/content messages)`);
    }
  });
  return out;
}

/** Content policy for every payload file: text hygiene, endpoint/credential scan, runtime-record detection. */
export function scanPayloadContent(dir, files) {
  const errors = [];
  for (const rel of files) {
    const buf = readFileSync(join(dir, rel));
    let text;
    try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(buf); } catch { errors.push(`${rel}: not valid UTF-8`); continue; }
    if (text.charCodeAt(0) === 0xfeff) errors.push(`${rel}: UTF-8 BOM not allowed`);
    if (text.includes("\r")) errors.push(`${rel}: CR characters not allowed (LF line endings only; digests hash raw bytes)`);
    if (text.includes("\0")) errors.push(`${rel}: NUL byte not allowed`);
    const ext = rel.slice(rel.lastIndexOf(".")).toLowerCase();
    if (ext === ".md" || ext === ".txt") {
      text.split("\n").forEach((line, i) => stringFindings(line, `${rel}:${i + 1}`).forEach((f) => errors.push(f)));
      const turns = text.split("\n").filter((l) => /^(user|assistant|human|ai|system|tool)\s*:/i.test(l)).length;
      if (turns >= 10) errors.push(`${rel}: looks like a conversation transcript (${turns} role-prefixed turns)`);
      continue;
    }
    let parsed;
    try {
      if (ext === ".json") JSON.parse(text); // JSON syntax first (JSON Lines/NDJSON fail here); then the v0.2 subset rules below
      parsed = parseYamlStrict(text);
    } catch (e) {
      errors.push(`${rel}: unparseable ${ext === ".json" ? "JSON (JSON Lines/NDJSON are not allowed)" : "YAML"}: ${e.message.split("\n")[0]}`);
      continue;
    }
    walk(parsed, rel, (v, path) => { if (typeof v === "string") stringFindings(v, path).forEach((f) => errors.push(f)); });
    runtimeRecordFindings(parsed, rel).forEach((f) => errors.push(f));
  }
  return errors;
}

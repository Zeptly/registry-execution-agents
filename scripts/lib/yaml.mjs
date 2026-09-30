import { readFileSync } from "node:fs";
import { parseDocument, visit, isScalar } from "yaml";
import { InputError } from "./diag.mjs";

/**
 * Protocol v0.2 manifest input: a JSON-compatible YAML subset (YAML 1.2 core schema).
 *  - string keys only; duplicate keys, anchors, aliases, merge keys, multiple documents and unsupported tags are rejected;
 *  - timestamps and yes/no/on/off remain strings;
 *  - numbers must be JSON-grammar decimals: integers within ±(2^53-1) and finite; integer-valued numbers outside that range are
 *    rejected at the SOURCE literal in every spelling (`9007199254740993.0`, `1e21`), hex/octal/`.inf`/`.nan`/`+1`/`.5` are rejected;
 *  - invalid UTF-8, BOMs, NULs and lone surrogates are rejected.
 * Problems are coded (machine-readable) and positioned; callers map them to exit code 2.
 */
export const MAX_SAFE = 9007199254740991n;
const CORE_TAGS = new Set(["tag:yaml.org,2002:str", "tag:yaml.org,2002:int", "tag:yaml.org,2002:float", "tag:yaml.org,2002:bool", "tag:yaml.org,2002:null", "tag:yaml.org,2002:map", "tag:yaml.org,2002:seq"]);
const JSON_NUMBER = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/;

/**
 * Exact analysis of a decimal numeric literal's source text: true when its mathematical value is an integer whose magnitude
 * exceeds MAX_SAFE, however it is spelled. Fractional values are never flagged. Returns null for non-decimal literals.
 */
export function isUnsafeIntegerLiteral(src) {
  const m = /^[+-]?(\d*)(?:\.(\d*))?(?:[eE]([+-]?\d+))?$/.exec(src);
  if (!m || (m[1] === "" && (m[2] ?? "") === "")) return null;
  let digits = (m[1] ?? "") + (m[2] ?? "");
  let exp = (m[3] ? parseInt(m[3], 10) : 0) - (m[2]?.length ?? 0);
  digits = digits.replace(/^0+/, "");
  if (digits === "") return false;
  while (digits.endsWith("0")) { digits = digits.slice(0, -1); exp++; }
  if (exp < 0) return false;
  if (digits.length + exp > 17) return true;
  return BigInt(digits) * 10n ** BigInt(exp) > MAX_SAFE;
}

const wellFormed = (s) => (typeof s.isWellFormed === "function" ? s.isWellFormed() : !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s));
const lineCol = (text, offset) => { const before = text.slice(0, offset); return { line: before.split("\n").length, column: offset - before.lastIndexOf("\n") }; };
const at = (p) => (p.line ? `line ${p.line}, column ${p.column}` : "unknown position");

export function parseYamlStrict(text) {
  const problems = [];
  const add = (code, message, offset) => problems.push({ code, message, ...(offset === undefined ? {} : lineCol(text, offset)) });
  const nul = text.indexOf("\0");
  if (nul >= 0) add("nul-byte", "NUL characters are not allowed", nul);

  const doc = parseDocument(text, { schema: "core", version: "1.2", intAsBigInt: true, keepSourceTokens: true, merge: false, uniqueKeys: true });
  for (const e of doc.errors) {
    const code = e.code === "DUPLICATE_KEY" ? "yaml-duplicate-key" : e.code === "MULTIPLE_DOCS" ? "yaml-multiple-documents" : "yaml-invalid";
    const p = e.linePos?.[0];
    problems.push({ code, message: code === "yaml-invalid" ? `invalid YAML: ${e.message.split("\n")[0]}` : e.message.split("\n")[0].replace(/ at line.*/, "") + (p ? ` at line ${p.line}, column ${p.col}` : ""), ...(p ? { line: p.line, column: p.col } : {}) });
  }
  if (problems.length) throw new InputError(problems);
  for (const w of doc.warnings) problems.push({ code: w.code === "TAG_RESOLVE_FAILED" || /tag/i.test(w.message) ? "yaml-unsupported-tag" : "yaml-invalid", message: `unsupported or ambiguous YAML construct: ${w.message.split("\n")[0]}`, ...(w.linePos?.[0] ? { line: w.linePos[0].line, column: w.linePos[0].col } : {}) });

  // NOTE: the library calls the most specific visitor only, so the anchor/tag checks run from each node-kind visitor.
  const checkNode = (node) => {
    if (node.anchor) add("yaml-anchor", `anchors are not allowed (&${node.anchor})`, node.range?.[0]);
    if (node.tag && !CORE_TAGS.has(node.tag)) add("yaml-unsupported-tag", `unsupported YAML tag '${node.tag}'`, node.range?.[0]);
  };
  visit(doc, {
    Alias(_, node) { add("yaml-alias", "aliases are not allowed", node.range?.[0]); },
    Collection(_, node) { checkNode(node); },
    Pair(_, pair) {
      const k = pair.key;
      if (!isScalar(k) || typeof k.value !== "string") { add("yaml-non-string-key", "mapping keys must be strings", k?.range?.[0]); return; }
      if (k.type === "PLAIN" && k.value === "<<") add("yaml-merge-key", "merge keys (<<) are not allowed", k.range?.[0]);
    },
    Scalar(_, node) {
      checkNode(node);
      const v = node.value;
      const off = node.range?.[0];
      if (typeof v === "string") {
        if (!wellFormed(v)) add("lone-surrogate", "string contains a lone surrogate", off);
        if (v.includes("\0")) add("nul-byte", "NUL characters are not allowed", off);
        return;
      }
      if (typeof v === "bigint" || typeof v === "number") {
        const src = typeof node.source === "string" ? node.source : String(v);
        const pos = node.range ? lineCol(text, off) : {};
        if (typeof v === "number" && !Number.isFinite(v)) { add("yaml-non-finite-number", `non-finite number '${src}' at ${at(pos)} is not allowed`, off); return; }
        if (!JSON_NUMBER.test(src)) { add("yaml-number-not-json", `number literal '${src}' at ${at(pos)} is not a JSON-compatible decimal`, off); return; }
        if (typeof v === "bigint") {
          if (v > MAX_SAFE || v < -MAX_SAFE) add("yaml-unsafe-integer", `numeric literal '${src}' at ${at(pos)} is an integer outside the safe range (±${MAX_SAFE}); quote it as a string`, off);
          else node.value = Number(v);
        } else if (isUnsafeIntegerLiteral(src)) add("yaml-unsafe-integer", `numeric literal '${src}' at ${at(pos)} is an integer-valued number outside the safe range (±${MAX_SAFE}); quote it as a string`, off);
      }
    },
  });
  if (problems.length) throw new InputError([...new Map(problems.map((p) => [p.message, p])).values()]);
  return doc.toJS();
}

/** Decode bytes as text: fatal UTF-8 decoding, no BOM, no NUL, no CR (manifests are LF-only). Throws coded InputErrors. */
export function decodeTextStrict(buf) {
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(buf); }
  catch { throw new InputError({ code: "utf8-invalid", message: "not valid UTF-8" }); }
  if (text.charCodeAt(0) === 0xfeff) throw new InputError({ code: "utf8-bom", message: "UTF-8 BOM not allowed" });
  const nul = text.indexOf("\0");
  if (nul >= 0) throw new InputError({ code: "nul-byte", message: "NUL characters are not allowed", ...lineCol(text, nul) });
  const cr = text.indexOf("\r");
  if (cr >= 0) throw new InputError({ code: "line-ending-cr", message: "CR characters not allowed (LF line endings only)", ...lineCol(text, cr) });
  return text;
}

export const readTextStrict = (path) => decodeTextStrict(readFileSync(path));
export const readYamlStrict = (path) => parseYamlStrict(readTextStrict(path));

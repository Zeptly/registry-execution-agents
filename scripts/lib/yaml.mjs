import { readFileSync } from "node:fs";
import { parseDocument, visit } from "yaml";

/** Largest magnitude of an integer that IEEE-754 doubles represent exactly (2^53 - 1). */
export const MAX_SAFE = 9007199254740991n;

/**
 * Exact analysis of a decimal numeric literal's source text: true when its mathematical value is an
 * integer whose magnitude exceeds MAX_SAFE (so a double cannot hold it exactly), however it is spelled
 * (`9007199254740993`, `9007199254740993.0`, `1e21`, `90071992547409930e-1`). Fractional values are never flagged.
 */
export function isUnsafeIntegerLiteral(src) {
  const m = /^[+-]?(\d*)(?:\.(\d*))?(?:[eE]([+-]?\d+))?$/.exec(src);
  if (!m || (m[1] === "" && (m[2] ?? "") === "")) return null; // not a plain decimal literal: caller falls back to value checks
  let digits = (m[1] ?? "") + (m[2] ?? "");
  let exp = (m[3] ? parseInt(m[3], 10) : 0) - (m[2]?.length ?? 0);
  digits = digits.replace(/^0+/, "");
  if (digits === "") return false; // zero
  while (digits.endsWith("0")) { digits = digits.slice(0, -1); exp++; }
  if (exp < 0) return false; // has a fractional part
  if (digits.length + exp > 17) return true; // 10^16 already exceeds 2^53 - 1
  return BigInt(digits) * 10n ** BigInt(exp) > MAX_SAFE;
}

const position = (text, offset) => {
  const before = text.slice(0, offset);
  return `line ${before.split("\n").length}, column ${offset - before.lastIndexOf("\n")}`;
};

/**
 * YAML parser used for every YAML file the registry reads. YAML 1.2 core schema, single document, duplicate keys
 * rejected, plus: integer-valued numbers outside the safe integer range are REJECTED at the source literal (before a
 * double can round them), including exponent and decimal-point spellings. Fractional numbers behave as before.
 */
export function parseYamlStrict(text) {
  const doc = parseDocument(text, { intAsBigInt: true, keepSourceTokens: true });
  if (doc.errors.length) throw new Error(`invalid YAML: ${doc.errors[0].message.split("\n")[0]}`);
  const problems = [];
  visit(doc, {
    Scalar(_, node) {
      const v = node.value;
      const at = () => (node.range ? position(text, node.range[0]) : "unknown position");
      if (typeof v === "bigint") {
        if (v > MAX_SAFE || v < -MAX_SAFE) problems.push(`numeric literal '${node.source}' at ${at()} is an integer outside the safe range (±${MAX_SAFE}); quote it as a string`);
        else node.value = Number(v);
      } else if (typeof v === "number" && Number.isFinite(v)) {
        const src = typeof node.source === "string" ? node.source : String(v);
        const unsafe = isUnsafeIntegerLiteral(src) ?? (Number.isInteger(v) && !Number.isSafeInteger(v));
        if (unsafe) problems.push(`numeric literal '${src}' at ${at()} is an integer-valued number outside the safe range (±${MAX_SAFE}); quote it as a string`);
      }
    },
  });
  if (problems.length) throw new Error(problems.join("; "));
  return doc.toJS();
}

/** Read a file as text: fatal UTF-8 decoding and no BOM (same policy as payload files). Throws controlled errors. */
export function readTextStrict(path) {
  const buf = readFileSync(path);
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(buf); }
  catch { throw new Error("not valid UTF-8"); }
  if (text.charCodeAt(0) === 0xfeff) throw new Error("UTF-8 BOM not allowed");
  return text;
}

export const readYamlStrict = (path) => parseYamlStrict(readTextStrict(path));

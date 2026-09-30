import canonicalize from "canonicalize";
import { InputError } from "./diag.mjs";

/**
 * Canonical JSON = RFC 8785 (JCS), produced by the `canonicalize` package (the RFC author's reference implementation):
 * UTF-16 code-unit key ordering, ECMAScript number and string serialization, no Unicode normalization, no whitespace.
 * Protocol v0.2 input restrictions are enforced BEFORE serialization so the library never silently drops or coerces values:
 * undefined, functions, symbols, BigInt, NaN/±Infinity, lone surrogates and non-plain objects are rejected.
 * Strings are serialized exactly as parsed (no line-ending normalization).
 */
const wellFormed = (s) => (typeof s.isWellFormed === "function" ? s.isWellFormed() : !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s));

export function assertJcsInput(v, path = "$") {
  const bad = (code, message) => { throw new InputError({ code, message: `${path}: ${message}` }); };
  if (v === null) return;
  switch (typeof v) {
    case "boolean": return;
    case "number": if (!Number.isFinite(v)) bad("non-finite-number", "non-finite numbers cannot be canonicalized"); return;
    case "string": if (!wellFormed(v)) bad("lone-surrogate", "string contains a lone surrogate"); return;
    case "object": {
      if (Array.isArray(v)) { v.forEach((x, i) => assertJcsInput(x, `${path}[${i}]`)); return; }
      const proto = Object.getPrototypeOf(v);
      if (proto !== Object.prototype && proto !== null) bad("jcs-unsupported-value", "non-plain objects cannot be canonicalized");
      for (const k of Object.keys(v)) { if (!wellFormed(k)) bad("lone-surrogate", `key ${JSON.stringify(k)} contains a lone surrogate`); assertJcsInput(v[k], `${path}.${k}`); }
      return;
    }
    default: bad("jcs-unsupported-value", `unsupported type ${typeof v}`);
  }
}

export function canonicalJson(v) {
  assertJcsInput(v);
  const s = canonicalize(v);
  if (typeof s !== "string") throw new InputError({ code: "jcs-unsupported-value", message: "value cannot be canonicalized" });
  return s;
}

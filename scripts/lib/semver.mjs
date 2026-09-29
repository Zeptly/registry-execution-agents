// Minimal semver: exact versions plus ^ and ~ ranges. No external dependency.
const RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*))?$/;

export function parse(v) {
  const m = RE.exec(v);
  if (!m) throw new Error(`invalid semver: ${v}`);
  return { major: +m[1], minor: +m[2], patch: +m[3], pre: m[4] ? m[4].split(".") : [] };
}

function cmpPre(a, b) {
  if (!a.length && !b.length) return 0;
  if (!a.length) return 1;
  if (!b.length) return -1;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if (a[i] === undefined) return -1;
    if (b[i] === undefined) return 1;
    const an = /^\d+$/.test(a[i]), bn = /^\d+$/.test(b[i]);
    if (an && bn) { if (+a[i] !== +b[i]) return +a[i] < +b[i] ? -1 : 1; }
    else if (an !== bn) return an ? -1 : 1;
    else if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}

export function compare(a, b) {
  const x = parse(a), y = parse(b);
  for (const k of ["major", "minor", "patch"]) if (x[k] !== y[k]) return x[k] < y[k] ? -1 : 1;
  return cmpPre(x.pre, y.pre);
}

export const isExact = (spec) => RE.test(spec);

export function satisfies(version, spec) {
  if (isExact(spec)) return compare(version, spec) === 0;
  const base = spec.slice(1);
  const b = parse(base);
  if (compare(version, base) < 0) return false;
  const v = parse(version);
  if (spec[0] === "~") return v.major === b.major && v.minor === b.minor;
  if (b.major > 0) return v.major === b.major;
  if (b.minor > 0) return v.major === 0 && v.minor === b.minor;
  return v.major === 0 && v.minor === 0 && v.patch === b.patch;
}

/** Which component changed going from `from` to `to` (highest wins). */
export function bumpKind(from, to) {
  const a = parse(from), b = parse(to);
  if (b.major !== a.major) return "major";
  if (b.minor !== a.minor) return "minor";
  if (b.patch !== a.patch) return "patch";
  return "none";
}
export const RANK = { none: 0, patch: 1, minor: 2, major: 3 };

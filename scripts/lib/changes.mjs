import { compare, bumpKind, RANK } from "./semver.mjs";
import { definitionDigest, resolveSchema } from "./registry.mjs";

// Allowed status transitions (same-status is always allowed).
export const TRANSITIONS = {
  draft: ["candidate", "active", "retired"],
  candidate: ["draft", "active", "retired"],
  active: ["deprecated"],
  deprecated: ["active", "retired"],
  retired: [],
};

const props = (s) => Object.keys(s?.properties ?? {});
const req = (s) => new Set(s?.required ?? []);

/** Heuristic: is the head contract a breaking change relative to base? */
export function contractChange(b, h) {
  const bi = resolveSchema(b.manifest.contract.input, b.dir), hi = resolveSchema(h.manifest.contract.input, h.dir);
  const bo = resolveSchema(b.manifest.contract.output, b.dir), ho = resolveSchema(h.manifest.contract.output, h.dir);
  const why = [];
  for (const p of req(hi)) if (!req(bi).has(p)) why.push(`input: '${p}' became required`);
  for (const p of props(bi)) if (!props(hi).includes(p)) why.push(`input: property '${p}' removed`);
  for (const p of props(bo)) if (!props(ho).includes(p)) why.push(`output: property '${p}' removed`);
  for (const p of req(bo)) if (!req(ho).has(p) && props(bo).includes(p)) why.push(`output: '${p}' no longer guaranteed`);
  if (bi.type !== hi.type || bo.type !== ho.type) why.push("top-level contract type changed");
  const changed = JSON.stringify(bi) !== JSON.stringify(hi) || JSON.stringify(bo) !== JSON.stringify(ho);
  return { breaking: why, changed };
}

const SIDE = { none: 0, reversible: 1, irreversible: 2 };
const EGRESS = { none: 0, declared_capabilities_only: 1 };

export function permissionExpansion(bm, hm) {
  const why = [];
  const bs = new Set(bm.permissions.scopes);
  for (const s of hm.permissions.scopes) if (!bs.has(s)) why.push(`scope added: ${s}`);
  if (SIDE[hm.permissions.side_effects] > SIDE[bm.permissions.side_effects]) why.push("side_effects raised");
  if (EGRESS[hm.permissions.egress.mode] > EGRESS[bm.permissions.egress.mode]) why.push("egress broadened");
  if (bm.security.classification !== hm.security.classification) why.push("classification changed");
  const bt = new Map((bm.tools ?? []).map((t) => [t.id, t]));
  for (const t of hm.tools ?? []) {
    const o = bt.get(t.id);
    if (!o) { if ((t.side_effects ?? "none") !== "none") why.push(`side-effecting tool added: ${t.id}`); continue; }
    if (o.requires_approval && !t.requires_approval) why.push(`approval removed from ${t.id}`);
  }
  for (const s of hm.security.secret_refs ?? []) if (!(bm.security.secret_refs ?? []).includes(s)) why.push(`secret added: ${s}`);
  return why;
}

/** Enforce rules between the base and head state of one agent. Returns string[]. */
export function checkAgentChange(b, h) {
  const errs = [];
  const bm = b.manifest, hm = h.manifest;
  if (!bm || !hm) return errs;
  if (bm.id !== hm.id) return [`id changed from ${bm.id} to ${hm.id}; ids are permanent`];

  // Release ledger is append-only.
  const bl = b.releases?.releases ?? [], hl = h.releases?.releases ?? [];
  bl.forEach((r, i) => {
    if (JSON.stringify(hl[i]) !== JSON.stringify(r)) errs.push(`releases.yaml entry ${r.version} was modified or removed; the ledger is append-only`);
  });

  // Lifecycle transition.
  if (bm.status !== hm.status && !TRANSITIONS[bm.status].includes(hm.status))
    errs.push(`illegal status transition ${bm.status} -> ${hm.status} (allowed: ${TRANSITIONS[bm.status].join(", ") || "none"})`);

  const bd = definitionDigest(bm, b.dir), hd = definitionDigest(hm, h.dir);
  const released = bl.find((r) => r.version === bm.version);
  if (hm.version === bm.version) {
    if (released && bd !== hd) errs.push(`definition of released ${bm.id}@${bm.version} changed without a version bump (immutable)`);
    return errs;
  }
  if (compare(hm.version, bm.version) < 0) errs.push(`version decreased ${bm.version} -> ${hm.version}`);
  if (bm.status === "retired") errs.push(`retired agents cannot change`);
  if (bd === hd) return errs;

  // Required minimum bump.
  const actual = bumpKind(bm.version, hm.version);
  const { breaking, changed } = contractChange(b, h);
  const expansion = permissionExpansion(bm, hm);
  let need = "patch", reasons = [];
  if (changed) { need = "minor"; reasons.push("contract changed"); }
  if (expansion.length) { need = "minor"; reasons.push(...expansion); }
  if (JSON.stringify(bm.purpose) !== JSON.stringify(hm.purpose)) { need = "major"; reasons.push("purpose changed"); }
  if (breaking.length) { need = "major"; reasons.push(...breaking); }
  if (RANK[actual] < RANK[need] && !(bm.version.startsWith("0.") && RANK[actual] >= RANK.minor))
    errs.push(`${bm.version} -> ${hm.version} is a ${actual} bump but changes require at least ${need}: ${reasons.join("; ")}`);
  if (expansion.length && !hm.security.review?.security_review_required)
    errs.push(`permission/security expansion (${expansion.join("; ")}) requires security.review.security_review_required: true`);
  return errs;
}

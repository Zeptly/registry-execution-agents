import { computeSeal, TREES } from "./core.mjs";

const keyOf = (o) => `${o.artifact.metadata.id}@${o.artifact.metadata.version}`;
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/**
 * Compare a base domain with the head domain and enforce immutability:
 * objects are never deleted or moved across domains, content digests never change, canonical never
 * reverts to candidate, attestations/approvals and lifecycle events are append-only.
 */
export function checkDomainChange(base, head) {
  const errs = [];
  const heads = new Map(head.objects.filter((o) => o.artifact).map((o) => [keyOf(o), o]));
  for (const b of base.objects.filter((o) => o.artifact)) {
    const k = keyOf(b), h = heads.get(k);
    if (!h) { errs.push(`${k}: removed or moved out of this domain; published objects are never deleted (revoke via the lifecycle overlay)`); continue; }
    const bs = computeSeal(b.artifact, b.dir), hs = computeSeal(h.artifact, h.dir);
    if (bs.artifactDigest !== hs.artifactDigest) errs.push(`${k}: content digest changed (artifact ${bs.artifactDigest} -> ${hs.artifactDigest}); published versions are immutable, publish a new version`);
    if (bs.sealDigest !== hs.sealDigest) errs.push(`${k}: content digest changed (payload/seal ${bs.sealDigest} -> ${hs.sealDigest}); published versions are immutable, publish a new version`);
    if (b.seal && h.seal && (b.seal.artifactDigest !== h.seal.artifactDigest || b.seal.sealDigest !== h.seal.sealDigest)) errs.push(`${k}: seal digest changed in seal.yaml`);
    if (b.tree === TREES.canonical && h.tree !== TREES.canonical) errs.push(`${k}: canonical objects cannot revert to candidate`);
    if (!same(b.artifact.metadata.origin, h.artifact.metadata.origin)) errs.push(`${k}: origin changed`);
    for (const f of ["attestations"]) b.artifact[f].forEach((x, i) => { if (!h.artifact[f].some((y) => same(x, y))) errs.push(`${k}: ${f}[${i}] was modified or removed (append-only)`); });
    b.artifact.security.approvals.forEach((x, i) => { if (!h.artifact.security.approvals.some((y) => same(x, y))) errs.push(`${k}: security.approvals[${i}] was modified or removed (append-only)`); });
  }
  const hOv = new Map(head.overlays.filter((o) => o.overlay).map((o) => [o.name, o.overlay]));
  for (const b of base.overlays.filter((o) => o.overlay)) {
    const h = hOv.get(b.name);
    if (!h) { errs.push(`lifecycle/${b.name}: removed; overlays are append-only`); continue; }
    b.overlay.events.forEach((e, i) => { if (!same(e, h.events[i])) errs.push(`lifecycle/${b.name}: event ${i} was modified, removed or reordered (append-only)`); });
  }
  return errs;
}

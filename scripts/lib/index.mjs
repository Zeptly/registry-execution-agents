import { relative } from "node:path";
import { compare } from "./semver.mjs";
import { effectiveLifecycle, computeSeal, toPosix, REPO_ROOT, API_VERSION, REGISTRY, KIND } from "./core.mjs";

/** Deterministic derived index for one domain (no timestamps; stable ordering). */
export function buildIndex(domain, domainName) {
  const entries = domain.objects.map((o) => {
    const a = o.artifact, m = a.metadata;
    const digest = computeSeal(a, o.dir).digest;
    const origin = { type: m.origin.type };
    if (m.origin.evolution) origin.evolutionKind = m.origin.evolution.kind;
    return {
      kind: KIND, id: m.id, version: m.version, digest, maturity: m.maturity,
      lifecycle: effectiveLifecycle(domain.overlays, m.id, m.version, digest),
      origin, location: toPosix(relative(REPO_ROOT, o.dir)),
    };
  }).sort((x, y) => x.id.localeCompare(y.id) || compare(x.version, y.version));
  return { apiVersion: API_VERSION, kind: "RegistryIndex", registry: REGISTRY, domain: domainName, entries };
}

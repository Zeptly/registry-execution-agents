import { relative } from "node:path";
import { compare } from "./semver.mjs";
import { effectiveLifecycle, computeSeal, toPosix, compareCodePoints, REPO_ROOT, API_VERSION, REGISTRY, KIND } from "./core.mjs";

/** Deterministic derived index for one domain: no timestamps or commit ids; entries ordered by code-point id, SemVer, code-point digest. */
export function buildIndex(domain, domainName) {
  const broken = domain.objects.filter((o) => !o.artifact);
  if (broken.length) throw new Error(`cannot index unreadable artifacts: ${broken.map((o) => `${o.dir} (${o.loadErrors?.join("; ") || "missing artifact.yaml"})`).join(", ")}`);
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
  }).sort((x, y) => compareCodePoints(x.id, y.id) || compare(x.version, y.version) || compareCodePoints(x.digest, y.digest));
  return { apiVersion: API_VERSION, kind: "RegistryIndex", registry: REGISTRY, domain: domainName, entries };
}

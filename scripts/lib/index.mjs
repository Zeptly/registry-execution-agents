import { relative } from "node:path";
import { compare } from "./semver.mjs";
import { effectiveLifecycle, computeSeal, toPosix, compareCodePoints, REPO_ROOT, API_VERSION, REGISTRY, KIND, DIGEST_ALGORITHM } from "./core.mjs";

/**
 * Deterministic derived index for one domain (Protocol v0.2): no timestamps or commit ids; entries ordered by Unicode code-point `id`,
 * then SemVer precedence, then `artifactDigest` (then `sealDigest`). JSON canonicalization (JCS, UTF-16 key order) is a separate rule.
 * `artifactDigest` is the pin target for references and a RuntimeLock `subject.digest`; `sealDigest` is the directory seal.
 */
export function buildIndex(domain, domainName) {
  const broken = domain.objects.filter((o) => !o.artifact);
  if (broken.length) throw new Error(`cannot index unreadable artifacts: ${broken.map((o) => `${o.dir} (${o.loadErrors?.map(String).join("; ") || "missing artifact.yaml"})`).join(", ")}`);
  const entries = domain.objects.map((o) => {
    const a = o.artifact, m = a.metadata;
    const { artifactDigest, sealDigest } = computeSeal(a, o.dir);
    const origin = { type: m.origin.type };
    if (m.origin.evolution) origin.evolutionKind = m.origin.evolution.kind;
    return {
      kind: KIND, registry: m.registry, id: m.id, version: m.version, artifactDigest, sealDigest, digestAlgorithm: DIGEST_ALGORITHM,
      maturity: m.maturity, lifecycle: effectiveLifecycle(domain.overlays, m.id, m.version, artifactDigest), origin, location: toPosix(relative(REPO_ROOT, o.dir)),
    };
  }).sort((x, y) => compareCodePoints(x.id, y.id) || compare(x.version, y.version) || compareCodePoints(x.artifactDigest, y.artifactDigest) || compareCodePoints(x.sealDigest, y.sealDigest));
  return { apiVersion: API_VERSION, kind: "RegistryIndex", registry: REGISTRY, domain: domainName, digestAlgorithm: DIGEST_ALGORITHM, entries };
}

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { compare, isExact, satisfies } from "./semver.mjs";
import {
  computeSeal, fmtErrors, readYaml, resolveSchema, payloadFiles, effectiveLifecycle,
  TREES, REGISTRY, KIND, API_VERSION, DIGEST_ALGORITHM,
} from "./core.mjs";
import { toDiag } from "./diag.mjs";
import { scanVersionDir, scanPayloadContent, stringFindings } from "./files.mjs";

const SYNTH = "synthetic.";
const SYNTH_EVIDENCE = "evidence://synthetic/";

function walk(v, path, fn) {
  fn(v, path);
  if (Array.isArray(v)) v.forEach((x, i) => walk(x, `${path}[${i}]`, fn));
  else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) walk(x, `${path}.${k}`, fn);
}

/** Every {registry, id} structured reference anywhere in the artifact. */
export function collectRefs(a) {
  const out = [];
  walk(a, "$", (v, path) => { if (v && typeof v === "object" && !Array.isArray(v) && typeof v.registry === "string" && typeof v.id === "string") out.push([path, v]); });
  return out.filter(([p]) => !p.startsWith("$.metadata"));
}

/** Every evidence pointer in an artifact, with its path. */
export function collectEvidencePointers(a) {
  const out = [];
  a.attestations.forEach((x, i) => out.push([`attestations[${i}].ref`, x.ref]));
  a.security.approvals.forEach((x, i) => { if (x.ref) out.push([`security.approvals[${i}].ref`, x.ref]); });
  a.provenance.sourceRefs.forEach((x, i) => { if (x.evidence) out.push([`provenance.sourceRefs[${i}].evidence`, x.evidence]); });
  (a.metadata.origin.evolution?.sourceRefs ?? []).forEach((x, i) => { if (x.evidence) out.push([`metadata.origin.evolution.sourceRefs[${i}].evidence`, x.evidence]); });
  return out;
}

const key = (r) => `${r.registry}/${r.id}`;

/** Rules that need only the object itself. */
function objectRules(o, v, errs, name) {
  const a = o.artifact, s = a.spec, m = a.metadata, dir = o.dir;
  const err = (x) => errs.push(x);
  const canonical = m.maturity === "canonical";

  // payload files & contracts
  const files = new Set(payloadFiles(dir));
  const need = [s.instructions.file, ...["input", "output"].map((k) => s.contract[k].schemaFile), ...s.evaluation.suites.map((x) => x.file)].filter(Boolean);
  for (const f of need) if (!files.has(f)) err(`referenced file missing: ${f}`);
  const cajv = new Ajv2020({ strict: false, allErrors: true });
  addFormats(cajv);
  const contracts = {};
  for (const k of ["input", "output"]) {
    try { contracts[k] = cajv.compile(resolveSchema(s.contract[k], dir)); }
    catch (e) { err(`spec.contract.${k} is not a valid JSON Schema: ${e.message}`); }
  }
  for (const su of s.evaluation.suites) {
    const p = join(dir, su.file);
    if (!existsSync(p)) continue;
    let suite;
    try { suite = readYaml(p); } catch (e) { err(`${su.file}: unparseable YAML: ${e.message}`); continue; }
    if (!v.evalSuite(suite)) { fmtErrors(v.evalSuite.errors).forEach((e) => err(`${su.file}: ${e}`)); continue; }
    if (suite.id !== su.id) err(`${su.file}: suite id '${suite.id}' != declared '${su.id}'`);
    if (contracts.input)
      for (const c of suite.cases)
        if (!contracts.input(c.input)) err(`${su.file}: case '${c.id}' input violates spec.contract.input: ${fmtErrors(contracts.input.errors).join("; ")}`);
  }

  // file policy (allow-list, size limits, symlinks) and payload content scans (endpoints, secrets, runtime records)
  scanVersionDir(dir).errors.forEach(err);
  scanPayloadContent(dir, [...files]).forEach(err);

  // no endpoints / credentials anywhere in the artifact (only JSON Schema `$schema` meta-schema ids are exempt)
  walk(a, "$", (val, path) => { if (typeof val === "string") stringFindings(val, path).forEach(err); });

  // evidence pointer restrictions: synthetic evidence only in the synthetic domain, never in production
  for (const [path, ptr] of collectEvidencePointers(a)) {
    if (name === "synthetic" && !ptr.startsWith(SYNTH_EVIDENCE)) err(`${path}: synthetic artifacts may only use '${SYNTH_EVIDENCE}…' evidence pointers, got '${ptr}'`);
    if (name !== "synthetic" && ptr.startsWith(SYNTH_EVIDENCE)) err(`${path}: production artifacts cannot cite synthetic evidence '${ptr}'`);
  }

  // references
  const seen = new Set();
  for (const r of a.references) {
    if (seen.has(key(r))) err(`duplicate reference ${key(r)}`);
    seen.add(key(r));
    if (canonical) {
      if (!isExact(r.version)) err(`canonical artifact: reference ${key(r)} must pin an exact version, got '${r.version}'`);
      if (!r.digest) err(`canonical artifact: reference ${key(r)} must carry a digest`);
    }
  }
  for (const [path, r] of collectRefs(a)) {
    if (path.startsWith("$.references") || path.includes("sourceRefs")) continue;
    if (canonical && r.version && !isExact(r.version)) err(`canonical artifact: ${path} must pin an exact version`);
  }

  // publication marker and synthetic marker
  if (m.lifecycle !== "active") err(`metadata.lifecycle is a publication marker and must be 'active'; record deprecation or revocation in the lifecycle overlay`);
  if (name === "synthetic" && a.provenance.synthetic !== true) err(`synthetic artifacts must carry the explicit synthetic marker provenance.synthetic: true`);
  if (name !== "synthetic" && a.provenance.synthetic !== undefined) err(`production artifacts cannot carry a synthetic marker (provenance.synthetic)`);

  // provenance/origin
  const o2 = m.origin;
  if (!["evolved", "discovered", "refined"].includes(o2.type) && o2.evolution) err(`origin.evolution is only valid for origin.type 'evolved', 'discovered' or 'refined'`);
  if (o2.type !== "upstream-seed" && o2.import) err(`origin.import is only valid for origin.type 'upstream-seed'`);
  if (o2.type === "evolved") {
    if (!o2.evolution.sourceRefs.some((r) => r.evidence && r.role === "motivates")) err(`origin.evolution needs at least one evidence source with role 'motivates'`);
    const lineage = o2.evolution.sourceRefs.filter((r) => r.registry === REGISTRY && r.id === m.id);
    if (!lineage.length) err(`origin.evolution.sourceRefs must include the ${REGISTRY} version this was evolved from`);
    for (const r of lineage) if (compare(r.version, m.version) >= 0) err(`evolved-from version ${r.version} must be lower than ${m.version}`);
  }

  // policy coherence (class-specific semantics preserved)
  const t = s.timeoutPolicy, cp = s.checkpointPolicy, rp = s.retryPolicy, perm = s.permissions, dh = s.dataHandling, sec = a.security;
  if (t.stepSeconds > t.runSeconds) err(`timeoutPolicy.stepSeconds exceeds runSeconds`);
  if (t.toolCallSeconds > t.runSeconds) err(`timeoutPolicy.toolCallSeconds exceeds runSeconds`);
  if (cp.strategy === "interval" && !cp.intervalSeconds) err(`checkpointPolicy.intervalSeconds required for strategy 'interval'`);
  if (cp.strategy === "none" && (cp.resumable || cp.rollback?.supported)) err(`checkpointPolicy: resumable/rollback require a strategy other than 'none'`);
  if (t.onTimeout === "checkpoint_and_suspend" && cp.strategy === "none") err(`timeoutPolicy.onTimeout 'checkpoint_and_suspend' requires checkpointing`);
  if (rp.maxAttempts > 1 && s.executionPolicy.idempotency === "none" && perm.sideEffects !== "none") err(`retries with side effects require executionPolicy.idempotency other than 'none'`);
  if (rp.retryOn?.some((x) => rp.neverRetryOn?.includes(x))) err(`retryOn and neverRetryOn overlap`);
  if (s.state.persistence === "none" && s.state.stores?.length) err(`state.stores declared but persistence is 'none'`);
  if (s.observability.evidence.recordTape && !s.observability.evidence.tapeIncludes?.length) err(`observability.evidence.tapeIncludes required when recordTape is true`);
  if (cp.rollback?.supported && perm.sideEffects === "irreversible" && (cp.rollback.compensation ?? "none") === "none") err(`rollback.supported with irreversible side effects needs compensation 'tool_declared' or 'manual'`);
  const rank = { none: 0, reversible: 1, irreversible: 2 };
  for (const tool of s.tools ?? []) {
    const se = tool.sideEffects ?? "none";
    if (se === "irreversible" && !tool.requiresApproval) err(`tool '${tool.ref.id}' has irreversible side effects and must set requiresApproval: true`);
    if (rank[se] > rank[perm.sideEffects]) err(`permissions.sideEffects is lower than tool '${tool.ref.id}' side effects`);
    if (tool.capability && !sec.capabilities.some((c) => key(c) === key(tool.capability))) err(`tool '${tool.ref.id}' references capability ${key(tool.capability)} not declared in security.capabilities`);
  }
  if (perm.sideEffects === "irreversible" && !perm.runtimeApprovals?.length) err(`irreversible side effects require at least one permissions.runtimeApprovals entry`);
  if (perm.sideEffects !== "none" && perm.scopes.every((x) => x.endsWith(":read"))) err(`side effects declared but no write/admin scope`);
  if (perm.egress.mode === "none" && sec.capabilities.length) err(`egress mode 'none' conflicts with declared security.capabilities`);
  if (["confidential", "restricted"].includes(sec.classification) && dh.redactInEvidence === false) err(`classification '${sec.classification}' requires redactInEvidence`);
  if (sec.classification === "restricted" && s.executionPolicy.humanInTheLoop === "never") err(`classification 'restricted' cannot use humanInTheLoop: never`);
  if (dh.processesPii && dh.redactInEvidence === false) err(`artifacts processing PII must redactInEvidence`);
  if (s.state.stores?.some((x) => x.containsPii) && !dh.processesPii) err(`a state store contains PII but dataHandling.processesPii is false`);
  if (!Object.keys(s.tools ?? []).length && s.executionPolicy.mode === "agent_loop") { /* tool-less loops are allowed */ }

  // canonical maturity gates (promotion requirements)
  if (canonical) {
    if (!s.evaluation.suites.some((x) => x.required)) err(`canonical artifacts need at least one required evaluation suite`);
    if (s.observability.tracing === "off") err(`canonical artifacts must not disable tracing`);
    if (m.origin.type === "evolved" && sec.classification !== "public" && !s.evaluation.promotionGates.humanApproval) err(`canonical evolved artifacts of non-public agents require promotionGates.humanApproval`);
  }
}

/** Seal, attestation and approval binding for one object. Returns { artifact, seal } (the recomputed digests) or null. */
function sealRules(o, v, errs) {
  const err = (x) => errs.push(x);
  if (!o.seal) { if (!o.loadErrors?.some((e) => e.file === "seal.yaml")) err(`missing seal.yaml (run: node scripts/seal.mjs <dir>)`); return null; }
  if (!v.seal(o.seal)) { fmtErrors(v.seal.errors).forEach((e) => err(`seal.yaml: ${e}`)); return null; }
  const actual = computeSeal(o.artifact, o.dir);
  if (o.seal.subject.registry !== o.artifact.metadata.registry || o.seal.subject.id !== o.artifact.metadata.id || o.seal.subject.version !== o.artifact.metadata.version) err(`seal subject does not match artifact identity`);
  if (o.seal.artifactDigest !== actual.artifactDigest) err(`artifact digest mismatch: artifact content changed after sealing (sealed ${o.seal.artifactDigest}, actual ${actual.artifactDigest}); published versions are immutable`);
  if (o.seal.sealDigest !== actual.sealDigest) err(`seal digest mismatch: payload or identity changed after sealing (sealed ${o.seal.sealDigest}, actual ${actual.sealDigest}); published versions are immutable`);
  if (JSON.stringify(o.seal.payload) !== JSON.stringify(actual.payload)) err(`seal payload list/hashes differ from the directory contents`);
  const ad = actual.artifactDigest, sd = actual.sealDigest;
  const stale = (x, label) => {
    if (x.subjectDigest !== ad) err(`${label} (${x.type}) is stale: subjectDigest ${x.subjectDigest} != artifact digest ${ad}`);
    else if (x.sealDigest !== sd) err(`${label} (${x.type}) is stale: sealDigest ${x.sealDigest} != seal digest ${sd}`);
  };
  o.artifact.attestations.forEach((x, i) => stale(x, `attestations[${i}]`));
  o.artifact.security.approvals.forEach((x, i) => stale(x, `security.approvals[${i}]`));
  return { artifact: ad, seal: sd };
}

/** Identity and content digest of a declared evaluation suite as sealed in this version (version from the suite file, digest of its bytes). */
function suiteInfo(o, su) {
  try {
    const sha = computeSeal(o.artifact, o.dir).payload.find((p) => p.path === su.file)?.sha256;
    const suite = readYaml(join(o.dir, su.file));
    return sha && suite?.version ? { version: suite.version, digest: sha } : null;
  } catch { return null; }
}

function promotionGates(o, digests, errs) {
  const a = o.artifact, sec = a.security;
  const bound = (x) => x.subjectDigest === digests.artifact && x.sealDigest === digests.seal;
  // Every required suite needs an explicit 'pass' whose suite identity (id, version, digest) and subject binding match the sealed
  // artifact. A failing result for the current suite blocks outright; missing and inconclusive results never satisfy the gate.
  for (const su of a.spec.evaluation.suites.filter((x) => x.required)) {
    const mine = a.attestations.filter((x) => x.type === "evaluation" && x.suite?.id === su.id && bound(x));
    const info = suiteInfo(o, su);
    if (!mine.length) { errs.push(`canonical artifact lacks a digest-bound 'evaluation' attestation for required suite '${su.id}'`); continue; }
    const current = mine.filter((x) => info && x.suite.version === info.version && x.suite.digest === info.digest);
    if (!current.length) { errs.push(`required suite '${su.id}': evaluation attestations do not match the sealed suite identity (expected version ${info?.version}, digest ${info?.digest}); a result for another suite version or digest does not satisfy promotion`); continue; }
    const results = current.map((x) => x.result);
    if (results.includes("fail")) errs.push(`required suite '${su.id}' has a failing evaluation result bound to this digest; a failed result blocks promotion`);
    else if (!results.includes("pass")) errs.push(`required suite '${su.id}' has no passing evaluation result bound to this digest (results: ${results.join(", ")}); missing or inconclusive results do not satisfy promotion`);
  }
  if (!a.attestations.some((x) => x.type === "security-review" && bound(x))) errs.push(`canonical artifact lacks a digest-bound 'security-review' attestation`);
  if (!sec.approvals.some((x) => x.type === "promotion" && bound(x))) errs.push(`canonical artifact lacks a digest-bound 'promotion' approval`);
  if (["confidential", "restricted"].includes(sec.classification) && !sec.approvals.some((x) => x.type === "security-review" && bound(x)))
    errs.push(`classification '${sec.classification}' requires a digest-bound 'security-review' approval`);
}

const LEGAL = { active: ["deprecated", "revoked"], deprecated: ["active", "revoked"], revoked: [] };

/** Validate one domain. Returns [{path, errors}]. */
export function validateDomain(domain, name, v) {
  const results = [];
  const loaded = domain.objects.map((o) => ({ o, errors: [], digest: null, ok: false }));
  const res = new Map(loaded.map((x) => [x.o.dir, x]));

  for (const x of loaded) {
    const { o, errors } = x;
    o.loadErrors?.forEach((e) => errors.push(e));
    if (!o.artifact) { if (!o.loadErrors?.length) errors.push(`missing artifact.yaml`); continue; }
    if (!v.artifact(o.artifact)) { fmtErrors(v.artifact.errors).forEach((e) => errors.push(`artifact.yaml: ${e}`)); continue; }
    x.ok = true;
    const m = o.artifact.metadata;
    if (o.idDir !== m.id || o.verDir !== m.version) errors.push(`path ${o.idDir}/${o.verDir} must equal metadata.id/version (${m.id}/${m.version})`);
    if ((o.tree === TREES.canonical) !== (m.maturity === "canonical")) errors.push(`metadata.maturity '${m.maturity}' does not match tree '${o.tree}'`);
    // domain isolation
    if (name === "synthetic") {
      if (!m.id.startsWith(SYNTH)) errors.push(`synthetic-domain ids must start with '${SYNTH}'`);
    } else {
      if (m.id.startsWith(SYNTH)) errors.push(`synthetic artifacts cannot exist in the production domain`);
      for (const [p, r] of collectRefs(o.artifact)) if (r.id.startsWith(SYNTH)) errors.push(`${p}: production artifacts cannot reference synthetic '${r.id}'`);
    }
    const dg = sealRules(o, v, errors);
    x.digest = dg?.artifact ?? null; x.sealDigest = dg?.seal ?? null;
    objectRules(o, v, errors, name);
  }

  // cross-object rules
  const valid = loaded.filter((x) => x.ok);
  const byId = new Map();
  for (const x of valid) { const id = x.o.artifact.metadata.id; (byId.get(id) ?? byId.set(id, []).get(id)).push(x); }
  for (const [id, xs] of byId) {
    const canon = xs.filter((x) => x.o.artifact.metadata.maturity === "canonical");
    for (const x of xs) {
      const m = x.o.artifact.metadata;
      const dup = xs.filter((y) => y !== x && y.o.artifact.metadata.version === m.version);
      if (dup.length) x.errors.push(`${id}@${m.version} exists in more than one tree/directory`);
      if (m.maturity === "candidate")
        for (const c of canon) if (compare(m.version, c.o.artifact.metadata.version) <= 0) x.errors.push(`candidate ${m.version} must exceed every canonical version (canonical ${c.o.artifact.metadata.version} exists)`);
    }
  }
  for (const x of valid) {
    const a = x.o.artifact, m = a.metadata;
    const canonical = m.maturity === "canonical";
    // Local reference resolution (structure only elsewhere; only this registry is resolvable offline).
    // 1) EXECUTABLE dependencies (`references[]`): canonical targets only, lifecycle-eligible:
    //    revoked never satisfies; deprecated satisfies an explicit exact pin but is excluded from range selection;
    //    ranges select the highest eligible version. Not enforced for a dependent that is itself revoked.
    const selfLife = x.digest ? effectiveLifecycle(domain.overlays, m.id, m.version, x.digest) : "active";
    for (const r of a.references.filter((q) => q.registry === REGISTRY)) {
      if (r.id === m.id) { x.errors.push(`reference to itself: ${key(r)}`); continue; }
      const exact = isExact(r.version);
      try { satisfies("0.0.0", r.version); } catch { x.errors.push(`invalid range '${r.version}' for reference ${key(r)}`); continue; }
      const matches = (byId.get(r.id) ?? []).filter((t) => t.o.artifact.metadata.maturity === "canonical" && satisfies(t.o.artifact.metadata.version, r.version));
      if (!matches.length) { x.errors.push(`unresolved local reference ${key(r)}@${r.version}${canonical ? " (canonical artifacts may only depend on canonical versions)" : ""}`); continue; }
      const life = (t) => (t.digest ? effectiveLifecycle(domain.overlays, t.o.artifact.metadata.id, t.o.artifact.metadata.version, t.digest) : "active");
      const eligible = matches.filter((t) => life(t) === "active" || (exact && life(t) === "deprecated"));
      if (!eligible.length) {
        if (selfLife !== "revoked") x.errors.push(exact
          ? `executable dependency ${key(r)}@${r.version} is ${life(matches[0])} and cannot satisfy it${life(matches[0]) === "deprecated" ? "" : " (revoked artifacts are never eligible)"}`
          : `no eligible version satisfies executable dependency ${key(r)}@${r.version}: matching versions are ${[...new Set(matches.map(life))].join("/")} (range selection excludes deprecated and revoked)`);
        continue;
      }
      const chosen = [...eligible].sort((p, q) => compare(q.o.artifact.metadata.version, p.o.artifact.metadata.version))[0];
      if (r.digest && exact && chosen.digest && chosen.digest !== r.digest) x.errors.push(`reference ${key(r)}@${r.version} digest mismatch (expected ${chosen.digest})`);
    }
    // 2) LINEAGE (`origin.evolution.sourceRefs`): historical description of an ancestor. Any maturity, any lifecycle
    //    (a revoked ancestor may be described; this never authorizes executing it). Existence and digest are still verified.
    for (const r of (m.origin.evolution?.sourceRefs ?? []).filter((q) => q.registry === REGISTRY)) {
      const target = (byId.get(r.id) ?? []).find((t) => t.o.artifact.metadata.version === r.version);
      if (!target) { x.errors.push(`unresolved lineage reference ${key(r)}@${r.version}`); continue; }
      if (r.digest && target.digest && target.digest !== r.digest) x.errors.push(`lineage reference ${key(r)}@${r.version} digest mismatch (expected ${target.digest})`);
    }
    if (canonical && x.digest) promotionGates(x.o, { artifact: x.digest, seal: x.sealDigest }, x.errors);
  }

  // lifecycle overlays
  const overlayResults = [];
  for (const ov of domain.overlays) {
    const errors = [];
    const o = ov.overlay;
    if (ov.loadErrors?.length) { overlayResults.push({ path: ov.file, errors: ov.loadErrors }); continue; }
    if (!v.lifecycle(o)) fmtErrors(v.lifecycle.errors).forEach((e) => errors.push(e));
    else {
      if (`${o.subject.id}.yaml` !== ov.name) errors.push(`file name must be ${o.subject.id}.yaml`);
      const state = new Map();
      let lastAt = "";
      for (const [i, e] of o.events.entries()) {
        const target = (byId.get(o.subject.id) ?? []).find((t) => t.o.artifact.metadata.version === e.version);
        if (!target) errors.push(`events[${i}]: no artifact ${o.subject.id}@${e.version}`);
        else if (target.digest && target.digest !== e.digest) errors.push(`events[${i}]: digest does not match ${o.subject.id}@${e.version} (${target.digest})`);
        if (e.at < lastAt) errors.push(`events[${i}]: events must be in chronological order (append-only)`);
        lastAt = e.at;
        if (["deprecated", "revoked"].includes(e.state) && !e.reason) errors.push(`events[${i}]: '${e.state}' requires a reason`);
        const k = `${e.version}|${e.digest}`;
        const prev = state.get(k);
        if (prev && !LEGAL[prev].includes(e.state)) errors.push(`events[${i}]: illegal lifecycle transition ${prev} -> ${e.state}`);
        state.set(k, e.state);
      }
    }
    overlayResults.push({ path: ov.file, errors: errors.map((e) => toDiag(e, { file: ov.file })) });
  }

  for (const x of loaded) results.push({ path: x.o.dir, errors: x.errors.map((e) => toDiag(e, { file: x.o.dir })) });
  if (domain.issues?.length) results.push({ path: domain.root, errors: domain.issues.map((e) => toDiag(e, { file: domain.root })) });
  return [...results, ...overlayResults];
}

export { effectiveLifecycle, KIND, API_VERSION };

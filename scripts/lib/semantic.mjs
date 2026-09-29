import { existsSync, readFileSync } from "node:fs";
import { join, basename } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { compare, isExact, satisfies } from "./semver.mjs";
import {
  definitionDigest, definitionFiles, fmtErrors, readYaml, resolveSchema, listAgentDirs, loadAgent,
} from "./registry.mjs";

const RELEASED = new Set(["active", "deprecated", "retired"]);
const SECRET_RE = /(sk-[A-Za-z0-9]{16,}|-----BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{10,})/;
const URL_RE = /https?:\/\//i;

function walkStrings(v, path, fn) {
  if (typeof v === "string") fn(v, path);
  else if (Array.isArray(v)) v.forEach((x, i) => walkStrings(x, `${path}[${i}]`, fn));
  else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) walkStrings(x, `${path}.${k}`, fn);
}

/** Validate a single agent directory. Returns string[] of problems. */
export function validateAgent(agent, v, opts = {}) {
  const errs = [];
  const { dir, manifest: m, releases } = agent;
  const slug = basename(dir);
  const err = (msg) => errs.push(msg);

  if (!m) return [`missing agent.yaml`];
  if (!v.agent(m)) return fmtErrors(v.agent.errors).map((e) => `agent.yaml: ${e}`);

  if (m.id !== `exec.${slug}`) err(`directory name '${slug}' must match id '${m.id}' (expected exec.${slug})`);
  if (opts.forbidCandidates && m.status === "candidate")
    err(`status 'candidate' cannot be merged; promote to 'active' (or 'draft') before merging`);

  // Referenced files
  for (const f of definitionFiles(m)) if (!existsSync(join(dir, f))) err(`referenced file missing: ${f}`);
  if (!existsSync(join(dir, "CHANGELOG.md"))) err(`missing CHANGELOG.md`);

  // Contracts compile as JSON Schema
  const contractAjv = new Ajv2020({ strict: false, allErrors: true });
  addFormats(contractAjv);
  const contracts = {};
  for (const k of ["input", "output"]) {
    try {
      const s = resolveSchema(m.contract[k], dir);
      contracts[k] = contractAjv.compile(s);
    } catch (e) {
      err(`contract.${k} is not a valid JSON Schema: ${e.message}`);
    }
  }

  // Eval suites
  for (const s of m.evaluation.suites) {
    const p = join(dir, s.file);
    if (!existsSync(p)) continue;
    let suite;
    try { suite = readYaml(p); } catch (e) { err(`${s.file}: unparseable YAML: ${e.message}`); continue; }
    if (!v.evalSuite(suite)) { fmtErrors(v.evalSuite.errors).forEach((e) => err(`${s.file}: ${e}`)); continue; }
    if (suite.id !== s.id) err(`${s.file}: suite id '${suite.id}' != declared '${s.id}'`);
    if (contracts.input)
      for (const c of suite.cases)
        if (!contracts.input(c.input)) err(`${s.file}: case '${c.id}' input violates contract.input: ${fmtErrors(contracts.input.errors).join("; ")}`);
  }

  // No infrastructure endpoints or secrets anywhere in the manifest
  walkStrings(m, "$", (s, path) => {
    if (URL_RE.test(s)) err(`${path}: contains an http(s) URL; definitions must not hard-code endpoints`);
    if (SECRET_RE.test(s)) err(`${path}: looks like a credential`);
  });

  // Dependency pinning
  const pinned = RELEASED.has(m.status);
  const deps = [...(m.skills ?? []).map((x) => ["skills", x]), ...(m.tools ?? []).map((x) => ["tools", x]),
    ...(m.capabilities ?? []).filter((x) => x.version).map((x) => ["capabilities", x])];
  const seen = new Set();
  for (const [kind, d] of deps) {
    if (seen.has(d.id)) err(`duplicate ${kind} binding: ${d.id}`);
    seen.add(d.id);
    if (pinned && !isExact(d.version)) err(`${kind} '${d.id}': status '${m.status}' requires an exact version, got '${d.version}'`);
  }
  for (const t of m.tools ?? []) {
    if (t.capability && !(m.capabilities ?? []).some((c) => c.id === t.capability))
      err(`tool '${t.id}' references capability '${t.capability}' not declared in capabilities`);
    if (t.side_effects === "irreversible" && !t.requires_approval)
      err(`tool '${t.id}' has irreversible side effects and must set requires_approval: true`);
  }

  // Policy coherence
  const t = m.timeout_policy;
  if (t.step_seconds && t.step_seconds > t.run_seconds) err(`timeout_policy.step_seconds exceeds run_seconds`);
  if (t.tool_call_seconds && t.tool_call_seconds > t.run_seconds) err(`timeout_policy.tool_call_seconds exceeds run_seconds`);
  if (m.checkpoint_policy.strategy === "interval" && !m.checkpoint_policy.interval_seconds) err(`checkpoint_policy.interval_seconds required for strategy 'interval'`);
  if (m.checkpoint_policy.strategy === "none" && (m.checkpoint_policy.resumable || m.checkpoint_policy.rollback?.supported))
    err(`checkpoint_policy: resumable/rollback require a checkpoint strategy other than 'none'`);
  if (m.timeout_policy.on_timeout === "checkpoint_and_suspend" && m.checkpoint_policy.strategy === "none")
    err(`timeout_policy.on_timeout 'checkpoint_and_suspend' requires checkpointing`);
  if (m.retry_policy.max_attempts > 1 && m.execution_policy.idempotency === "none" && m.permissions.side_effects !== "none")
    err(`retries with side effects require execution_policy.idempotency other than 'none'`);
  const rp = m.retry_policy;
  if (rp.retry_on && rp.never_retry_on && rp.retry_on.some((x) => rp.never_retry_on.includes(x))) err(`retry_on and never_retry_on overlap`);
  if (m.state.persistence === "none" && m.state.stores?.length) err(`state.stores declared but persistence is 'none'`);
  if (m.observability.evidence.record_tape && !m.observability.evidence.tape_includes?.length) err(`observability.evidence.tape_includes required when record_tape is true`);
  if (m.checkpoint_policy.rollback?.supported && m.permissions.side_effects === "irreversible" && m.checkpoint_policy.rollback.compensation === "none")
    err(`rollback.supported with irreversible side effects needs compensation 'tool_declared' or 'manual'`);

  // Security coupling
  const sec = m.security, perm = m.permissions;
  const toolSide = (m.tools ?? []).map((x) => x.side_effects ?? "none");
  const rank = { none: 0, reversible: 1, irreversible: 2 };
  if (toolSide.some((s) => rank[s] > rank[perm.side_effects])) err(`permissions.side_effects is lower than the strongest tool side effect`);
  if (perm.side_effects === "irreversible" && !perm.approvals?.length) err(`irreversible side effects require at least one permissions.approvals entry`);
  if (perm.side_effects !== "none" && perm.scopes.every((s) => s.endsWith(":read"))) err(`side effects declared but no write/admin scope`);
  if (perm.egress.mode === "none" && (m.capabilities ?? []).length) err(`egress mode 'none' conflicts with declared capabilities`);
  if (["confidential", "restricted"].includes(sec.classification)) {
    if (!sec.review?.security_review_required) err(`classification '${sec.classification}' requires security.review.security_review_required: true`);
    if (sec.data_handling.redact_in_evidence === false) err(`classification '${sec.classification}' requires redact_in_evidence`);
  }
  if (sec.classification === "restricted" && m.execution_policy.human_in_the_loop === "never") err(`classification 'restricted' cannot use human_in_the_loop: never`);
  if (sec.data_handling.processes_pii && sec.data_handling.redact_in_evidence === false) err(`agents processing PII must redact_in_evidence`);
  if (m.state.stores?.some((s) => s.contains_pii) && !sec.data_handling.processes_pii) err(`a state store contains PII but data_handling.processes_pii is false`);

  // Lifecycle
  if (m.status === "deprecated" && !m.lifecycle?.status_reason) err(`deprecated agents need lifecycle.status_reason`);
  if (m.status === "retired" && !m.lifecycle?.status_reason) err(`retired agents need lifecycle.status_reason`);
  if (m.lifecycle?.replaced_by && m.lifecycle.replaced_by.id === m.id) err(`lifecycle.replaced_by cannot reference itself`);
  if (m.status === "active") {
    if (!m.evaluation.suites.some((s) => s.required)) err(`active agents need at least one required evaluation suite`);
    if (m.observability.tracing === "off") err(`active agents must not disable tracing`);
    if (m.provenance.origin === "candidate_mutation" && !m.evaluation.promotion_gates.human_approval && m.security.classification !== "public")
      err(`promoted candidate mutations of non-public agents require promotion_gates.human_approval`);
  }
  if (m.provenance.derived_from && m.provenance.derived_from.id !== m.id && m.provenance.origin === "candidate_mutation")
    err(`candidate_mutation must derive from the same agent id`);
  if (m.provenance.derived_from?.id === m.id && compare(m.provenance.derived_from.version, m.version) >= 0)
    err(`provenance.derived_from.version must be lower than version`);
  const evIds = new Set();
  for (const e of m.provenance.evidence ?? []) {
    if (evIds.has(e.id)) err(`duplicate evidence id '${e.id}'`);
    evIds.add(e.id);
  }
  if (m.provenance.origin === "candidate_mutation" && !(m.provenance.evidence ?? []).some((e) => e.role === "motivates"))
    err(`candidate_mutation needs at least one evidence entry with role 'motivates'`);

  // Release ledger
  if (releases) {
    if (!v.releases(releases)) fmtErrors(v.releases.errors).forEach((e) => err(`releases.yaml: ${e}`));
    else {
      if (releases.agent !== m.id) err(`releases.yaml agent '${releases.agent}' != '${m.id}'`);
      const vs = releases.releases.map((r) => r.version);
      if (new Set(vs).size !== vs.length) err(`releases.yaml has duplicate versions`);
      for (let i = 1; i < vs.length; i++) if (compare(vs[i - 1], vs[i]) >= 0) err(`releases.yaml versions must be strictly ascending`);
      for (const r of releases.releases) if (r.git_tag !== `${m.id}@${r.version}`) err(`releases.yaml: git_tag for ${r.version} must be '${m.id}@${r.version}'`);
      const cur = releases.releases.find((r) => r.version === m.version);
      if (RELEASED.has(m.status)) {
        if (!cur) err(`status '${m.status}' requires a releases.yaml entry for ${m.version} (run: npm run release -- ${m.id})`);
        else if (cur.digest !== definitionDigest(m, dir))
          err(`definition digest changed but version ${m.version} is already released; bump the version (expected ${cur.digest}, got ${definitionDigest(m, dir)})`);
      } else if (cur) err(`version ${m.version} has a release entry but status is '${m.status}'`);
      const latest = vs[vs.length - 1];
      if (latest && compare(m.version, latest) < 0) err(`version ${m.version} is lower than latest released ${latest}`);
      if (m.provenance.derived_from?.id === m.id && !vs.includes(m.provenance.derived_from.version))
        err(`derived_from ${m.provenance.derived_from.version} is not a released version of this agent`);
    }
  } else if (RELEASED.has(m.status)) err(`status '${m.status}' requires releases.yaml`);

  return errs;
}

/** Validate every agent in a directory plus cross-agent references. */
export function validateRegistry(agentsDir, v, opts = {}) {
  const results = [];
  const loaded = [];
  for (const dir of listAgentDirs(agentsDir)) {
    let agent;
    try { agent = loadAgent(dir); } catch (e) { results.push({ dir, errors: [`unparseable: ${e.message}`] }); continue; }
    loaded.push(agent);
    results.push({ dir, id: agent.manifest?.id, errors: validateAgent(agent, v, opts) });
  }
  const byId = new Map(loaded.filter((a) => a.manifest?.id).map((a) => [a.manifest.id, a]));
  for (const r of results) {
    const a = loaded.find((x) => x.dir === r.dir);
    const m = a?.manifest;
    if (!m || r.errors.length) continue;
    for (const ref of [m.lifecycle?.replaced_by, ...(m.compatibility.supersedes ?? [])].filter(Boolean)) {
      const target = byId.get(ref.id);
      if (!target) { r.errors.push(`references unknown agent ${ref.id}`); continue; }
      if (!target.releases?.releases.some((x) => x.version === ref.version)) r.errors.push(`references ${ref.id}@${ref.version}, which has no release entry`);
    }
  }
  return results;
}

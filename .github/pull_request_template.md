## Change type
- [ ] New agent (draft)
- [ ] New version of an existing agent
- [ ] Candidate mutation (evidence-driven)
- [ ] Lifecycle change (deprecate / retire)
- [ ] Registry tooling / schema / docs

## Agent(s) and version(s)
<!-- e.g. exec.support-ticket-triage 1.0.0 -> 1.0.1 (patch) -->

## Why
<!-- For candidate mutations: what evidence motivated this? Link the evidence refs in provenance.evidence. -->

## Checklist
- [ ] `npm run ci` passes locally
- [ ] Version bump matches the rules in `docs/versioning.md`
- [ ] Released versions were not edited (a new version + ledger entry was added instead)
- [ ] `CHANGELOG.md` updated
- [ ] Permission/security expansion is called out and `security_review_required` is set
- [ ] Promotion gates satisfied (evaluation evidence recorded in `releases.yaml`) — promotions only
- [ ] No endpoints, credentials or raw execution data committed

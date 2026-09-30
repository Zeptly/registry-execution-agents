## Change type
- [ ] New candidate artifact
- [ ] Promotion (candidate -> canonical)
- [ ] Lifecycle overlay event
- [ ] Attestation / approval append
- [ ] Tooling / schema / docs

## Identities and versions
<!-- e.g. support.ticket-triage 1.0.1 (candidate) -->

## Why
<!-- For evolved candidates: what evidence motivated this? (evidence:// pointers in origin.evolution.sourceRefs) -->

## Checklist
- [ ] `npm run ci` passes; indexes regenerated (`npm run build:index`)
- [ ] No sealed version was edited; attestations/approvals/overlays are append-only
- [ ] Attestations and approvals are bound to the current artifact and seal digests; evaluation attestations carry an explicit `result`
- [ ] Canonical references pin exact version and digest
- [ ] No endpoints, credentials or raw runtime data
- [ ] Synthetic content stays under `synthetic/`

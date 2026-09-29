# Versioning

## Identity and references

- **ID** `exec.<slug>` is permanent. Retire, don't rename or delete.
- **Version** is [SemVer](https://semver.org). A reference is always `id@version`, optionally with `digest`.
- **Digest** = `sha256` of canonical JSON of the manifest (excluding `status` and `lifecycle`) plus the hashes of the instructions file, contract schema files and eval suites.
- **Ledger** `agents/<slug>/releases.yaml` maps each released version to its digest, date, `change_ref`, git tag, approvers and evaluation evidence. Entries are append-only.
- **Git tag** `exec.<slug>@x.y.z` is created by CI after merge. Runtimes should resolve exact versions from a tag (or the ledger digest), never from a moving branch.

## Immutability

Once a version has a ledger entry, any change to its digest inputs is rejected. Fix forward with a new version. Status/lifecycle changes (deprecate, retire) are allowed on a released version because they are excluded from the digest.

## Bump rules (checked by `scripts/check-changes.mjs`)

| Change | Minimum bump |
|---|---|
| Prompt wording, policy tuning (timeouts, retries, budgets), eval additions, docs | **patch** |
| Contract changed compatibly (new optional input, new output field); new/changed skills, tools, model aliases; **any permission/security expansion** (new scope, higher side-effect class, broader egress, new secret, classification change, approval removed) | **minor** |
| `purpose` changed; input property removed or newly required; output property removed or no longer guaranteed; top-level contract type changed | **major** |

The checker is a conservative heuristic; reviewers may require a larger bump. Pre-1.0 versions (`0.x`) may use minor for breaking changes. Permission expansion additionally requires `security.review.security_review_required: true`.

## Dependency pins

`draft`/`candidate`: `^`/`~` ranges allowed. `active`/`deprecated`/`retired`: exact versions only (optionally with `digest`), so a released agent version is reproducible.

## Recording a release

```bash
# after bumping version in agent.yaml and CHANGELOG.md, with status active
npm run release -- exec.<slug> --change-ref github:Zeptly/registry-execution-agents#<PR> --approved-by github:<reviewer>
```

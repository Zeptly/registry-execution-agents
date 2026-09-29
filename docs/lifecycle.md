# Lifecycle

```
draft ──► candidate ──► active ──► deprecated ──► retired
  │           │           ▲            │
  │           └──► draft  └────────────┘ (re-activate)
  └──────────────────────► active (first release)
```

| Status | Meaning | Runtime resolvable | Notes |
|---|---|---|---|
| `draft` | Being incubated | No | May use version ranges; no ledger entry |
| `candidate` | Proposed improvement awaiting evaluation/review | No | **Branch/PR only — CI merge-gate blocks merging** |
| `active` | Canonical, production-eligible | Yes | Requires ledger entry, exact pins, required eval suite, tracing on |
| `deprecated` | Still resolvable, discouraged | Yes (warn) | Needs `lifecycle.status_reason`; may set `replaced_by`, `sunset_at` |
| `retired` | No longer runnable | No | Terminal; needs `status_reason`; directory kept for history |

Legal transitions are encoded in `scripts/lib/changes.mjs` (`TRANSITIONS`) and enforced against the base branch. Agents are never deleted.

`candidate` is a *change proposal state*, not a deployment state: main only ever contains `draft`, `active`, `deprecated`, `retired`. A promoted candidate merges as a new `active` version; the prior version stays in history and in the ledger (and stays resolvable unless deprecated).

Status changes do not alter the digest and need no version bump, but are still reviewed PRs.

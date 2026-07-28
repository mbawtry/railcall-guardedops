# GuardedOps for RailCall

Verified source for two RailCall marketplace entries that make GitHub
automation useful without hiding writes or bypassing human approval.

## Included entries

### [GitHub Operations Airlock](github-operations-airlock/)

RailCall module `guardedops/github-operations` v1.1.2 provides 31 governed
commands for issues, pull requests, Actions, releases, repository contents,
branches, protection rules, and deployments. Every write produces a preview
and requires approval; destructive and policy-changing actions are high risk.

Marketplace install:

```shell
railcall market install cms3gwq2d0001zle91po4xn5f
```

### [GitHub Backlog Intake Airlock](github-backlog-intake-airlock/)

RailCall workflow `guardedops/github-backlog-intake-airlock` v1.3.0 turns
reviewed CSV backlog rows into approval-gated GitHub issue previews. It
validates, deduplicates, preserves source-row evidence, and suppresses replayed
receipt keys before any external effect.

Marketplace install:

```shell
railcall market install cms3gy7cr0003zle98pimd6xd
```

## Verification

On 2026-07-28, the exact public source passed:

- 33 module tests, including live read-only GitHub checks, signature/tamper
  detection, all 31 registered handlers, and a clean stock-station load.
- 7 workflow tests against the stock RailCall engine, including a complete
  two-effect in-memory execution and a zero-effect replay.
- A credential and personal-data scan of every published file.

No live GitHub write was used for validation. Test credentials are explicit
non-secret fixtures. The repository contains no publisher seed, access token,
private configuration, customer data, or local workspace artifact.

See each entry's `README.md` and `VALIDATION.md` for behavior, limitations, and
test scope.


# GitHub Backlog Intake Airlock

This workflow is for engineering leads who receive backlog CSVs and need GitHub
issues created without bypassing review or repeating rows from an earlier run.
It parses and validates locally, deduplicates the batch, suppresses receipt keys
that already landed, stages exact issue writes for human approval, and returns
reconciliation evidence for the next run.

## Install and connect

```shell
railcall market install cms3gy7cr0003zle98pimd6xd
```

Connect GitHub in RailCall. Use a fine-grained token limited to the target
repository with **Metadata: read** and **Issues: read/write**. The token stays
in RailCall's local credential store; it is never accepted in workflow input.

## Working example

Start the workflow manually with CSV text:

```csv
status,title,body
new,Document local setup,Add a concise setup guide for first-time contributors.
ready,Add retry regression coverage,Cover bounded read retries and ambiguous write failures.
new,Document local setup,Add a concise setup guide for first-time contributors.
```

Before approval, the pure nodes produce:

```json
{
  "candidate_count": 2,
  "eligible_count": 2,
  "duplicate_count": 1,
  "replay_keys": [
    "rcbk1:7549264679453230848:16203312213274446281",
    "rcbk1:16138741616069553252:17014738065517534042"
  ]
}
```

Approve only the two displayed `github.create_issue` effects. Reconciliation
then returns the actual issue numbers and those successful keys in
`next_prior_replay_keys`. Supply that list as optional `prior_replay_keys` on
the next run; the same CSV then yields:

```json
{"candidate_count": 2, "eligible_count": 0, "replay_suppressed_count": 2, "attempted": 0}
```

## How it works

`parse_csv`, `validate`, `dedup`, and `replay_guard` are pure transforms.
`create_issue` is the only external effect and requires human approval.
`reconcile` is a pure fan-in merge. Source row numbers survive every decision,
and the whole run receives RailCall receipts.

## Limitations

Input must contain `status,title,body`; actionable statuses are `new` and
`ready`. Replay protection is explicit and receipt-driven: the workflow does
not search GitHub automatically. Keep `next_prior_replay_keys` with the run
receipt and pass it back on later runs. GitHub title/body limits and repository
permissions still apply. A failed effect rolls back through RailCall's
compensation path.

`contest:2026Q3`

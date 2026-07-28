# Contest entry copy

## Title

GitHub Backlog Intake Airlock — Replay-Safe CSV-to-Issue Workflow

## Submission description

GitHub Backlog Intake Airlock is a six-node, receipt-driven workflow for
engineering leads: parse quoted CSV, validate rows, deduplicate within the
batch, suppress replay keys from prior successful runs, fan out governed
`github.create_issue` effects, and reconcile results.

The included sample produces two eligible issue previews, one evidenced
same-batch duplicate, one validation failure, one review hold, and one terminal
row. After the approved run, reconciliation returns actual issue numbers plus
`next_prior_replay_keys`. Passing that list into the same workflow makes a
second identical run complete with zero GitHub effects.

Four transforms and the final merge are pure. The only external node is visible
in the blast radius, policy-gated, compensable, and held for human approval.
There are no placeholders, stage aliases, hidden provider searches, or
credentials in input.

Seven tests run against the stock RailCall archive. They exercise the complete
plan, a complete two-effect execution through an in-memory GitHub adapter, a
complete zero-effect replay, CSV failure cases, receipt integrity, and two
stock pending-approval previews. No live write occurs during validation.

`contest:2026Q3`

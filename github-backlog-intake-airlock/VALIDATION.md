# Validation record

Version 1.3.0 was validated on 2026-07-28 against the stock RailCall station
archive with SHA-256
`44182d0931e8400f0789152b022484522fd3e9f08174a528b6c3f397f0262b91`.

- Payload contains six real nodes: four pure transforms, one governed GitHub
  effect, and one pure fan-in merge.
- Full `plan_workflow` completes across every node with no blocked binding or
  transform result.
- Full `run_workflow` completes against an in-memory GitHub test adapter,
  creates two mock issues, reconciles issue numbers, and verifies the workflow
  receipt structure.
- Re-running the full stock engine with the first receipt's
  `next_prior_replay_keys` completes with zero GitHub effect calls and two
  evidenced replay suppressions.
- The CSV parser rejects unclosed quotes, invalid replay-key versions, missing
  headers, duplicate headers, and wrong column counts.
- Six sample rows yield two eligible actions, one same-batch duplicate, one
  missing-title failure, one review hold, and one terminal row.
- Both eligible rows pass the stock `github.create_issue` semantic firewall and
  persist as distinct pending approvals.
- All transform code passes RailCall's AST safety gate.
- README is under 500 words; marketplace description is 800–1,500 characters.

Seven automated tests pass. Tests use local fixtures and an in-memory GitHub
adapter; no live GitHub write or other external mutation occurs.

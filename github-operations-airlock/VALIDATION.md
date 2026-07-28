# Validation record

Version 1.1.2 was validated on 2026-07-28 against the current stock station
archive downloaded from `https://railcall.ai/railcall_station.tar.gz`.

- Station archive SHA-256:
  `44182d0931e8400f0789152b022484522fd3e9f08174a528b6c3f397f0262b91`
- Stock loader: accepts a signed disposable copy and registers all 31 commands
  in a clean temporary workspace.
- Live reads: public repository, issue, and pull-request endpoints return valid
  GitHub data using REST API version `2026-03-10`.
- Signature checks: a valid bundle is accepted; a changed handler is rejected.
- Safety checks: malformed identifiers and paths fail before network access;
  writes require a vault credential and never retry; response bodies are
  bounded; token text is redacted; read retries are bounded; rate-limit timing
  is surfaced; protection payloads require GitHub's complete top-level shape.
- New family checks: Actions dispatch, file writes, branch/protection guards,
  and pull-request review rules are exercised without live mutation.
- README: under 500 words and includes a working read example, expected output,
  credentials, limitations, and `contest:2026Q3`.
- Automated checks: 33 passed, including live public reads, signing/tamper
  detection, and a clean stock-station load.

No live GitHub write was performed. Write behavior was exercised with local
response fixtures so no repository state changed.

The signed marketplace package uses the verified GuardedOps publisher identity.

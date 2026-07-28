# Contest entry copy

## Title

GitHub Operations Airlock - Governed GitHub Automation

## Submission description

GitHub Operations Airlock adds 31 real GitHub commands to RailCall across
issue triage, pull-request review and merging, Actions, releases, repository
files, branches and protection, plus deployments. Public reads need no token;
private access and writes use a fine-grained token from RailCall's local vault.

Every command is previewable and receipted. All writes require approval, with
destructive or policy-changing operations marked high risk. The handler
validates inputs and response size, allowlists returned fields, redacts tokens,
handles rate limits honestly, and never retries an ambiguous write.

Validation covers the current stock RailCall station, all 31 registered
handlers, live public reads, signed-bundle tamper rejection, and local response
fixtures for Actions, file, branch, protection, review, and other write
families. No live repository mutation was performed.

`contest:2026Q3`

## Suggested screenshot sequence

1. Marketplace card with the verified GuardedOps publisher fingerprint.
2. Modules page showing all 31 commands.
3. A successful public `github.get_repository` read.
4. A staged high-risk `github.merge_pull_request` preview awaiting approval.

# GitHub Operations Airlock

This module is for engineering and release teams that want agents to triage
GitHub, review pull requests, operate Actions, and manage releases or repository
state without granting unrestricted write access.

It provides 31 governed commands:

- Issues: repository metadata; list, get, search, create, update, and comment.
- Pull requests: list/get, request reviewers, review, and merge.
- Actions: list runs/artifacts, dispatch workflows, and cancel runs.
- Releases: list, create, update, and delete.
- Repository state: read/write/delete files, list/create/delete branches, and
  read/update branch protection.
- Deployments: list/create deployments and create deployment statuses.

Every command produces a preview and receipt. All writes require human
approval; destructive and policy-changing commands are high risk.

## Install and connect

```shell
railcall market install cms3gwq2d0001zle91po4xn5f
```

Public repository reads need no credential. Private reads and writes use a
fine-grained GitHub token stored only in RailCall's local vault under provider
`github`, secret field `GITHUB_TOKEN` (`token` is accepted for compatibility).
Optional saved `owner` and `repo` values provide a default target.

Grant only what you use: Metadata read; Issues, Pull requests, Actions,
Contents, and Deployments read/write as applicable; Workflows read/write for
`.github/workflows`; Administration read/write only for branch protection.

## Working example

Run:

```json
{"command":"github.get_repository","inputs":{"owner":"octocat","repo":"Hello-World"}}
```

Expected output shape:

```json
{
  "ok": true,
  "http_status": 200,
  "repository": {
    "full_name": "octocat/Hello-World",
    "private": false,
    "owner": "octocat"
  },
  "rate_limit": {"remaining": 59}
}
```

The live rate-limit value and omitted repository fields vary. A write such as
`github.dispatch_workflow` or `github.put_file` first returns an approval card;
no request is sent until a person approves it.

## Safety and limitations

The handler validates identifiers, paths, enums, payloads, list sizes, and text
lengths; allowlists output; caps response bodies; and redacts tokens from
errors. Reads use bounded retries. Writes never retry automatically because an
ambiguous failure may already have succeeded. Rate-limit responses include
reset timing.

Known limits: github.com REST only; one page and at most 100 records per list;
GitHub permissions and plan rules still apply. It does not download artifacts
or arbitrary URLs. API requests use GitHub REST version `2026-03-10`.

`contest:2026Q3`

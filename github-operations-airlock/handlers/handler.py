"""Governed GitHub issue and pull-request operations for RailCall.

The module calls only https://api.github.com, keeps credentials in RailCall's
local vault, bounds response data, and never retries a write when its outcome
could be ambiguous. RailCall's host airlock provides preview, approval, and
receipt signing around the functions declared in module.json.
"""

from __future__ import annotations

import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request


_HELPERS = globals().get("__rc_helpers__") or {}
_VAULT_GET = _HELPERS.get("vault_get")
_URLOPEN = urllib.request.urlopen
_SLEEP = time.sleep
_TIME = time.time
_BASE_URL = "https://api.github.com"
_API_VERSION = "2026-03-10"
_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,98}[A-Za-z0-9])?$")
_TOKEN_RE = re.compile(r"^[^\s\x00-\x1f\x7f]{20,255}$")
_SHA_RE = re.compile(r"^[0-9a-fA-F]{40,64}$")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
_MAX_RESPONSE_BYTES = 4_000_000


def _text(value, field, *, required=True, maximum=65_536):
    if value is None and not required:
        return None
    if not isinstance(value, str):
        raise RuntimeError(f"{field} must be a string")
    value = value.strip()
    if required and not value:
        raise RuntimeError(f"{field} must be a non-empty string")
    if len(value) > maximum:
        raise RuntimeError(f"{field} exceeds the {maximum}-character limit")
    return value


def _owner(value):
    value = _text(value, "owner", maximum=39)
    if not _OWNER_RE.fullmatch(value):
        raise RuntimeError("owner is not a valid GitHub account name")
    return value


def _repo(value):
    value = _text(value, "repo", maximum=100)
    if not _REPO_RE.fullmatch(value) or value in (".", ".."):
        raise RuntimeError("repo contains unsupported characters")
    return value


def _login(value, field):
    value = _text(value, field, maximum=100)
    if not _LOGIN_RE.fullmatch(value):
        raise RuntimeError(f"{field} is not a valid GitHub login or team slug")
    return value


def _repo_identity(inputs):
    entry = _VAULT_GET("github") if callable(_VAULT_GET) else None
    entry = entry if isinstance(entry, dict) else {}
    owner = inputs.get("owner")
    repo = inputs.get("repo")
    if owner is None:
        owner = entry.get("owner") or entry.get("GITHUB_OWNER")
    if repo is None:
        repo = entry.get("repo") or entry.get("GITHUB_REPO")
    return _owner(owner), _repo(repo)


def _positive_int(value, field):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimeError(f"{field} must be a positive integer")
    if isinstance(value, float) and not value.is_integer():
        raise RuntimeError(f"{field} must be a positive integer")
    value = int(value)
    if value < 1:
        raise RuntimeError(f"{field} must be a positive integer")
    return value


def _optional_bool(value, field, default=None):
    if value is None:
        return default
    if not isinstance(value, bool):
        raise RuntimeError(f"{field} must be a boolean")
    return value


def _sha(value, field="sha"):
    value = _text(value, field, maximum=64)
    if not _SHA_RE.fullmatch(value):
        raise RuntimeError(f"{field} must be a 40-64 character hexadecimal Git SHA")
    return value.lower()


def _ref_name(value, field="ref"):
    value = _text(value, field, maximum=255)
    if (
        value.startswith(("/", "."))
        or value.endswith(("/", "."))
        or ".." in value
        or "@{" in value
        or "\\" in value
        or re.search(r"[\x00-\x20~^:?*\[]", value)
    ):
        raise RuntimeError(f"{field} is not a safe Git reference name")
    return value


def _relative_path(value, field="path"):
    value = _text(value, field, maximum=1_024)
    if value.startswith("/") or "\\" in value:
        raise RuntimeError(f"{field} must be a repository-relative path")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise RuntimeError(f"{field} contains an empty or traversal segment")
    return "/".join(urllib.parse.quote(part, safe="._-") for part in parts)


def _workflow_id(value):
    if isinstance(value, bool):
        raise RuntimeError("workflow_id must be a positive integer or workflow file name")
    if isinstance(value, (int, float)):
        return str(_positive_int(value, "workflow_id"))
    value = _text(value, "workflow_id", maximum=255)
    if "/" in value or "\\" in value or value in (".", ".."):
        raise RuntimeError("workflow_id must be an ID or workflow file name")
    return urllib.parse.quote(value, safe="._-")


def _json_object(value, field, *, required=False, maximum=65_536):
    if value is None and not required:
        return None
    if not isinstance(value, dict):
        raise RuntimeError(f"{field} must be an object")
    if len(json.dumps(value, separators=(",", ":"), default=str)) > maximum:
        raise RuntimeError(f"{field} exceeds the {maximum}-character limit")
    return value


def _base64_content(value):
    value = _text(value, "content_base64", maximum=1_500_000)
    compact = "".join(value.split())
    if len(compact) % 4 or not _BASE64_RE.fullmatch(compact):
        raise RuntimeError("content_base64 must be valid padded base64 text")
    return compact


def _https_url(value, field):
    if value is None:
        return None
    value = _text(value, field, maximum=2_048)
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise RuntimeError(f"{field} must be an absolute HTTPS URL without credentials")
    return value


def _bounded_limit(value, default=30):
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimeError("limit must be a number")
    return max(1, min(100, int(value)))


def _enum(value, field, allowed, default=None):
    if value is None:
        return default
    value = _text(value, field, maximum=32).lower()
    if value not in allowed:
        raise RuntimeError(f"{field} must be one of: {', '.join(sorted(allowed))}")
    return value


def _string_list(value, field, *, maximum_items=20, login=False):
    if value is None:
        return None
    if not isinstance(value, list):
        raise RuntimeError(f"{field} must be an array of strings")
    if len(value) > maximum_items:
        raise RuntimeError(f"{field} exceeds the {maximum_items}-item limit")
    result = []
    for index, item in enumerate(value):
        name = f"{field}[{index}]"
        item = _login(item, name) if login else _text(item, name, maximum=100)
        if item not in result:
            result.append(item)
    return result


def _vault_token(*, required):
    entry = _VAULT_GET("github") if callable(_VAULT_GET) else None
    token = ""
    if isinstance(entry, str):
        token = entry.strip()
    elif isinstance(entry, dict):
        token = str(
            entry.get("token")
            or entry.get("GITHUB_TOKEN")
            or entry.get("api_key")
            or ""
        ).strip()
    if token and not _TOKEN_RE.fullmatch(token):
        raise RuntimeError("GitHub token in the local vault is malformed")
    if required and not token:
        raise RuntimeError(
            "no GitHub token saved - configure a fine-grained token in "
            "RailCall's local vault under provider 'github'"
        )
    return token


def _rate_metadata(headers):
    def _header(name):
        try:
            return headers.get(name)
        except Exception:
            return None

    remaining = _header("X-RateLimit-Remaining")
    reset = _header("X-RateLimit-Reset")
    return {
        "remaining": int(remaining) if str(remaining or "").isdigit() else None,
        "reset_epoch": int(reset) if str(reset or "").isdigit() else None,
        "resource": _header("X-RateLimit-Resource"),
        "request_id": _header("X-GitHub-Request-Id"),
    }


def _decode_json(raw):
    if not raw:
        return {}
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError("GitHub returned a non-JSON response") from exc


def _error_detail(raw, token):
    try:
        parsed = json.loads(raw.decode("utf-8"))
        if isinstance(parsed, dict):
            message = str(parsed.get("message") or "request failed")
            errors = parsed.get("errors")
            if isinstance(errors, list) and errors:
                message += ": " + "; ".join(str(item) for item in errors[:3])
        else:
            message = str(parsed)
    except Exception:
        message = raw.decode("utf-8", errors="replace") or "empty response"
    if token:
        message = message.replace(token, "[REDACTED]")
    return message[:500]


def _rate_wait_seconds(headers):
    retry_after = None
    try:
        value = headers.get("Retry-After")
        if value is not None:
            retry_after = max(0.0, float(value))
    except Exception:
        retry_after = None
    if retry_after is not None:
        return retry_after
    try:
        remaining = headers.get("X-RateLimit-Remaining")
        reset = headers.get("X-RateLimit-Reset")
        if str(remaining) == "0" and str(reset or "").isdigit():
            return max(0.0, float(reset) - _TIME())
    except Exception:
        pass
    return None


def _request(method, path, *, params=None, body=None, write=False):
    if not isinstance(path, str) or not path.startswith("/") or ".." in path:
        raise RuntimeError("invalid GitHub API path")
    if method not in ("GET", "POST", "PATCH", "PUT", "DELETE"):
        raise RuntimeError("unsupported GitHub HTTP method")
    if write and method == "GET":
        raise RuntimeError("internal error: write request cannot use GET")

    token = _vault_token(required=write)
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "RailCall-GitHub-Operations/1.1",
        "X-GitHub-Api-Version": _API_VERSION,
    }
    if token:
        headers["Authorization"] = "Bearer " + token

    url = _BASE_URL + path
    if params:
        clean_params = {
            key: value for key, value in params.items() if value is not None
        }
        if clean_params:
            url += "?" + urllib.parse.urlencode(clean_params, doseq=True)

    data = None
    if body is not None:
        if not isinstance(body, dict):
            raise RuntimeError("internal error: GitHub request body must be an object")
        data = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"

    attempts = 1 if write else 3
    for attempt in range(attempts):
        request = urllib.request.Request(
            url, data=data, method=method, headers=headers
        )
        try:
            with _URLOPEN(request, timeout=20) as response:
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(raw) > _MAX_RESPONSE_BYTES:
                    raise RuntimeError(
                        f"GitHub response exceeded the {_MAX_RESPONSE_BYTES}-byte safety limit"
                    )
                payload = _decode_json(raw)
                return response.getcode(), payload, _rate_metadata(response.headers)
        except urllib.error.HTTPError as exc:
            raw = b""
            try:
                raw = exc.read()[:4_096]
            except Exception:
                pass
            rate_limited = exc.code in (403, 429) and (
                str(exc.headers.get("X-RateLimit-Remaining") or "") == "0"
                or exc.code == 429
                or "rate limit" in _error_detail(raw, token).lower()
            )
            if rate_limited:
                wait_seconds = _rate_wait_seconds(exc.headers)
                if (
                    not write
                    and attempt + 1 < attempts
                    and wait_seconds is not None
                    and wait_seconds <= 2
                ):
                    _SLEEP(wait_seconds)
                    continue
                reset = _rate_metadata(exc.headers).get("reset_epoch")
                detail = (
                    f"retry after {wait_seconds:.0f}s"
                    if wait_seconds is not None
                    else "retry later"
                )
                if reset:
                    detail += f" (reset epoch {reset})"
                raise RuntimeError(f"GitHub rate limit reached; {detail}") from exc

            if (
                not write
                and exc.code in (502, 503, 504)
                and attempt + 1 < attempts
            ):
                _SLEEP(0.25 * (2**attempt))
                continue

            detail = _error_detail(raw, token)
            if write:
                raise RuntimeError(
                    f"GitHub write returned HTTP {exc.code} and was not retried: {detail}"
                ) from exc
            raise RuntimeError(f"GitHub HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            if write:
                raise RuntimeError(
                    "GitHub write transport failed; outcome is unknown and was "
                    "not retried. Inspect GitHub before approving a fresh attempt."
                ) from exc
            if attempt + 1 < attempts:
                _SLEEP(0.25 * (2**attempt))
                continue
            reason = getattr(exc, "reason", str(exc))
            raise RuntimeError(f"GitHub network error after bounded retries: {reason}") from exc

    raise RuntimeError("GitHub request failed after bounded retries")


def _repo_path(owner, repo):
    return "/repos/{}/{}".format(
        urllib.parse.quote(owner, safe=""),
        urllib.parse.quote(repo, safe=""),
    )


def _compact_repository(item):
    owner = item.get("owner") if isinstance(item.get("owner"), dict) else {}
    return {
        "id": item.get("id"),
        "full_name": item.get("full_name"),
        "html_url": item.get("html_url"),
        "description": item.get("description"),
        "private": bool(item.get("private")),
        "archived": bool(item.get("archived")),
        "disabled": bool(item.get("disabled")),
        "default_branch": item.get("default_branch"),
        "open_issues_count": item.get("open_issues_count"),
        "has_issues": bool(item.get("has_issues")),
        "owner": owner.get("login"),
        "updated_at": item.get("updated_at"),
    }


def _compact_issue(item, *, include_body=False):
    user = item.get("user") if isinstance(item.get("user"), dict) else {}
    labels = item.get("labels") if isinstance(item.get("labels"), list) else []
    assignees = (
        item.get("assignees") if isinstance(item.get("assignees"), list) else []
    )
    result = {
        "number": item.get("number"),
        "title": item.get("title"),
        "state": item.get("state"),
        "state_reason": item.get("state_reason"),
        "html_url": item.get("html_url"),
        "author": user.get("login"),
        "labels": [
            label.get("name")
            for label in labels
            if isinstance(label, dict) and label.get("name")
        ],
        "assignees": [
            person.get("login")
            for person in assignees
            if isinstance(person, dict) and person.get("login")
        ],
        "comments": item.get("comments"),
        "locked": bool(item.get("locked")),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
        "closed_at": item.get("closed_at"),
    }
    if include_body:
        body = item.get("body")
        result["body"] = body[:16_384] if isinstance(body, str) else body
        result["body_truncated"] = isinstance(body, str) and len(body) > 16_384
    return result


def _compact_pull_request(item, *, detailed=False):
    user = item.get("user") if isinstance(item.get("user"), dict) else {}
    head = item.get("head") if isinstance(item.get("head"), dict) else {}
    base = item.get("base") if isinstance(item.get("base"), dict) else {}
    result = {
        "number": item.get("number"),
        "title": item.get("title"),
        "state": item.get("state"),
        "draft": bool(item.get("draft")),
        "html_url": item.get("html_url"),
        "author": user.get("login"),
        "head": head.get("ref"),
        "base": base.get("ref"),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
    }
    if detailed:
        reviewers = (
            item.get("requested_reviewers")
            if isinstance(item.get("requested_reviewers"), list)
            else []
        )
        teams = (
            item.get("requested_teams")
            if isinstance(item.get("requested_teams"), list)
            else []
        )
        body = item.get("body")
        result.update(
            {
                "body": body[:16_384] if isinstance(body, str) else body,
                "body_truncated": isinstance(body, str) and len(body) > 16_384,
                "mergeable": item.get("mergeable"),
                "mergeable_state": item.get("mergeable_state"),
                "merged": bool(item.get("merged")),
                "commits": item.get("commits"),
                "additions": item.get("additions"),
                "deletions": item.get("deletions"),
                "changed_files": item.get("changed_files"),
                "requested_reviewers": [
                    person.get("login")
                    for person in reviewers
                    if isinstance(person, dict) and person.get("login")
                ],
                "requested_teams": [
                    team.get("slug")
                    for team in teams
                    if isinstance(team, dict) and team.get("slug")
                ],
            }
        )
    return result


def _compact_workflow_run(item):
    actor = item.get("actor") if isinstance(item.get("actor"), dict) else {}
    return {
        "id": item.get("id"),
        "name": item.get("name"),
        "event": item.get("event"),
        "status": item.get("status"),
        "conclusion": item.get("conclusion"),
        "workflow_id": item.get("workflow_id"),
        "run_number": item.get("run_number"),
        "head_branch": item.get("head_branch"),
        "head_sha": item.get("head_sha"),
        "html_url": item.get("html_url"),
        "actor": actor.get("login"),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
    }


def _compact_artifact(item):
    workflow_run = (
        item.get("workflow_run")
        if isinstance(item.get("workflow_run"), dict)
        else {}
    )
    return {
        "id": item.get("id"),
        "name": item.get("name"),
        "size_in_bytes": item.get("size_in_bytes"),
        "expired": bool(item.get("expired")),
        "expires_at": item.get("expires_at"),
        "workflow_run_id": workflow_run.get("id"),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
    }


def _compact_release(item, *, include_body=False):
    author = item.get("author") if isinstance(item.get("author"), dict) else {}
    result = {
        "id": item.get("id"),
        "tag_name": item.get("tag_name"),
        "target_commitish": item.get("target_commitish"),
        "name": item.get("name"),
        "draft": bool(item.get("draft")),
        "prerelease": bool(item.get("prerelease")),
        "html_url": item.get("html_url"),
        "author": author.get("login"),
        "created_at": item.get("created_at"),
        "published_at": item.get("published_at"),
    }
    if include_body:
        body = item.get("body")
        result["body"] = body[:16_384] if isinstance(body, str) else body
        result["body_truncated"] = isinstance(body, str) and len(body) > 16_384
    return result


def _compact_file(item):
    content = item.get("content")
    return {
        "type": item.get("type"),
        "name": item.get("name"),
        "path": item.get("path"),
        "sha": item.get("sha"),
        "size": item.get("size"),
        "encoding": item.get("encoding"),
        "content": content if isinstance(content, str) else None,
        "html_url": item.get("html_url"),
        "download_url": item.get("download_url"),
    }


def _compact_branch(item):
    commit = item.get("commit") if isinstance(item.get("commit"), dict) else {}
    return {
        "name": item.get("name"),
        "sha": commit.get("sha"),
        "protected": bool(item.get("protected")),
        "protection_url": item.get("protection_url"),
    }


def _compact_deployment(item):
    creator = item.get("creator") if isinstance(item.get("creator"), dict) else {}
    return {
        "id": item.get("id"),
        "ref": item.get("ref"),
        "sha": item.get("sha"),
        "environment": item.get("environment"),
        "description": item.get("description"),
        "transient_environment": bool(item.get("transient_environment")),
        "production_environment": bool(item.get("production_environment")),
        "creator": creator.get("login"),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
    }


def github_get_repository(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    status, payload, rate = _request("GET", _repo_path(owner, repo))
    if not isinstance(payload, dict) or not payload.get("full_name"):
        raise RuntimeError("GitHub returned an unexpected repository payload")
    return {
        "ok": True,
        "http_status": status,
        "repository": _compact_repository(payload),
        "rate_limit": rate,
    }, None


def github_list_issues(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    state = _enum(
        inputs.get("state"), "state", {"open", "closed", "all"}, default="open"
    )
    labels = _string_list(inputs.get("labels"), "labels") or []
    assignee = inputs.get("assignee")
    if assignee is not None:
        assignee = _login(assignee, "assignee")
    limit = _bounded_limit(inputs.get("limit"))
    status, payload, rate = _request(
        "GET",
        _repo_path(owner, repo) + "/issues",
        params={
            "state": state,
            "labels": ",".join(labels) if labels else None,
            "assignee": assignee,
            "per_page": limit,
            "sort": "updated",
            "direction": "desc",
        },
    )
    if not isinstance(payload, list):
        raise RuntimeError("GitHub returned an unexpected issues payload")
    issues = [
        _compact_issue(item)
        for item in payload
        if isinstance(item, dict) and "pull_request" not in item
    ][:limit]
    return {
        "ok": True,
        "http_status": status,
        "count": len(issues),
        "issues": issues,
        "rate_limit": rate,
    }, None


def github_get_issue(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    number = _positive_int(inputs.get("issue_number"), "issue_number")
    status, payload, rate = _request(
        "GET", _repo_path(owner, repo) + f"/issues/{number}"
    )
    if not isinstance(payload, dict) or not payload.get("number"):
        raise RuntimeError("GitHub returned an unexpected issue payload")
    return {
        "ok": True,
        "http_status": status,
        "issue": _compact_issue(payload, include_body=True),
        "rate_limit": rate,
    }, None


def github_search_issues(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    query = _text(inputs.get("query"), "query", maximum=256)
    state = _enum(
        inputs.get("state"), "state", {"open", "closed", "all"}, default="all"
    )
    limit = _bounded_limit(inputs.get("limit"))
    qualifiers = [f"repo:{owner}/{repo}", "is:issue"]
    if state != "all":
        qualifiers.append(f"is:{state}")
    status, payload, rate = _request(
        "GET",
        "/search/issues",
        params={
            "q": " ".join([query] + qualifiers),
            "per_page": limit,
            "sort": "updated",
            "order": "desc",
        },
    )
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        raise RuntimeError("GitHub returned an unexpected issue-search payload")
    issues = [
        _compact_issue(item)
        for item in payload["items"][:limit]
        if isinstance(item, dict)
    ]
    return {
        "ok": True,
        "http_status": status,
        "count": len(issues),
        "total_count": payload.get("total_count"),
        "incomplete_results": bool(payload.get("incomplete_results")),
        "issues": issues,
        "rate_limit": rate,
    }, None


def github_create_issue(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    title = _text(inputs.get("title"), "title", maximum=256)
    body = _text(inputs.get("body"), "body", required=False)
    labels = _string_list(inputs.get("labels"), "labels")
    assignees = _string_list(inputs.get("assignees"), "assignees", login=True)
    request_body = {"title": title}
    if body is not None:
        request_body["body"] = body
    if labels is not None:
        request_body["labels"] = labels
    if assignees is not None:
        request_body["assignees"] = assignees
    status, payload, rate = _request(
        "POST",
        _repo_path(owner, repo) + "/issues",
        body=request_body,
        write=True,
    )
    if not isinstance(payload, dict) or not payload.get("number"):
        raise RuntimeError("GitHub accepted the issue but returned no issue number")
    return {
        "ok": True,
        "http_status": status,
        "issue": _compact_issue(payload, include_body=True),
        "rate_limit": rate,
    }, None


def github_update_issue(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    number = _positive_int(inputs.get("issue_number"), "issue_number")
    fields = {}
    if "title" in inputs:
        fields["title"] = _text(inputs.get("title"), "title", maximum=256)
    if "body" in inputs:
        fields["body"] = _text(inputs.get("body"), "body", required=False) or ""
    if "state" in inputs:
        fields["state"] = _enum(inputs.get("state"), "state", {"open", "closed"})
    if "state_reason" in inputs:
        fields["state_reason"] = _enum(
            inputs.get("state_reason"),
            "state_reason",
            {"completed", "not_planned", "reopened"},
        )
        if "state" not in fields:
            raise RuntimeError("state_reason requires state in the same update")
    if "labels" in inputs:
        fields["labels"] = _string_list(inputs.get("labels"), "labels") or []
    if "assignees" in inputs:
        fields["assignees"] = (
            _string_list(inputs.get("assignees"), "assignees", login=True) or []
        )
    if not fields:
        raise RuntimeError(
            "provide at least one of title, body, state, state_reason, labels, or assignees"
        )
    status, payload, rate = _request(
        "PATCH",
        _repo_path(owner, repo) + f"/issues/{number}",
        body=fields,
        write=True,
    )
    if not isinstance(payload, dict) or not payload.get("number"):
        raise RuntimeError("GitHub accepted the update but returned no issue number")
    return {
        "ok": True,
        "http_status": status,
        "issue": _compact_issue(payload, include_body=True),
        "rate_limit": rate,
    }, None


def github_add_issue_comment(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    number = _positive_int(inputs.get("issue_number"), "issue_number")
    body = _text(inputs.get("body"), "body")
    status, payload, rate = _request(
        "POST",
        _repo_path(owner, repo) + f"/issues/{number}/comments",
        body={"body": body},
        write=True,
    )
    if not isinstance(payload, dict) or not payload.get("id"):
        raise RuntimeError("GitHub accepted the comment but returned no comment id")
    user = payload.get("user") if isinstance(payload.get("user"), dict) else {}
    return {
        "ok": True,
        "http_status": status,
        "comment": {
            "id": payload.get("id"),
            "html_url": payload.get("html_url"),
            "author": user.get("login"),
            "created_at": payload.get("created_at"),
        },
        "rate_limit": rate,
    }, None


def github_list_pull_requests(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    state = _enum(
        inputs.get("state"), "state", {"open", "closed", "all"}, default="open"
    )
    base = inputs.get("base")
    if base is not None:
        base = _text(base, "base", maximum=255)
    limit = _bounded_limit(inputs.get("limit"))
    status, payload, rate = _request(
        "GET",
        _repo_path(owner, repo) + "/pulls",
        params={
            "state": state,
            "base": base,
            "per_page": limit,
            "sort": "updated",
            "direction": "desc",
        },
    )
    if not isinstance(payload, list):
        raise RuntimeError("GitHub returned an unexpected pull-request payload")
    pull_requests = [
        _compact_pull_request(item)
        for item in payload[:limit]
        if isinstance(item, dict)
    ]
    return {
        "ok": True,
        "http_status": status,
        "count": len(pull_requests),
        "pull_requests": pull_requests,
        "rate_limit": rate,
    }, None


def github_get_pull_request(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    number = _positive_int(inputs.get("pull_number"), "pull_number")
    status, payload, rate = _request(
        "GET", _repo_path(owner, repo) + f"/pulls/{number}"
    )
    if not isinstance(payload, dict) or not payload.get("number"):
        raise RuntimeError("GitHub returned an unexpected pull-request payload")
    return {
        "ok": True,
        "http_status": status,
        "pull_request": _compact_pull_request(payload, detailed=True),
        "rate_limit": rate,
    }, None


def github_request_pull_request_reviewers(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    number = _positive_int(inputs.get("pull_number"), "pull_number")
    reviewers = (
        _string_list(inputs.get("reviewers"), "reviewers", login=True) or []
    )
    team_reviewers = (
        _string_list(inputs.get("team_reviewers"), "team_reviewers", login=True)
        or []
    )
    if not reviewers and not team_reviewers:
        raise RuntimeError("provide at least one reviewer or team_reviewer")
    status, payload, rate = _request(
        "POST",
        _repo_path(owner, repo) + f"/pulls/{number}/requested_reviewers",
        body={"reviewers": reviewers, "team_reviewers": team_reviewers},
        write=True,
    )
    if not isinstance(payload, dict):
        raise RuntimeError("GitHub returned an unexpected reviewer-request payload")
    users = payload.get("users") if isinstance(payload.get("users"), list) else []
    teams = payload.get("teams") if isinstance(payload.get("teams"), list) else []
    return {
        "ok": True,
        "http_status": status,
        "requested_reviewers": {
            "users": [
                person.get("login")
                for person in users
                if isinstance(person, dict) and person.get("login")
            ],
            "teams": [
                team.get("slug")
                for team in teams
                if isinstance(team, dict) and team.get("slug")
            ],
        },
        "rate_limit": rate,
    }, None


def github_list_workflow_runs(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    limit = _bounded_limit(inputs.get("limit"))
    branch = inputs.get("branch")
    if branch is not None:
        branch = _ref_name(branch, "branch")
    status_filter = inputs.get("status")
    if status_filter is not None:
        status_filter = _enum(
            status_filter,
            "status",
            {
                "completed",
                "action_required",
                "cancelled",
                "failure",
                "neutral",
                "skipped",
                "stale",
                "success",
                "timed_out",
                "in_progress",
                "queued",
                "requested",
                "waiting",
                "pending",
            },
        )
    event = inputs.get("event")
    if event is not None:
        event = _text(event, "event", maximum=64)
    status, payload, rate = _request(
        "GET",
        _repo_path(owner, repo) + "/actions/runs",
        params={
            "branch": branch,
            "status": status_filter,
            "event": event,
            "per_page": limit,
        },
    )
    runs = payload.get("workflow_runs") if isinstance(payload, dict) else None
    if not isinstance(runs, list):
        raise RuntimeError("GitHub returned an unexpected workflow-runs payload")
    compact = [
        _compact_workflow_run(item)
        for item in runs[:limit]
        if isinstance(item, dict)
    ]
    return {
        "ok": True,
        "http_status": status,
        "count": len(compact),
        "total_count": payload.get("total_count"),
        "workflow_runs": compact,
        "rate_limit": rate,
    }, None


def github_dispatch_workflow(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    workflow_id = _workflow_id(inputs.get("workflow_id"))
    ref = _ref_name(inputs.get("ref"), "ref")
    workflow_inputs = _json_object(
        inputs.get("inputs"), "inputs", required=False, maximum=16_384
    ) or {}
    status, payload, rate = _request(
        "POST",
        _repo_path(owner, repo) + f"/actions/workflows/{workflow_id}/dispatches",
        body={"ref": ref, "inputs": workflow_inputs},
        write=True,
    )
    return {
        "ok": status == 204,
        "http_status": status,
        "workflow_id": urllib.parse.unquote(workflow_id),
        "ref": ref,
        "rate_limit": rate,
    }, None


def github_cancel_workflow_run(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    run_id = _positive_int(inputs.get("run_id"), "run_id")
    status, payload, rate = _request(
        "POST",
        _repo_path(owner, repo) + f"/actions/runs/{run_id}/cancel",
        write=True,
    )
    return {
        "ok": status in (202, 204),
        "http_status": status,
        "run_id": run_id,
        "rate_limit": rate,
    }, None


def github_list_workflow_run_artifacts(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    run_id = _positive_int(inputs.get("run_id"), "run_id")
    limit = _bounded_limit(inputs.get("limit"))
    status, payload, rate = _request(
        "GET",
        _repo_path(owner, repo) + f"/actions/runs/{run_id}/artifacts",
        params={"per_page": limit},
    )
    artifacts = payload.get("artifacts") if isinstance(payload, dict) else None
    if not isinstance(artifacts, list):
        raise RuntimeError("GitHub returned an unexpected artifacts payload")
    compact = [
        _compact_artifact(item)
        for item in artifacts[:limit]
        if isinstance(item, dict)
    ]
    return {
        "ok": True,
        "http_status": status,
        "count": len(compact),
        "total_count": payload.get("total_count"),
        "artifacts": compact,
        "rate_limit": rate,
    }, None


def github_list_releases(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    limit = _bounded_limit(inputs.get("limit"))
    status, payload, rate = _request(
        "GET",
        _repo_path(owner, repo) + "/releases",
        params={"per_page": limit},
    )
    if not isinstance(payload, list):
        raise RuntimeError("GitHub returned an unexpected releases payload")
    releases = [
        _compact_release(item)
        for item in payload[:limit]
        if isinstance(item, dict)
    ]
    return {
        "ok": True,
        "http_status": status,
        "count": len(releases),
        "releases": releases,
        "rate_limit": rate,
    }, None


def github_create_release(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    body = {
        "tag_name": _text(inputs.get("tag_name"), "tag_name", maximum=255),
        "draft": _optional_bool(inputs.get("draft"), "draft", False),
        "prerelease": _optional_bool(inputs.get("prerelease"), "prerelease", False),
        "generate_release_notes": _optional_bool(
            inputs.get("generate_release_notes"), "generate_release_notes", False
        ),
    }
    if inputs.get("target_commitish") is not None:
        body["target_commitish"] = _ref_name(
            inputs.get("target_commitish"), "target_commitish"
        )
    if inputs.get("name") is not None:
        body["name"] = _text(inputs.get("name"), "name", required=False, maximum=255)
    if inputs.get("body") is not None:
        body["body"] = _text(inputs.get("body"), "body", required=False)
    status, payload, rate = _request(
        "POST",
        _repo_path(owner, repo) + "/releases",
        body=body,
        write=True,
    )
    if not isinstance(payload, dict) or not payload.get("id"):
        raise RuntimeError("GitHub accepted the release but returned no release id")
    return {
        "ok": True,
        "http_status": status,
        "release": _compact_release(payload, include_body=True),
        "rate_limit": rate,
    }, None


def github_update_release(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    release_id = _positive_int(inputs.get("release_id"), "release_id")
    fields = {}
    text_fields = {
        "tag_name": 255,
        "target_commitish": 255,
        "name": 255,
        "body": 65_536,
    }
    for field, maximum in text_fields.items():
        if field in inputs:
            value = _text(
                inputs.get(field), field, required=False, maximum=maximum
            )
            fields[field] = value or ""
    for field in ("draft", "prerelease", "make_latest"):
        if field in inputs:
            if field == "make_latest":
                fields[field] = _enum(
                    inputs.get(field), field, {"true", "false", "legacy"}
                )
            else:
                fields[field] = _optional_bool(inputs.get(field), field)
    if not fields:
        raise RuntimeError("provide at least one release field to update")
    status, payload, rate = _request(
        "PATCH",
        _repo_path(owner, repo) + f"/releases/{release_id}",
        body=fields,
        write=True,
    )
    if not isinstance(payload, dict) or not payload.get("id"):
        raise RuntimeError("GitHub accepted the update but returned no release id")
    return {
        "ok": True,
        "http_status": status,
        "release": _compact_release(payload, include_body=True),
        "rate_limit": rate,
    }, None


def github_delete_release(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    release_id = _positive_int(inputs.get("release_id"), "release_id")
    status, payload, rate = _request(
        "DELETE",
        _repo_path(owner, repo) + f"/releases/{release_id}",
        write=True,
    )
    return {
        "ok": status == 204,
        "http_status": status,
        "deleted_release_id": release_id,
        "rate_limit": rate,
    }, None


def github_get_file(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    path = _relative_path(inputs.get("path"))
    ref = inputs.get("ref")
    if ref is not None:
        ref = _ref_name(ref, "ref")
    status, payload, rate = _request(
        "GET",
        _repo_path(owner, repo) + f"/contents/{path}",
        params={"ref": ref},
    )
    if not isinstance(payload, dict) or payload.get("type") != "file":
        raise RuntimeError("GitHub did not return a single file payload")
    return {
        "ok": True,
        "http_status": status,
        "file": _compact_file(payload),
        "rate_limit": rate,
    }, None


def github_put_file(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    path = _relative_path(inputs.get("path"))
    body = {
        "message": _text(inputs.get("message"), "message", maximum=1_024),
        "content": _base64_content(inputs.get("content_base64")),
    }
    if inputs.get("sha") is not None:
        body["sha"] = _sha(inputs.get("sha"))
    if inputs.get("branch") is not None:
        body["branch"] = _ref_name(inputs.get("branch"), "branch")
    status, payload, rate = _request(
        "PUT",
        _repo_path(owner, repo) + f"/contents/{path}",
        body=body,
        write=True,
    )
    content = payload.get("content") if isinstance(payload, dict) else None
    commit = payload.get("commit") if isinstance(payload, dict) else None
    if not isinstance(content, dict) or not isinstance(commit, dict):
        raise RuntimeError("GitHub accepted the file write but returned no content record")
    return {
        "ok": True,
        "http_status": status,
        "content": {
            "path": content.get("path"),
            "sha": content.get("sha"),
            "html_url": content.get("html_url"),
        },
        "commit": {
            "sha": commit.get("sha"),
            "html_url": commit.get("html_url"),
            "message": commit.get("message"),
        },
        "rate_limit": rate,
    }, None


def github_delete_file(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    path = _relative_path(inputs.get("path"))
    body = {
        "message": _text(inputs.get("message"), "message", maximum=1_024),
        "sha": _sha(inputs.get("sha")),
    }
    if inputs.get("branch") is not None:
        body["branch"] = _ref_name(inputs.get("branch"), "branch")
    status, payload, rate = _request(
        "DELETE",
        _repo_path(owner, repo) + f"/contents/{path}",
        body=body,
        write=True,
    )
    commit = payload.get("commit") if isinstance(payload, dict) else None
    if not isinstance(commit, dict):
        raise RuntimeError("GitHub accepted the file deletion but returned no commit")
    return {
        "ok": True,
        "http_status": status,
        "deleted_path": urllib.parse.unquote(path),
        "commit": {
            "sha": commit.get("sha"),
            "html_url": commit.get("html_url"),
            "message": commit.get("message"),
        },
        "rate_limit": rate,
    }, None


def github_list_branches(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    limit = _bounded_limit(inputs.get("limit"))
    protected = _optional_bool(inputs.get("protected"), "protected", None)
    status, payload, rate = _request(
        "GET",
        _repo_path(owner, repo) + "/branches",
        params={"protected": protected, "per_page": limit},
    )
    if not isinstance(payload, list):
        raise RuntimeError("GitHub returned an unexpected branches payload")
    branches = [
        _compact_branch(item)
        for item in payload[:limit]
        if isinstance(item, dict)
    ]
    return {
        "ok": True,
        "http_status": status,
        "count": len(branches),
        "branches": branches,
        "rate_limit": rate,
    }, None


def github_create_branch(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    branch = _ref_name(inputs.get("branch"), "branch")
    sha = _sha(inputs.get("sha"))
    status, payload, rate = _request(
        "POST",
        _repo_path(owner, repo) + "/git/refs",
        body={"ref": "refs/heads/" + branch, "sha": sha},
        write=True,
    )
    obj = payload.get("object") if isinstance(payload, dict) else None
    if not isinstance(obj, dict) or not payload.get("ref"):
        raise RuntimeError("GitHub accepted the branch but returned no reference")
    return {
        "ok": True,
        "http_status": status,
        "branch": branch,
        "ref": payload.get("ref"),
        "sha": obj.get("sha"),
        "rate_limit": rate,
    }, None


def github_delete_branch(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    branch = _ref_name(inputs.get("branch"), "branch")
    encoded = "/".join(
        urllib.parse.quote(part, safe="._-") for part in branch.split("/")
    )
    status, payload, rate = _request(
        "DELETE",
        _repo_path(owner, repo) + f"/git/refs/heads/{encoded}",
        write=True,
    )
    return {
        "ok": status == 204,
        "http_status": status,
        "deleted_branch": branch,
        "rate_limit": rate,
    }, None


def github_get_branch_protection(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    branch = _ref_name(inputs.get("branch"), "branch")
    encoded = urllib.parse.quote(branch, safe="")
    status, payload, rate = _request(
        "GET",
        _repo_path(owner, repo) + f"/branches/{encoded}/protection",
    )
    if not isinstance(payload, dict):
        raise RuntimeError("GitHub returned an unexpected protection payload")
    return {
        "ok": True,
        "http_status": status,
        "branch": branch,
        "protection": payload,
        "rate_limit": rate,
    }, None


def github_update_branch_protection(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    branch = _ref_name(inputs.get("branch"), "branch")
    protection = _json_object(
        inputs.get("protection"), "protection", required=True, maximum=65_536
    )
    required = {
        "required_status_checks",
        "enforce_admins",
        "required_pull_request_reviews",
        "restrictions",
    }
    missing = sorted(required - set(protection))
    if missing:
        raise RuntimeError(
            "protection is missing required keys: " + ", ".join(missing)
        )
    allowed = required | {
        "required_linear_history",
        "allow_force_pushes",
        "allow_deletions",
        "block_creations",
        "required_conversation_resolution",
        "lock_branch",
        "allow_fork_syncing",
    }
    extras = sorted(set(protection) - allowed)
    if extras:
        raise RuntimeError(
            "protection contains unsupported keys: " + ", ".join(extras)
        )
    encoded = urllib.parse.quote(branch, safe="")
    status, payload, rate = _request(
        "PUT",
        _repo_path(owner, repo) + f"/branches/{encoded}/protection",
        body=protection,
        write=True,
    )
    if not isinstance(payload, dict):
        raise RuntimeError("GitHub accepted protection settings but returned no record")
    return {
        "ok": True,
        "http_status": status,
        "branch": branch,
        "protection": payload,
        "rate_limit": rate,
    }, None


def github_merge_pull_request(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    number = _positive_int(inputs.get("pull_number"), "pull_number")
    body = {
        "merge_method": _enum(
            inputs.get("merge_method"),
            "merge_method",
            {"merge", "squash", "rebase"},
            default="merge",
        )
    }
    if inputs.get("sha") is not None:
        body["sha"] = _sha(inputs.get("sha"))
    if inputs.get("commit_title") is not None:
        body["commit_title"] = _text(
            inputs.get("commit_title"), "commit_title", maximum=256
        )
    if inputs.get("commit_message") is not None:
        body["commit_message"] = _text(
            inputs.get("commit_message"),
            "commit_message",
            required=False,
            maximum=65_536,
        )
    status, payload, rate = _request(
        "PUT",
        _repo_path(owner, repo) + f"/pulls/{number}/merge",
        body=body,
        write=True,
    )
    if not isinstance(payload, dict) or "merged" not in payload:
        raise RuntimeError("GitHub returned an unexpected merge payload")
    return {
        "ok": bool(payload.get("merged")),
        "http_status": status,
        "pull_number": number,
        "merged": bool(payload.get("merged")),
        "sha": payload.get("sha"),
        "message": payload.get("message"),
        "rate_limit": rate,
    }, None


def github_create_pull_request_review(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    number = _positive_int(inputs.get("pull_number"), "pull_number")
    event = _enum(
        inputs.get("event"),
        "event",
        {"approve", "request_changes", "comment"},
    ).upper()
    body_text = _text(
        inputs.get("body"), "body", required=False, maximum=65_536
    )
    if event == "REQUEST_CHANGES" and not body_text:
        raise RuntimeError("body is required when event is request_changes")
    request_body = {"event": event}
    if body_text is not None:
        request_body["body"] = body_text
    if inputs.get("commit_id") is not None:
        request_body["commit_id"] = _sha(inputs.get("commit_id"), "commit_id")
    status, payload, rate = _request(
        "POST",
        _repo_path(owner, repo) + f"/pulls/{number}/reviews",
        body=request_body,
        write=True,
    )
    user = payload.get("user") if isinstance(payload, dict) else None
    if not isinstance(payload, dict) or not payload.get("id"):
        raise RuntimeError("GitHub accepted the review but returned no review id")
    return {
        "ok": True,
        "http_status": status,
        "review": {
            "id": payload.get("id"),
            "state": payload.get("state"),
            "html_url": payload.get("html_url"),
            "author": user.get("login") if isinstance(user, dict) else None,
            "submitted_at": payload.get("submitted_at"),
        },
        "rate_limit": rate,
    }, None


def github_list_deployments(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    limit = _bounded_limit(inputs.get("limit"))
    ref = inputs.get("ref")
    if ref is not None:
        ref = _ref_name(ref, "ref")
    environment = inputs.get("environment")
    if environment is not None:
        environment = _text(environment, "environment", maximum=255)
    status, payload, rate = _request(
        "GET",
        _repo_path(owner, repo) + "/deployments",
        params={
            "ref": ref,
            "environment": environment,
            "per_page": limit,
        },
    )
    if not isinstance(payload, list):
        raise RuntimeError("GitHub returned an unexpected deployments payload")
    deployments = [
        _compact_deployment(item)
        for item in payload[:limit]
        if isinstance(item, dict)
    ]
    return {
        "ok": True,
        "http_status": status,
        "count": len(deployments),
        "deployments": deployments,
        "rate_limit": rate,
    }, None


def github_create_deployment(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    body = {
        "ref": _ref_name(inputs.get("ref"), "ref"),
        "auto_merge": _optional_bool(inputs.get("auto_merge"), "auto_merge", False),
        "transient_environment": _optional_bool(
            inputs.get("transient_environment"), "transient_environment", False
        ),
        "production_environment": _optional_bool(
            inputs.get("production_environment"), "production_environment", True
        ),
    }
    if inputs.get("required_contexts") is not None:
        body["required_contexts"] = _string_list(
            inputs.get("required_contexts"),
            "required_contexts",
            maximum_items=50,
        )
    if inputs.get("environment") is not None:
        body["environment"] = _text(
            inputs.get("environment"), "environment", maximum=255
        )
    if inputs.get("description") is not None:
        body["description"] = _text(
            inputs.get("description"), "description", required=False, maximum=255
        )
    if inputs.get("payload") is not None:
        body["payload"] = _json_object(
            inputs.get("payload"), "payload", maximum=16_384
        )
    status, payload, rate = _request(
        "POST",
        _repo_path(owner, repo) + "/deployments",
        body=body,
        write=True,
    )
    if not isinstance(payload, dict) or not payload.get("id"):
        raise RuntimeError("GitHub accepted the deployment but returned no id")
    return {
        "ok": True,
        "http_status": status,
        "deployment": _compact_deployment(payload),
        "rate_limit": rate,
    }, None


def github_create_deployment_status(inputs, stamp):
    owner, repo = _repo_identity(inputs)
    deployment_id = _positive_int(
        inputs.get("deployment_id"), "deployment_id"
    )
    body = {
        "state": _enum(
            inputs.get("state"),
            "state",
            {
                "error",
                "failure",
                "inactive",
                "in_progress",
                "queued",
                "pending",
                "success",
            },
        )
    }
    if inputs.get("description") is not None:
        body["description"] = _text(
            inputs.get("description"), "description", required=False, maximum=140
        )
    if inputs.get("environment") is not None:
        body["environment"] = _text(
            inputs.get("environment"), "environment", maximum=255
        )
    if inputs.get("log_url") is not None:
        body["log_url"] = _https_url(inputs.get("log_url"), "log_url")
    if inputs.get("environment_url") is not None:
        body["environment_url"] = _https_url(
            inputs.get("environment_url"), "environment_url"
        )
    if inputs.get("auto_inactive") is not None:
        body["auto_inactive"] = _optional_bool(
            inputs.get("auto_inactive"), "auto_inactive"
        )
    status, payload, rate = _request(
        "POST",
        _repo_path(owner, repo)
        + f"/deployments/{deployment_id}/statuses",
        body=body,
        write=True,
    )
    creator = payload.get("creator") if isinstance(payload, dict) else None
    if not isinstance(payload, dict) or not payload.get("id"):
        raise RuntimeError("GitHub accepted the deployment status but returned no id")
    return {
        "ok": True,
        "http_status": status,
        "deployment_status": {
            "id": payload.get("id"),
            "state": payload.get("state"),
            "environment": payload.get("environment"),
            "description": payload.get("description"),
            "creator": creator.get("login") if isinstance(creator, dict) else None,
            "created_at": payload.get("created_at"),
        },
        "rate_limit": rate,
    }, None

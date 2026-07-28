import importlib.util
import io
import json
import pathlib
import unittest
import urllib.error


ROOT = pathlib.Path(__file__).resolve().parents[1]
HANDLER_PATH = ROOT / "handlers" / "handler.py"
MANIFEST_PATH = ROOT / "module.json"
README_PATH = ROOT / "README.md"


def load_handler():
    spec = importlib.util.spec_from_file_location("github_operations_handler", HANDLER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeResponse:
    def __init__(self, payload, status=200, headers=None):
        self._payload = json.dumps(payload).encode("utf-8")
        self._status = status
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, size=-1):
        return self._payload if size < 0 else self._payload[:size]

    def getcode(self):
        return self._status


class ManifestTests(unittest.TestCase):
    def test_manifest_has_31_unique_commands_and_gated_writes(self):
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        commands = manifest["commands"]
        self.assertEqual("1.1.2", manifest["version"])
        self.assertEqual(31, len(commands))
        ids = [command["id"] for command in commands]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn("contest:2026Q3", manifest["description"])
        self.assertGreaterEqual(len(manifest["description"]), 1_500)
        self.assertLessEqual(len(manifest["description"]), 2_500)
        self.assertTrue(manifest["homepage"].startswith("https://"))
        self.assertTrue(manifest["tests_url"].startswith("https://"))
        self.assertEqual("api_key", manifest["auth"]["type"])
        self.assertEqual("github", manifest["auth"]["vault_provider"])
        self.assertEqual("GITHUB_TOKEN", manifest["auth"]["secret_field"])
        for command in commands:
            self.assertTrue(command["preview"])
            self.assertTrue(command["receipt_required"])
            self.assertFalse(command["input_schema"]["owner"]["required"])
            self.assertFalse(command["input_schema"]["repo"]["required"])
            if command["mode"] == "write_requires_approval":
                self.assertIn(command["risk"], {"medium", "high"})
                self.assertIn("GITHUB_TOKEN", command["requires"])

    def test_readme_stays_within_contest_limit(self):
        readme = README_PATH.read_text(encoding="utf-8")
        words = readme.split()
        self.assertLessEqual(len(words), 500)
        self.assertIn("contest:2026Q3", readme)

    def test_signed_release_has_publisher_identity(self):
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        publisher_pubkey = manifest["publisher_pubkey"]
        self.assertEqual(64, len(publisher_pubkey))
        self.assertTrue(all(char in "0123456789abcdef" for char in publisher_pubkey))
        self.assertTrue((ROOT / "module.sig").exists())

    def test_every_command_has_a_handler(self):
        handler = load_handler()
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        for command in manifest["commands"]:
            function_name = command["id"].replace(".", "_")
            self.assertTrue(callable(getattr(handler, function_name, None)), function_name)


class HandlerSafetyTests(unittest.TestCase):
    def setUp(self):
        self.handler = load_handler()
        self.handler._SLEEP = lambda _: None

    def test_public_read_works_without_a_token(self):
        self.handler._VAULT_GET = lambda _: None
        self.handler._URLOPEN = lambda request, timeout=20: FakeResponse(
            {
                "id": 1,
                "full_name": "octocat/Hello-World",
                "owner": {"login": "octocat"},
                "private": False,
            },
            headers={"X-RateLimit-Remaining": "59"},
        )
        result, artifact = self.handler.github_get_repository(
            {"owner": "octocat", "repo": "Hello-World"}, {}
        )
        self.assertIsNone(artifact)
        self.assertEqual("octocat/Hello-World", result["repository"]["full_name"])

    def test_write_requires_vault_token_before_network(self):
        calls = []
        self.handler._VAULT_GET = lambda _: None
        self.handler._URLOPEN = lambda *args, **kwargs: calls.append(args)
        with self.assertRaisesRegex(RuntimeError, "no GitHub token saved"):
            self.handler.github_create_issue(
                {
                    "owner": "octocat",
                    "repo": "Hello-World",
                    "title": "Test",
                },
                {},
            )
        self.assertEqual([], calls)

    def test_legacy_string_vault_token_is_supported(self):
        self.handler._VAULT_GET = lambda _: "unit-test-token-1234567890"
        self.handler._URLOPEN = lambda request, timeout=20: FakeResponse(
            {
                "number": 7,
                "title": "Created",
                "state": "open",
                "user": {"login": "octocat"},
            },
            status=201,
        )
        result, _ = self.handler.github_create_issue(
            {"owner": "octocat", "repo": "Hello-World", "title": "Created"},
            {},
        )
        self.assertEqual(201, result["http_status"])

    def test_saved_repository_is_used_when_inputs_omit_owner_and_repo(self):
        seen_urls = []
        self.handler._VAULT_GET = lambda _: {
            "token": "unit-test-token-1234567890",
            "owner": "octocat",
            "repo": "Hello-World",
        }

        def accept(request, timeout=20):
            seen_urls.append(request.full_url)
            return FakeResponse(
                {
                    "number": 8,
                    "title": "From workflow",
                    "state": "open",
                    "user": {"login": "octocat"},
                },
                status=201,
            )

        self.handler._URLOPEN = accept
        result, _ = self.handler.github_create_issue(
            {"title": "From workflow", "body": "Queued through the airlock"},
            {},
        )
        self.assertEqual(201, result["http_status"])
        self.assertEqual(
            ["https://api.github.com/repos/octocat/Hello-World/issues"],
            seen_urls,
        )

    def test_write_http_error_redacts_token_and_is_not_retried(self):
        token = "sensitive-unit-test-token-1234567890"
        calls = []
        self.handler._VAULT_GET = lambda _: {"token": token}

        def reject(request, timeout=20):
            calls.append(request)
            raise urllib.error.HTTPError(
                request.full_url,
                401,
                "Unauthorized",
                {},
                io.BytesIO(
                    json.dumps({"message": f"bad credential {token}"}).encode()
                ),
            )

        self.handler._URLOPEN = reject
        with self.assertRaises(RuntimeError) as caught:
            self.handler.github_create_issue(
                {"owner": "octocat", "repo": "Hello-World", "title": "Test"},
                {},
            )
        self.assertEqual(1, len(calls))
        self.assertNotIn(token, str(caught.exception))
        self.assertIn("[REDACTED]", str(caught.exception))

    def test_write_transport_failure_is_not_retried(self):
        calls = []
        self.handler._VAULT_GET = lambda _: {"token": "unit-test-token-1234567890"}

        def fail(request, timeout=20):
            calls.append(request)
            raise urllib.error.URLError("connection reset")

        self.handler._URLOPEN = fail
        with self.assertRaisesRegex(RuntimeError, "outcome is unknown"):
            self.handler.github_create_issue(
                {
                    "owner": "octocat",
                    "repo": "Hello-World",
                    "title": "Test",
                },
                {},
            )
        self.assertEqual(1, len(calls))

    def test_read_transport_failure_uses_bounded_retry(self):
        calls = []
        self.handler._VAULT_GET = lambda _: None

        def flaky(request, timeout=20):
            calls.append(request)
            if len(calls) < 3:
                raise urllib.error.URLError("temporary")
            return FakeResponse(
                {
                    "id": 1,
                    "full_name": "octocat/Hello-World",
                    "owner": {"login": "octocat"},
                }
            )

        self.handler._URLOPEN = flaky
        result, _ = self.handler.github_get_repository(
            {"owner": "octocat", "repo": "Hello-World"}, {}
        )
        self.assertEqual(3, len(calls))
        self.assertTrue(result["ok"])

    def test_long_rate_limit_wait_surfaces_without_retrying(self):
        calls = []
        self.handler._VAULT_GET = lambda _: None

        def limited(request, timeout=20):
            calls.append(request)
            raise urllib.error.HTTPError(
                request.full_url,
                429,
                "Too Many Requests",
                {"Retry-After": "5", "X-RateLimit-Remaining": "0"},
                io.BytesIO(json.dumps({"message": "rate limit"}).encode()),
            )

        self.handler._URLOPEN = limited
        with self.assertRaisesRegex(RuntimeError, "retry after 5s"):
            self.handler.github_get_repository(
                {"owner": "octocat", "repo": "Hello-World"}, {}
            )
        self.assertEqual(1, len(calls))

    def test_short_read_rate_limit_wait_retries_once(self):
        calls = []
        waits = []
        self.handler._VAULT_GET = lambda _: None
        self.handler._SLEEP = waits.append

        def briefly_limited(request, timeout=20):
            calls.append(request)
            if len(calls) == 1:
                raise urllib.error.HTTPError(
                    request.full_url,
                    429,
                    "Too Many Requests",
                    {"Retry-After": "1", "X-RateLimit-Remaining": "0"},
                    io.BytesIO(json.dumps({"message": "rate limit"}).encode()),
                )
            return FakeResponse(
                {
                    "id": 1,
                    "full_name": "octocat/Hello-World",
                    "owner": {"login": "octocat"},
                }
            )

        self.handler._URLOPEN = briefly_limited
        result, _ = self.handler.github_get_repository(
            {"owner": "octocat", "repo": "Hello-World"}, {}
        )
        self.assertTrue(result["ok"])
        self.assertEqual(2, len(calls))
        self.assertEqual([1.0], waits)

    def test_malformed_identifiers_fail_before_network(self):
        calls = []
        self.handler._VAULT_GET = lambda _: None
        self.handler._URLOPEN = lambda *args, **kwargs: calls.append(args)
        with self.assertRaisesRegex(RuntimeError, "owner"):
            self.handler.github_get_repository(
                {"owner": "../../etc", "repo": "Hello-World"}, {}
            )
        self.assertEqual([], calls)

    def test_one_character_login_is_valid_but_trailing_hyphen_is_not(self):
        self.assertEqual("x", self.handler._login("x", "reviewer"))
        with self.assertRaisesRegex(RuntimeError, "reviewer"):
            self.handler._login("bad-", "reviewer")

    def test_fractional_issue_number_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "positive integer"):
            self.handler._positive_int(1.5, "issue_number")

    def test_issue_listing_filters_pull_requests(self):
        self.handler._VAULT_GET = lambda _: None
        self.handler._URLOPEN = lambda request, timeout=20: FakeResponse(
            [
                {"number": 1, "title": "Issue", "state": "open", "user": {"login": "a"}},
                {
                    "number": 2,
                    "title": "PR",
                    "state": "open",
                    "user": {"login": "b"},
                    "pull_request": {"url": "https://api.github.com/pulls/2"},
                },
            ]
        )
        result, _ = self.handler.github_list_issues(
            {"owner": "octocat", "repo": "Hello-World"}, {}
        )
        self.assertEqual(1, result["count"])
        self.assertEqual(1, result["issues"][0]["number"])

    def test_success_response_size_is_bounded(self):
        self.handler._MAX_RESPONSE_BYTES = 64
        self.handler._VAULT_GET = lambda _: None
        self.handler._URLOPEN = lambda request, timeout=20: FakeResponse(
            {"id": 1, "full_name": "octocat/" + ("x" * 100)}
        )
        with self.assertRaisesRegex(RuntimeError, "safety limit"):
            self.handler.github_get_repository(
                {"owner": "octocat", "repo": "Hello-World"}, {}
            )

    def test_workflow_dispatch_is_one_approval_gated_post(self):
        requests = []
        self.handler._VAULT_GET = lambda _: {
            "token": "unit-test-token-1234567890"
        }

        def accept(request, timeout=20):
            requests.append(request)
            return FakeResponse(None, status=204)

        self.handler._URLOPEN = accept
        result, _ = self.handler.github_dispatch_workflow(
            {
                "owner": "octocat",
                "repo": "Hello-World",
                "workflow_id": "ci.yml",
                "ref": "main",
                "inputs": {"suite": "safe"},
            },
            {},
        )
        self.assertTrue(result["ok"])
        self.assertEqual(1, len(requests))
        self.assertEqual("POST", requests[0].get_method())
        self.assertIn("/actions/workflows/ci.yml/dispatches", requests[0].full_url)

    def test_file_write_validates_base64_and_uses_put(self):
        requests = []
        self.handler._VAULT_GET = lambda _: {
            "token": "unit-test-token-1234567890"
        }

        def accept(request, timeout=20):
            requests.append(request)
            return FakeResponse(
                {
                    "content": {
                        "path": "docs/runbook.md",
                        "sha": "a" * 40,
                        "html_url": "https://github.com/octocat/Hello-World",
                    },
                    "commit": {
                        "sha": "b" * 40,
                        "html_url": "https://github.com/octocat/Hello-World",
                        "message": "Add runbook",
                    },
                },
                status=201,
            )

        self.handler._URLOPEN = accept
        result, _ = self.handler.github_put_file(
            {
                "owner": "octocat",
                "repo": "Hello-World",
                "path": "docs/runbook.md",
                "message": "Add runbook",
                "content_base64": "SGVsbG8=",
            },
            {},
        )
        self.assertTrue(result["ok"])
        self.assertEqual("PUT", requests[0].get_method())
        with self.assertRaisesRegex(RuntimeError, "base64"):
            self.handler.github_put_file(
                {
                    "owner": "octocat",
                    "repo": "Hello-World",
                    "path": "docs/runbook.md",
                    "message": "Add runbook",
                    "content_base64": "not base64!",
                },
                {},
            )

    def test_repository_paths_and_protection_payloads_are_strict(self):
        with self.assertRaisesRegex(RuntimeError, "path"):
            self.handler._relative_path("../secrets.txt")
        with self.assertRaisesRegex(RuntimeError, "missing required keys"):
            self.handler.github_update_branch_protection(
                {
                    "owner": "octocat",
                    "repo": "Hello-World",
                    "branch": "main",
                    "protection": {"enforce_admins": True},
                },
                {},
            )

    def test_request_changes_review_requires_explanation(self):
        with self.assertRaisesRegex(RuntimeError, "body is required"):
            self.handler.github_create_pull_request_review(
                {
                    "owner": "octocat",
                    "repo": "Hello-World",
                    "pull_number": 42,
                    "event": "request_changes",
                },
                {},
            )

    def test_actions_read_commands_use_expected_endpoints(self):
        calls = []

        def fake_request(method, path, **kwargs):
            calls.append((method, path, kwargs))
            if path.endswith("/actions/runs"):
                return 200, {"workflow_runs": [{"id": 7}], "total_count": 1}, {}
            return 200, {"artifacts": [{"id": 8}], "total_count": 1}, {}

        self.handler._request = fake_request
        runs, _ = self.handler.github_list_workflow_runs(
            {"owner": "octocat", "repo": "Hello-World", "status": "failure"}, {}
        )
        artifacts, _ = self.handler.github_list_workflow_run_artifacts(
            {"owner": "octocat", "repo": "Hello-World", "run_id": 7}, {}
        )
        self.assertEqual([7], [item["id"] for item in runs["workflow_runs"]])
        self.assertEqual([8], [item["id"] for item in artifacts["artifacts"]])
        self.assertEqual("GET", calls[0][0])
        self.assertIn("/actions/runs/7/artifacts", calls[1][1])

    def test_release_create_update_delete_contracts(self):
        calls = []

        def fake_request(method, path, **kwargs):
            calls.append((method, path, kwargs))
            if method == "DELETE":
                return 204, {}, {}
            return 201 if method == "POST" else 200, {
                "id": 9,
                "tag_name": "v1.1.0",
                "draft": method == "POST",
            }, {}

        self.handler._request = fake_request
        created, _ = self.handler.github_create_release(
            {
                "owner": "octocat",
                "repo": "Hello-World",
                "tag_name": "v1.1.0",
                "draft": True,
            },
            {},
        )
        updated, _ = self.handler.github_update_release(
            {
                "owner": "octocat",
                "repo": "Hello-World",
                "release_id": 9,
                "draft": False,
            },
            {},
        )
        deleted, _ = self.handler.github_delete_release(
            {
                "owner": "octocat",
                "repo": "Hello-World",
                "release_id": 9,
            },
            {},
        )
        self.assertEqual(9, created["release"]["id"])
        self.assertEqual(9, updated["release"]["id"])
        self.assertTrue(deleted["ok"])
        self.assertEqual(["POST", "PATCH", "DELETE"], [call[0] for call in calls])
        self.assertTrue(all(call[2]["write"] for call in calls))

    def test_file_and_branch_command_contracts(self):
        calls = []

        def fake_request(method, path, **kwargs):
            calls.append((method, path, kwargs))
            if "/contents/" in path and method == "GET":
                return 200, {
                    "type": "file",
                    "name": "runbook.md",
                    "path": "docs/runbook.md",
                    "sha": "a" * 40,
                    "content": "SGVsbG8=",
                }, {}
            if "/contents/" in path and method == "DELETE":
                return 200, {"commit": {"sha": "b" * 40}}, {}
            if path.endswith("/branches"):
                return 200, [
                    {"name": "main", "commit": {"sha": "c" * 40}, "protected": True}
                ], {}
            if path.endswith("/git/refs"):
                return 201, {
                    "ref": "refs/heads/release/v1.1",
                    "object": {"sha": "d" * 40},
                }, {}
            return 204, {}, {}

        self.handler._request = fake_request
        file_result, _ = self.handler.github_get_file(
            {
                "owner": "octocat",
                "repo": "Hello-World",
                "path": "docs/runbook.md",
            },
            {},
        )
        deleted_file, _ = self.handler.github_delete_file(
            {
                "owner": "octocat",
                "repo": "Hello-World",
                "path": "docs/old.md",
                "message": "Remove old file",
                "sha": "a" * 40,
            },
            {},
        )
        branches, _ = self.handler.github_list_branches(
            {"owner": "octocat", "repo": "Hello-World"}, {}
        )
        created_branch, _ = self.handler.github_create_branch(
            {
                "owner": "octocat",
                "repo": "Hello-World",
                "branch": "release/v1.1",
                "sha": "a" * 40,
            },
            {},
        )
        deleted_branch, _ = self.handler.github_delete_branch(
            {
                "owner": "octocat",
                "repo": "Hello-World",
                "branch": "release/old",
            },
            {},
        )
        self.assertEqual("docs/runbook.md", file_result["file"]["path"])
        self.assertEqual("docs/old.md", deleted_file["deleted_path"])
        self.assertEqual("main", branches["branches"][0]["name"])
        self.assertEqual("refs/heads/release/v1.1", created_branch["ref"])
        self.assertTrue(deleted_branch["ok"])
        self.assertTrue(
            any("/git/refs/heads/release/old" in call[1] for call in calls)
        )

    def test_protection_merge_and_review_contracts(self):
        calls = []

        def fake_request(method, path, **kwargs):
            calls.append((method, path, kwargs))
            if path.endswith("/protection"):
                return 200, {"url": "https://api.github.com/protection"}, {}
            if path.endswith("/merge"):
                return 200, {"merged": True, "sha": "a" * 40, "message": "merged"}, {}
            return 200, {
                "id": 55,
                "state": "APPROVED",
                "user": {"login": "octocat"},
            }, {}

        self.handler._request = fake_request
        protection = {
            "required_status_checks": None,
            "enforce_admins": True,
            "required_pull_request_reviews": None,
            "restrictions": None,
        }
        read_result, _ = self.handler.github_get_branch_protection(
            {"owner": "octocat", "repo": "Hello-World", "branch": "release/v1.1"},
            {},
        )
        update_result, _ = self.handler.github_update_branch_protection(
            {
                "owner": "octocat",
                "repo": "Hello-World",
                "branch": "release/v1.1",
                "protection": protection,
            },
            {},
        )
        merged, _ = self.handler.github_merge_pull_request(
            {
                "owner": "octocat",
                "repo": "Hello-World",
                "pull_number": 42,
                "merge_method": "squash",
            },
            {},
        )
        review, _ = self.handler.github_create_pull_request_review(
            {
                "owner": "octocat",
                "repo": "Hello-World",
                "pull_number": 42,
                "event": "approve",
            },
            {},
        )
        self.assertTrue(read_result["ok"])
        self.assertTrue(update_result["ok"])
        self.assertTrue(merged["merged"])
        self.assertEqual(55, review["review"]["id"])
        self.assertIn("/branches/release%2Fv1.1/protection", calls[0][1])
        self.assertEqual("PUT", calls[1][0])
        self.assertEqual("PUT", calls[2][0])
        self.assertEqual("POST", calls[3][0])

    def test_deployment_create_list_and_status_contracts(self):
        calls = []

        def fake_request(method, path, **kwargs):
            calls.append((method, path, kwargs))
            if method == "GET":
                return 200, [{"id": 88, "environment": "staging"}], {}
            if path.endswith("/deployments"):
                return 201, {"id": 88, "environment": "staging"}, {}
            return 201, {
                "id": 89,
                "state": "success",
                "creator": {"login": "octocat"},
            }, {}

        self.handler._request = fake_request
        listed, _ = self.handler.github_list_deployments(
            {
                "owner": "octocat",
                "repo": "Hello-World",
                "environment": "staging",
            },
            {},
        )
        created, _ = self.handler.github_create_deployment(
            {
                "owner": "octocat",
                "repo": "Hello-World",
                "ref": "main",
                "environment": "staging",
            },
            {},
        )
        status, _ = self.handler.github_create_deployment_status(
            {
                "owner": "octocat",
                "repo": "Hello-World",
                "deployment_id": 88,
                "state": "success",
                "environment_url": "https://example.com/deploy/88",
            },
            {},
        )
        self.assertEqual(1, listed["count"])
        self.assertEqual(88, created["deployment"]["id"])
        self.assertEqual(89, status["deployment_status"]["id"])
        self.assertNotIn("required_contexts", calls[1][2]["body"])
        self.assertEqual(["GET", "POST", "POST"], [call[0] for call in calls])


if __name__ == "__main__":
    unittest.main()

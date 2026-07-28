"""Live, read-only integration tests against the real GitHub REST API."""

import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
HANDLER_PATH = ROOT / "handlers" / "handler.py"


def load_handler():
    spec = importlib.util.spec_from_file_location("github_operations_live", HANDLER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module._VAULT_GET = lambda _: None
    return module


class GitHubLiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handler = load_handler()

    def test_get_public_repository(self):
        result, artifact = self.handler.github_get_repository(
            {"owner": "octocat", "repo": "Hello-World"}, {}
        )
        self.assertIsNone(artifact)
        self.assertEqual("octocat/Hello-World", result["repository"]["full_name"])
        self.assertFalse(result["repository"]["private"])

    def test_get_public_issue(self):
        result, _ = self.handler.github_get_issue(
            {
                "owner": "octocat",
                "repo": "Hello-World",
                "issue_number": 1347,
            },
            {},
        )
        self.assertEqual(1347, result["issue"]["number"])
        self.assertTrue(result["issue"]["html_url"].startswith("https://github.com/"))

    def test_list_public_pull_requests(self):
        result, _ = self.handler.github_list_pull_requests(
            {
                "owner": "octocat",
                "repo": "Hello-World",
                "state": "all",
                "limit": 5,
            },
            {},
        )
        self.assertLessEqual(result["count"], 5)
        self.assertIsInstance(result["pull_requests"], list)


if __name__ == "__main__":
    unittest.main()

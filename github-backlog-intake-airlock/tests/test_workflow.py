import importlib
import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / "workflow.json"
SAMPLE_PATH = ROOT / "sample_backlog.csv"
README_PATH = ROOT / "README.md"
STATION_WORKBENCH = os.environ.get("RAILCALL_STATION_WORKBENCH")


def load_file(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestSigning:
    SIG_VERIFIED = "signed_and_verified"

    def sign_block(self, integrity_value):
        return {"alg": "test-only", "value": integrity_value}

    def verify_against_install(self, integrity_value, signature):
        if signature == {"alg": "test-only", "value": integrity_value}:
            return self.SIG_VERIFIED
        return "signature_fail"


class FakeGitHubClient:
    def __init__(self):
        self.created = []
        self.closed = []

    def create_issue(self, title, body=None):
        number = 100 + len(self.created) + 1
        issue = {
            "number": number,
            "html_url": "https://example.invalid/issues/%d" % number,
            "title": title,
            "body": body,
        }
        self.created.append(issue)
        return issue

    def close_issue(self, issue_number):
        self.closed.append(issue_number)
        return {"number": issue_number, "state": "closed"}


@unittest.skipUnless(
    STATION_WORKBENCH,
    "set RAILCALL_STATION_WORKBENCH to run stock-station workflow tests",
)
class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workbench = pathlib.Path(STATION_WORKBENCH).resolve()
        cls.transform = load_file(
            "railcall_transform_for_contest_workflow_v130",
            cls.workbench / "workflow_transform.py",
        )
        station_root = str(cls.workbench.parent)
        sys.path.insert(0, station_root)
        try:
            cls.engine = importlib.import_module("workbench.workflow_engine")
        finally:
            sys.path.pop(0)
        cls.spec = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
        cls.nodes = {node["id"]: node for node in cls.spec["nodes"]}
        cls.sample_text = SAMPLE_PATH.read_text(encoding="utf-8")

    def run_transform(self, node_id, value):
        return self.transform.run_transform(
            self.nodes[node_id]["code"], value
        )["output"]

    def process_sample(self, prior_replay_keys=None):
        parsed = self.run_transform(
            "parse_csv",
            {
                "csv_text": self.sample_text,
                "prior_replay_keys": prior_replay_keys or [],
            },
        )
        validated = self.run_transform("validate", parsed)
        deduped = self.run_transform("dedup", validated)
        eligible = self.run_transform("replay_guard", deduped)
        return parsed, validated, deduped, eligible

    def test_marketplace_shape_and_readme_limit(self):
        self.assertEqual(
            "guardedops/github-backlog-intake-airlock", self.spec["id"]
        )
        self.assertEqual("1.3.0", self.spec["version"])
        self.assertEqual({"type": "manual", "input": "csv_text"}, self.spec["trigger"])
        self.assertEqual("require_human", self.spec["approval"])
        self.assertFalse(self.spec["irreversible"])
        self.assertNotIn("steps", self.spec)
        self.assertNotIn("stage_map", self.spec)
        self.assertIn("contest:2026Q3", self.spec["description"])
        self.assertGreaterEqual(len(self.spec["description"]), 800)
        self.assertLessEqual(len(self.spec["description"]), 1_500)
        self.assertLessEqual(
            len(README_PATH.read_text(encoding="utf-8").split()), 500
        )
        self.assertEqual(
            [
                "parse_csv",
                "validate",
                "dedup",
                "replay_guard",
                "create_issue",
                "reconcile",
            ],
            [node["id"] for node in self.spec["nodes"]],
        )
        self.assertEqual(
            ["transform", "transform", "transform", "transform", "effect", "merge"],
            [node["type"] for node in self.spec["nodes"]],
        )
        effect = self.nodes["create_issue"]
        self.assertEqual("github.create_issue", effect["action_id"])
        self.assertEqual("{{nodes.replay_guard.output}}", effect["for_each"])
        self.assertEqual("{{ctx.item.title}}", effect["args"]["title"])
        self.assertEqual("{{ctx.item.body}}", effect["args"]["body"])
        self.assertEqual(
            ["dedup", "replay_guard", "create_issue"],
            self.nodes["reconcile"]["inputs"],
        )

    def test_real_transforms_parse_validate_deduplicate_and_guard(self):
        parsed, validated, deduped, eligible = self.process_sample()
        self.assertEqual(6, parsed["parsed_count"])
        self.assertEqual([], parsed["parse_errors"])
        self.assertEqual([], parsed["prior_key_errors"])

        self.assertEqual(3, len(validated["valid_rows"]))
        self.assertEqual(
            [{"source_row": 5, "reason": "missing_title"}],
            validated["invalid_rows"],
        )
        self.assertEqual(1, len(validated["held_rows"]))
        self.assertEqual(1, len(validated["terminal_rows"]))

        self.assertEqual(2, deduped["candidate_count"])
        self.assertEqual(1, deduped["duplicate_count"])
        self.assertEqual([], deduped["key_collisions"])
        self.assertEqual(
            ["Document local setup", "Add retry regression coverage"],
            [row["title"] for row in deduped["candidate_rows"]],
        )
        self.assertEqual(2, len(eligible))
        self.assertTrue(
            all(row["replay_key"].startswith("rcbk1:") for row in eligible)
        )

    def test_receipt_keys_suppress_a_second_run(self):
        _, _, _, first_eligible = self.process_sample()
        prior = [row["replay_key"] for row in first_eligible]
        _, _, deduped, second_eligible = self.process_sample(prior)
        self.assertEqual(prior, deduped["prior_replay_keys"])
        self.assertEqual([], second_eligible)

    def test_csv_parser_rejects_unclosed_quotes_and_bad_prior_keys(self):
        parsed = self.run_transform(
            "parse_csv",
            {
                "csv_text": 'status,title,body\nnew,"unclosed,body',
                "prior_replay_keys": ["wrong:1", "rcbk1:1:2", "rcbk1:1:2"],
            },
        )
        self.assertEqual([], parsed["rows"])
        self.assertEqual(
            [{"source_row": 2, "reason": "unclosed_quote"}],
            parsed["parse_errors"],
        )
        self.assertEqual(["rcbk1:1:2"], parsed["prior_replay_keys"])
        self.assertEqual(
            [{"index": 0, "reason": "unsupported_replay_key"}],
            parsed["prior_key_errors"],
        )

    def test_stock_engine_plans_every_node_without_binding_errors(self):
        plan = self.engine.plan_workflow(
            self.spec,
            signing=TestSigning(),
            policy_gate=lambda provider, verb, action_class: {
                "decision": "require_human",
                "reason": "test policy",
            },
        )
        self.assertEqual(6, plan["blast_radius"]["node_count"])
        self.assertEqual(["github"], plan["blast_radius"]["systems_touched"])
        self.assertEqual("require_human", plan["blast_radius"]["requires"])
        self.assertEqual(
            [
                "parse_csv",
                "validate",
                "dedup",
                "replay_guard",
                "create_issue",
                "reconcile",
            ],
            [node["id"] for node in plan["nodes"]],
        )
        self.assertFalse(
            any(node["policy"]["decision"] == "block" for node in plan["nodes"])
        )
        self.assertIsNotNone(plan["workflow_root"])
        self.assertEqual(
            plan["workflow_root"], plan["signature"]["value"]
        )

    def test_stock_engine_runs_full_workflow_then_zero_effect_replay(self):
        signer = TestSigning()
        first_client = FakeGitHubClient()
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(
                self.engine,
                "_client",
                return_value=(first_client, "mock"),
            ):
                first = self.engine.run_workflow(
                    self.spec,
                    ws=temporary,
                    signing=signer,
                    allow_live_effects=False,
                )
            self.assertEqual("COMPLETED", first["outcome"])
            self.assertEqual(2, len(first_client.created))
            summary = first["outputs"]["reconcile"]["output"]
            self.assertEqual(2, summary["candidate_count"])
            self.assertEqual(2, summary["eligible_count"])
            self.assertEqual(0, summary["replay_suppressed_count"])
            self.assertEqual(2, summary["attempted"])
            self.assertEqual(2, summary["succeeded"])
            self.assertEqual(0, summary["failed"])
            self.assertEqual([101, 102], summary["issue_numbers"])
            self.assertEqual(2, len(summary["next_prior_replay_keys"]))
            self.assertTrue(summary["result_count_matches_expected"])
            verified, details = self.engine.verify_workflow_receipt(
                first["workflow_receipt"],
                first["node_receipts"],
                signing=signer,
            )
            self.assertTrue(verified, details)

            replay_spec = json.loads(json.dumps(self.spec))
            replay_spec["context"]["prior_replay_keys"] = summary[
                "next_prior_replay_keys"
            ]
            second_client = FakeGitHubClient()
            with mock.patch.object(
                self.engine,
                "_client",
                return_value=(second_client, "mock"),
            ):
                second = self.engine.run_workflow(
                    replay_spec,
                    ws=temporary,
                    signing=signer,
                    allow_live_effects=False,
                )
            self.assertEqual("COMPLETED", second["outcome"])
            self.assertEqual([], second_client.created)
            replay_summary = second["outputs"]["reconcile"]["output"]
            self.assertEqual(0, replay_summary["eligible_count"])
            self.assertEqual(2, replay_summary["replay_suppressed_count"])
            self.assertEqual(0, replay_summary["attempted"])
            self.assertEqual(0, replay_summary["succeeded"])
            self.assertEqual(
                summary["next_prior_replay_keys"],
                replay_summary["next_prior_replay_keys"],
            )

    def test_unique_rows_stage_as_two_stock_airlock_previews(self):
        sys.path.insert(0, str(self.workbench))
        try:
            station = load_file(
                "railcall_station_for_contest_workflow_v130",
                self.workbench / "studio_server.py",
            )
        finally:
            sys.path.pop(0)

        _, _, _, eligible = self.process_sample()
        with tempfile.TemporaryDirectory() as temporary:
            station.WS = temporary
            pathlib.Path(temporary, "integrations.json").write_text(
                json.dumps(
                    {"engineering": [{"id": "github", "status": "tested"}]}
                ),
                encoding="utf-8",
            )
            pathlib.Path(temporary, "keys.local.json").write_text(
                json.dumps(
                    {
                        "github": {
                            "token": "test_token_not_used",
                            "owner": "octocat",
                            "repo": "Hello-World",
                        }
                    }
                ),
                encoding="utf-8",
            )
            previews = [
                station.preview_command(
                    "github.create_issue",
                    {"title": row["title"], "body": row["body"]},
                    intent="contest-workflow-v1.3-test",
                )
                for row in eligible
            ]
            self.assertEqual(
                ["pending_approval", "pending_approval"],
                [item["status"] for item in previews],
            )
            pending = json.loads(
                pathlib.Path(temporary, "pending_approvals.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(2, len(pending))


if __name__ == "__main__":
    unittest.main()

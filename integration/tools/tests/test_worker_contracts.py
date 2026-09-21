import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "integration" / "tools" / "worker_contracts.py"


def load_module():
    spec = importlib.util.spec_from_file_location("worker_contracts", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def base_author_result(**overrides):
    result = {
        "contract_version": "swiyu.worker-result.v1",
        "task_id": "m03-openac-baseline",
        "role": "author",
        "status": "ready_for_review",
        "summary": "Mapped the real proof path and added baseline checks.",
        "changed_paths": ["docs/platform/milestone-03-openac-baseline.md"],
        "artifacts": [
            {
                "path": "docs/platform/milestone-03-openac-baseline.md",
                "purpose": "baseline reproduction note",
            }
        ],
        "commands": [
            {
                "command": "node --test integration/providers/openac/tests/provider.test.mjs",
                "status": "passed",
                "evidence": "20 tests passed",
            }
        ],
        "issues": [],
        "next": "start_reviewer",
        "usage": {"model": "composer-2.5", "reported_cost": "unknown"},
    }
    result.update(overrides)
    return result


def base_review_result(**overrides):
    result = {
        "contract_version": "swiyu.worker-result.v1",
        "task_id": "m03-openac-baseline",
        "role": "reviewer",
        "status": "pass",
        "summary": "No blocking issues found.",
        "changed_paths": [],
        "artifacts": [
            {
                "path": "docs/platform/milestone-03-openac-baseline.md",
                "purpose": "reviewed baseline note",
            }
        ],
        "commands": [
            {
                "command": "node --test integration/providers/openac/tests/provider.test.mjs",
                "status": "passed",
                "evidence": "20 tests passed",
            }
        ],
        "issues": [],
        "reviewed_paths": ["docs/platform/milestone-03-openac-baseline.md"],
        "next": "master_accept",
        "usage": {"model": "grok-4.6", "reported_cost": "unknown"},
    }
    result.update(overrides)
    return result


class WorkerContractsTest(unittest.TestCase):
    def setUp(self):
        self.contracts = load_module()

    def test_accepts_ready_author_result(self):
        normalized = self.contracts.validate_result(
            base_author_result(), expected_task_id="m03-openac-baseline", expected_role="author"
        )
        self.assertEqual(normalized["next"], "start_reviewer")

    def test_rejects_reviewer_pass_with_open_issues(self):
        bad = base_review_result(
            issues=[
                {
                    "severity": "blocking",
                    "path": "integration/providers/openac/provider.mjs",
                    "line": 1,
                    "message": "Verifier still returns a stubbed result.",
                }
            ]
        )
        with self.assertRaisesRegex(self.contracts.ContractError, "pass.*issues"):
            self.contracts.validate_result(
                bad, expected_task_id="m03-openac-baseline", expected_role="reviewer"
            )

    def test_reviewer_pass_must_cover_author_changed_paths(self):
        author = base_author_result(
            changed_paths=[
                "docs/platform/milestone-03-openac-baseline.md",
                "integration/providers/openac/provider.mjs",
            ]
        )
        reviewer = base_review_result(
            reviewed_paths=["docs/platform/milestone-03-openac-baseline.md"]
        )
        with self.assertRaisesRegex(self.contracts.ContractError, "reviewed_paths"):
            self.contracts.validate_review_against_author(author, reviewer)

    def test_changes_requested_requires_issue(self):
        reviewer = base_review_result(status="changes_requested", next="request_repair")
        with self.assertRaisesRegex(self.contracts.ContractError, "requires at least one issue"):
            self.contracts.validate_result(
                reviewer,
                expected_task_id="m03-openac-baseline",
                expected_role="reviewer",
            )

    def test_next_action_drives_author_review_repair_accept_flow(self):
        self.assertEqual(
            self.contracts.next_action(base_author_result()), "start_reviewer"
        )
        self.assertEqual(
            self.contracts.next_action(
                base_author_result(),
                base_review_result(
                    status="changes_requested",
                    issues=[
                        {
                            "severity": "blocking",
                            "path": "docs/platform/milestone-03-openac-baseline.md",
                            "message": "Missing challenge rejection evidence.",
                        }
                    ],
                    next="request_repair",
                ),
            ),
            "request_repair",
        )
        self.assertEqual(
            self.contracts.next_action(base_author_result(), base_review_result()),
            "master_accept",
        )

    def test_reviewer_prompt_contains_original_task_and_contract(self):
        prompt = self.contracts.render_reviewer_prompt(
            task_id="m03-openac-baseline",
            original_task="Capture one real OpenAC proof baseline.",
            author_result=base_author_result(),
        )
        self.assertIn("Capture one real OpenAC proof baseline.", prompt)
        self.assertIn("docs/platform/milestone-03-openac-baseline.md", prompt)
        self.assertIn('"role": "reviewer"', prompt)
        self.assertIn('"status": "pass"', prompt)
        self.assertIn("Return only the JSON contract", prompt)

    def test_author_prompt_contains_task_and_author_contract(self):
        prompt = self.contracts.render_author_prompt(
            task_id="m03-openac-baseline",
            original_task="Capture one real OpenAC proof baseline.",
        )
        self.assertIn("Capture one real OpenAC proof baseline.", prompt)
        self.assertIn('"role": "author"', prompt)
        self.assertIn('"next": "start_reviewer"', prompt)
        self.assertIn("Return only the JSON contract", prompt)

    def test_build_pi_command_uses_cursor_nonfast_json_mode(self):
        cmd = self.contracts.build_pi_command(
            Path("/tmp/brief.md"), model="composer-2.5", effort=None
        )
        self.assertEqual(cmd[:4], ["pi", "--provider", "cursor", "--model"])
        self.assertIn("composer-2.5", cmd)
        self.assertIn("--cursor-no-fast", cmd)
        self.assertIn("--mode", cmd)
        self.assertIn("json", cmd)
        self.assertIn("@/tmp/brief.md", cmd)

    def test_extracts_contract_from_cursor_jsonl_final_message(self):
        contract = json.dumps(base_author_result())
        raw = "\n".join(
            [
                json.dumps({"type": "message_update", "assistantMessageEvent": {"delta": "x"}}),
                json.dumps(
                    {
                        "type": "message_end",
                        "message": {
                            "role": "assistant",
                            "content": [{"type": "text", "text": contract}],
                        },
                    }
                ),
            ]
        )
        parsed = self.contracts.extract_result_contract(raw)
        self.assertEqual(parsed["task_id"], "m03-openac-baseline")

    def test_cli_validates_contract_file_and_prints_next_action(self):
        with tempfile.TemporaryDirectory() as tmp:
            contract_path = Path(tmp) / "author.json"
            contract_path.write_text(json.dumps(base_author_result()), encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(MODULE_PATH),
                    "validate",
                    str(contract_path),
                    "--task-id",
                    "m03-openac-baseline",
                    "--role",
                    "author",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["ok"], True)
        self.assertEqual(parsed["next"], "start_reviewer")


if __name__ == "__main__":
    unittest.main()

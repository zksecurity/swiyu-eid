"""Claim CLI tests."""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

SEMANTICS = Path(__file__).resolve().parents[1]
CLAIMS = SEMANTICS / "claims"
PYTHON = sys.executable


class TestClaimCli(unittest.TestCase):
    def _run(self, *args):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(SEMANTICS)
        return subprocess.run(
            [PYTHON, "-m", "semantics.claim_cli", *args],
            cwd=str(SEMANTICS),
            capture_output=True,
            text=True,
            env=env,
        )

    def test_check_clearance_claim(self):
        proc = self._run("check", "--claim", str(CLAIMS / "clearance-status.json"))
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "ok")

    def test_explain_includes_where(self):
        proc = self._run("explain", "--claim", str(CLAIMS / "clearance-status.json"))
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        payload = json.loads(proc.stdout)
        self.assertIn("where", payload)

    def test_plan_public_metadata_only(self):
        proc = self._run("plan", "--claim", str(CLAIMS / "clearance-status.json"))
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        payload = json.loads(proc.stdout)
        self.assertTrue(payload["cases"])
        self.assertNotIn("fixture", proc.stdout)
        self.assertNotIn("given", json.dumps(payload["cases"][0]))


if __name__ == "__main__":
    unittest.main()

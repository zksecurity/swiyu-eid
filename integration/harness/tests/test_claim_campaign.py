"""CAMPAIGN claims-demo RED gate — transparent provider functional + privacy findings."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ZKBENCH = ROOT / "zkbench.py"
SEMANTICS = Path(__file__).resolve().parents[2] / "semantics"
CLEARANCE = SEMANTICS / "claims" / "clearance-status.json"


class TestClaimsDemo(unittest.TestCase):
    def _run(self, *args):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(SEMANTICS) + os.pathsep + env.get("PYTHONPATH", "")
        return subprocess.run(
            [sys.executable, str(ZKBENCH), *args],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            env=env,
        )

    def test_claims_demo_functional_report_with_privacy_findings(self):
        with tempfile.TemporaryDirectory(prefix="claims-demo-") as out:
            proc = self._run(
                "claims-demo",
                "--claim",
                str(CLEARANCE),
                "--output",
                out,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            report_path = Path(out) / "report.json"
            self.assertTrue(report_path.is_file(), "missing report.json")
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["overall"], "passed")
            self.assertTrue(report.get("cases"))
            privacy = report.get("privacy", {})
            self.assertEqual(privacy.get("status"), "findings")
            self.assertTrue(privacy.get("findings"))
            self.assertTrue((Path(out) / "report.html").is_file())


if __name__ == "__main__":
    unittest.main()

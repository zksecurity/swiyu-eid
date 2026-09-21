"""CAMPAIGN harden RED — claims-demo accept-all, replay, identities, manifest."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import claim_campaign
from provider_client import ProviderClient
from semantics.claims import load_claim
from semantics.planner import plan_campaign_cases

ROOT = Path(__file__).resolve().parents[1]
ZKBENCH = ROOT / "zkbench.py"
SEMANTICS = Path(__file__).resolve().parents[2] / "semantics"
CLEARANCE = SEMANTICS / "claims" / "clearance-status.json"
PROVIDERS = ROOT.parent / "providers"
MANIFEST = PROVIDERS / "semantic-reference" / "manifest.json"
PROFILE = "swiyu.semantic-reference.v0"


class TestClaimsDemoHardening(unittest.TestCase):
    def _run_demo(self, output: str, *extra: str):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(SEMANTICS) + os.pathsep + env.get("PYTHONPATH", "")
        return subprocess.run(
            [
                os.environ.get("SWIYU_TEST_PYTHON") or __import__("sys").executable,
                str(ZKBENCH),
                "claims-demo",
                "--claim",
                str(CLEARANCE),
                "--output",
                output,
                *extra,
            ],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            env=env,
        )

    def test_accept_all_preserves_expected_answers_and_campaign_identity(self):
        with tempfile.TemporaryDirectory(prefix="harden-honest-") as honest_dir:
            with tempfile.TemporaryDirectory(prefix="harden-accept-") as accept_dir:
                honest = self._run_demo(honest_dir)
                injected = self._run_demo(accept_dir, "--inject-accept-all")
                self.assertTrue(
                    (Path(honest_dir) / "report.json").is_file(),
                    honest.stderr + honest.stdout,
                )
                self.assertTrue(
                    (Path(accept_dir) / "report.json").is_file(),
                    injected.stderr + injected.stdout,
                )
                honest_report = json.loads(
                    (Path(honest_dir) / "report.json").read_text(encoding="utf-8")
                )
                accept_report = json.loads(
                    (Path(accept_dir) / "report.json").read_text(encoding="utf-8")
                )
                honest_expected = [c["expected_verdict"] for c in honest_report["cases"]]
                accept_expected = [c["expected_verdict"] for c in accept_report["cases"]]
                self.assertEqual(honest_expected, accept_expected)
                self.assertEqual(
                    honest_report["campaign_identity"],
                    accept_report["campaign_identity"],
                )
                self.assertNotEqual(
                    honest_report["implementation_identity"],
                    "",
                )
                positives = [c for c in accept_report["cases"] if c["expected_verdict"] is True]
                negatives = [c for c in accept_report["cases"] if c["expected_verdict"] is False]
                self.assertTrue(positives, "accept-all run missing positive cases")
                self.assertTrue(negatives, "accept-all run missing genuine negative cases")
                for case in positives:
                    self.assertEqual(case["outcome"], "passed", case)
                for case in negatives:
                    self.assertEqual(case["outcome"], "failed", case)

    def test_report_has_three_identities_and_per_stage_harness_timing(self):
        with tempfile.TemporaryDirectory(prefix="harden-ids-") as out:
            proc = self._run_demo(out)
            report = json.loads((Path(out) / "report.json").read_text(encoding="utf-8"))
            html = (Path(out) / "report.html").read_text(encoding="utf-8")
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            for key in (
                "statement_identity",
                "implementation_identity",
                "campaign_identity",
            ):
                self.assertTrue(report.get(key), key)
                self.assertIn(str(report[key])[:12], html)
            timings = report["stage_timings"]
            for stage in ("initialize", "prepare", "present", "verify", "cleanup"):
                self.assertIn(stage, timings)
                self.assertIsInstance(timings[stage], (int, float))
            self.assertIn("e2e", timings)

    def test_manifest_does_not_embed_tempfile_interpreter(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        command = manifest["command"]
        joined = " ".join(command)
        self.assertNotIn("/private/tmp", joined)
        self.assertNotIn("venv/bin", joined)
        self.assertEqual(command[0], "python3")
        self.assertEqual(command[1], "provider.py")


class TestVerifierReplayHardening(unittest.TestCase):
    def test_replay_presentation_against_independent_given_nonce(self):
        claim = load_claim(CLEARANCE)
        planned = plan_campaign_cases(claim, seed=1, max_cases=8)
        positive = next(c for c in planned if c.expected_verdict is True)
        independent = copy.deepcopy(positive.given)
        independent["session"] = dict(independent["session"])
        independent["session"]["nonce"] = independent["session"]["nonce"] + "-changed"

        env_path = os.environ.get("PATH", "")
        bindir = str(Path(__import__("sys").executable).parent)
        os.environ["PATH"] = bindir + os.pathsep + env_path
        try:
            with ProviderClient(str(MANIFEST), timeout=15.0) as client:
                client.call("initialize", {})
                prep = client.call(
                    "prepare",
                    {
                        "profile": PROFILE,
                        "statement_digest": claim.statement_digest,
                        "fixture": positive.fixture,
                        "given": positive.given,
                        "release": claim.document.get("release", {}),
                    },
                )
                presented = client.call(
                    "present",
                    {"profile": PROFILE, "handle": prep["handle"]},
                )
                verified = client.call(
                    "verify",
                    {
                        "profile": PROFILE,
                        "presentation": presented["presentation"],
                        "claim_path": str(CLEARANCE.resolve()),
                        "given": independent,
                    },
                )
                client.call("cleanup", {})
        finally:
            os.environ["PATH"] = env_path

        self.assertIs(verified.get("verified"), False)
        self.assertNotEqual(verified.get("stage"), "accepted")
        self.assertNotEqual(verified.get("stage"), "verifier_accepted")

    def test_run_claims_demo_accepts_explicit_support_path(self):
        import hashlib
        import shutil

        from semantics.support import SupportError

        support_src = PROVIDERS / "semantic-reference" / "support.json"
        with tempfile.TemporaryDirectory(prefix="harden-alt-support-") as tmp:
            alt = Path(tmp)
            shutil.copy(PROVIDERS / "semantic-reference" / "provider.py", alt / "provider.py")
            (alt / "manifest.json").write_text(
                json.dumps(
                    {
                        "schema": "swiyu.provider-manifest.v1",
                        "id": "alt-reference",
                        "title": "Alternate support",
                        "kind": "test-only",
                        "profiles": ["swiyu.semantic-reference.v0"],
                        "command": ["python3", "provider.py"],
                    }
                ),
                encoding="utf-8",
            )
            doc = json.loads(support_src.read_text(encoding="utf-8"))
            doc["supported_claims"] = [
                entry
                for entry in doc["supported_claims"]
                if entry["id"] != "test.clearance-status.v1"
            ]
            doc["approved_roots"] = []
            provider_sha = hashlib.sha256((alt / "provider.py").read_bytes()).hexdigest()
            manifest_sha = hashlib.sha256((alt / "manifest.json").read_bytes()).hexdigest()
            doc["artifact_pins"] = [
                {"path": "provider.py", "sha256": provider_sha},
                {"path": "manifest.json", "sha256": manifest_sha},
            ]
            support_path = alt / "support.json"
            support_path.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaises(SupportError):
                claim_campaign.run_claims_demo(
                    claim_path=str(CLEARANCE),
                    output=str(alt / "out"),
                    manifest_path=str(alt / "manifest.json"),
                    support_path=str(support_path),
                )


if __name__ == "__main__":
    unittest.main()

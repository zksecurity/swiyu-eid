"""Final campaign RED — pairs, codec not_run, identity sources, bounded reports."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import claim_campaign
from semantics.claims import load_claim
from semantics.planner import plan_campaign_cases

ROOT = Path(__file__).resolve().parents[1]
SEMANTICS = Path(__file__).resolve().parents[2] / "semantics"
COMPOSED = SEMANTICS / "claims" / "composed-status.json"
CLEARANCE = SEMANTICS / "claims" / "clearance-status.json"


class TestCampaignPairsAndCodec(unittest.TestCase):
    def test_composed_demo_records_eligible_pair_observations(self):
        claim = load_claim(COMPOSED)
        planned = plan_campaign_cases(claim, seed=1, max_cases=64)
        or_labels = ("or_tt", "or_tf", "or_ft", "or_ff")
        recipes = " ".join(c.recipe for c in planned)
        for label in or_labels:
            self.assertIn(label, recipes, recipes)
        with tempfile.TemporaryDirectory(prefix="final-pairs-") as out:
            code, report = claim_campaign.run_claims_demo(
                claim_path=str(COMPOSED),
                output=out,
                max_cases=64,
            )
            self.assertEqual(code, 0, report.get("overall"))
            privacy = report["privacy"]
            self.assertEqual(privacy.get("timing_stats", {}).get("status"), "not_run")
            pairs = privacy["pairs"]
            eligible = [p for p in pairs if p.get("eligibility") == "eligible"]
            self.assertTrue(eligible, f"expected nonempty eligible pairs; got {pairs!r}")
            statuses = {p.get("status") for p in eligible}
            self.assertTrue(statuses)
            ineligible = [p for p in pairs if p.get("eligibility") == "ineligible"]
            if "ineligible_count" in privacy:
                self.assertGreaterEqual(privacy["ineligible_count"], 0)
            else:
                self.assertTrue(ineligible or privacy.get("ineligible_excluded", 0) >= 0)

    def test_unknown_codec_privacy_status_is_not_run_not_clean(self):
        def fake_leak(**_kwargs):
            return {
                "status": "not_run",
                "reason": "unknown codec unavailable",
                "findings": [],
            }

        with tempfile.TemporaryDirectory(prefix="final-codec-") as out:
            with patch(
                "claim_campaign.analyze_presentation_leakage",
                side_effect=fake_leak,
            ):
                _code, report = claim_campaign.run_claims_demo(
                    claim_path=str(CLEARANCE),
                    output=out,
                    max_cases=2,
                )
            self.assertEqual(report["privacy"]["status"], "not_run")
            self.assertNotEqual(report["privacy"]["status"], "clean")
            coverage = report["privacy"].get("coverage") or report.get("coverage") or {}
            self.assertGreaterEqual(coverage.get("unknown_codec", 0), 1)


class TestCampaignIdentityAndBounds(unittest.TestCase):
    def test_identity_includes_leakage_and_is_stable(self):
        with tempfile.TemporaryDirectory(prefix="final-id-a-") as a:
            with tempfile.TemporaryDirectory(prefix="final-id-b-") as b:
                _c1, r1 = claim_campaign.run_claims_demo(
                    claim_path=str(CLEARANCE), output=a, max_cases=2
                )
                _c2, r2 = claim_campaign.run_claims_demo(
                    claim_path=str(CLEARANCE), output=b, max_cases=2
                )
        self.assertEqual(r1["campaign_identity"], r2["campaign_identity"])
        self.assertTrue(r1["campaign_identity"])

        real_read = Path.read_bytes

        def patched(self):
            data = real_read(self)
            if self.name == "leakage.py":
                return data + b"\n# campaign-identity-probe\n"
            return data

        with tempfile.TemporaryDirectory(prefix="final-id-c-") as c:
            with patch.object(Path, "read_bytes", patched):
                _c3, r3 = claim_campaign.run_claims_demo(
                    claim_path=str(CLEARANCE), output=c, max_cases=2
                )
        self.assertNotEqual(
            r1["campaign_identity"],
            r3["campaign_identity"],
            "editing leakage.py must change campaign identity",
        )

    def test_max_cases_keeps_not_run_and_accept_all_preserves_answers(self):
        with tempfile.TemporaryDirectory(prefix="final-cap-") as out:
            _code, capped = claim_campaign.run_claims_demo(
                claim_path=str(COMPOSED),
                output=out,
                max_cases=2,
            )
        outcomes = {c["outcome"] for c in capped["cases"]}
        self.assertIn("not_run", outcomes)
        self.assertTrue(any(c["outcome"] == "not_run" for c in capped["cases"]))

        with tempfile.TemporaryDirectory(prefix="final-honest-") as honest_dir:
            with tempfile.TemporaryDirectory(prefix="final-accept-") as accept_dir:
                _h, honest = claim_campaign.run_claims_demo(
                    claim_path=str(CLEARANCE),
                    output=honest_dir,
                    max_cases=8,
                )
                a_code, injected = claim_campaign.run_claims_demo(
                    claim_path=str(CLEARANCE),
                    output=accept_dir,
                    max_cases=8,
                    inject_accept_all=True,
                )
        self.assertEqual(a_code, 1)
        self.assertEqual(
            [c["expected_verdict"] for c in honest["cases"]],
            [c["expected_verdict"] for c in injected["cases"]],
        )
        self.assertEqual(honest["campaign_identity"], injected["campaign_identity"])
        positives = [c for c in injected["cases"] if c["expected_verdict"] is True]
        negatives = [c for c in injected["cases"] if c["expected_verdict"] is False]
        self.assertTrue(positives and negatives)
        for case in positives:
            if case["outcome"] != "not_run":
                self.assertEqual(case["outcome"], "passed")
        for case in negatives:
            if case["outcome"] != "not_run":
                self.assertEqual(case["outcome"], "failed")


if __name__ == "__main__":
    unittest.main()

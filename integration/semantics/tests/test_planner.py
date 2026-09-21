"""CAMPAIGN planner RED gate — behavioral cases from complete claims."""

import unittest
from pathlib import Path

from semantics.claims import load_claim
from semantics.planner import PlanCase, plan_campaign_cases

CLAIMS_DIR = Path(__file__).resolve().parents[1] / "claims"


class TestPlannerCampaignCases(unittest.TestCase):
    def test_clearance_derives_positive_and_false_where(self):
        claim = load_claim(CLAIMS_DIR / "clearance-status.json")
        cases = plan_campaign_cases(claim, seed=1)
        self.assertGreaterEqual(len(cases), 2)
        ids = [c.id for c in cases]
        self.assertEqual(len(ids), len(set(ids)))
        positives = [c for c in cases if c.expected_verdict is True]
        false_where = [
            c
            for c in cases
            if c.expected_verdict is False and c.expectation_basis == "where_false"
        ]
        self.assertTrue(positives, "missing positive control")
        self.assertTrue(false_where, "missing false where case")
        for case in cases:
            self.assertIsInstance(case, PlanCase)
            self.assertTrue(case.recipe)
            self.assertIn(
                case.expectation_basis,
                (
                    "positive_control",
                    "where_true",
                    "where_false",
                    "assertion_failure",
                    "not_run",
                ),
            )

    def test_composed_or_claim_includes_constructible_branch_variants(self):
        claim = load_claim(CLAIMS_DIR / "composed-status.json")
        cases = plan_campaign_cases(claim, seed=1, max_cases=64)
        bases = {c.expectation_basis for c in cases}
        self.assertIn("positive_control", bases)
        self.assertIn("where_false", bases)


if __name__ == "__main__":
    unittest.main()

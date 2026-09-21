"""Shared age-25 holder-challenge claim: same statement both ZK providers declare."""

from __future__ import annotations

import unittest
from pathlib import Path

from semantics.claims import load_claim
from semantics.predicates import evaluate_predicate

SEMANTICS = Path(__file__).resolve().parents[1]
CLAIM_PATH = SEMANTICS / "claims" / "age25-holder-challenge.json"
EPFL_CLAIM_PATH = SEMANTICS / "claims" / "epfl-d10-age25-jwt.json"

SHARED_OPERATIONS = {
    "credential.authentic@1",
    "presentation.challenge-bound@1",
    "holder.signature-valid@1",
}

EXCLUDED_OPERATIONS = {
    "credential.expected-metadata@1",
    "credential.valid-at@1",
    "presentation.context-bound@1",
    "status.zero-at-reference@1",
}


class TestSharedAge25Claim(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.claim = load_claim(CLAIM_PATH)
        cls.epfl = load_claim(EPFL_CLAIM_PATH)

    def test_claim_id_is_shared_not_backend_branded(self) -> None:
        self.assertEqual(self.claim.document["id"], "swiyu.shared.age25-holder-challenge.v0")
        self.assertNotEqual(self.claim.document["id"], self.epfl.document["id"])

    def test_obligations_match_epfl_d10_statement(self) -> None:
        operations = {entry["assert"] for entry in self.claim.document["require"]}
        self.assertEqual(operations, SHARED_OPERATIONS)
        self.assertTrue(EXCLUDED_OPERATIONS.isdisjoint(operations))
        epfl_ops = {entry["assert"] for entry in self.epfl.document["require"]}
        self.assertEqual(operations, epfl_ops)
        self.assertEqual(
            self.claim.document["where"],
            self.epfl.document["where"],
        )
        self.assertEqual(self.claim.document["release"], self.epfl.document["release"])
        self.assertEqual(self.claim.document["attributes"], self.epfl.document["attributes"])
        self.assertEqual(self.claim.document["given"], self.epfl.document["given"])

    def test_statement_digest_differs_only_because_claim_id_differs(self) -> None:
        self.assertNotEqual(self.claim.statement_digest, self.epfl.statement_digest)
        self.assertEqual(len(self.claim.statement_digest), 64)

    def test_yyyymmdd_age_gate_matches_both_circuits(self) -> None:
        types = {
            "birthdate": "swiyu.date@0",
            "reference": "swiyu.date-yyyymmdd@0",
            "min_years": "swiyu.unix-seconds@0",
        }
        self.assertTrue(
            evaluate_predicate(
                "date.yyyymmdd-age-at-least@1",
                {"birthdate": "1988-06-19", "reference": 20130619, "min_years": "25"},
                types,
            )
        )
        self.assertFalse(
            evaluate_predicate(
                "date.yyyymmdd-age-at-least@1",
                {"birthdate": "1988-06-19", "reference": 20130618, "min_years": "25"},
                types,
            )
        )


if __name__ == "__main__":
    unittest.main()

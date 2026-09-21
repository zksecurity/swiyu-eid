"""EPFL d10 bounded semantic claim and support bridge."""

from __future__ import annotations

import copy
import hashlib
import unittest
from pathlib import Path

from semantics.assertions import evaluate_claim
from semantics.canonical import canonical_json_bytes
from semantics.claims import Claim, load_claim, validate_claim
from semantics.fixtures import make_fixture
from semantics.support import SupportError, load_support, verify_claim_supported

SEMANTICS = Path(__file__).resolve().parents[1]
CLAIM_PATH = SEMANTICS / "claims" / "epfl-d10-age25-jwt.json"
EPFL = SEMANTICS.parent / "providers" / "epfl"


class TestEpflSemanticBridge(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.claim = load_claim(CLAIM_PATH)

    def test_bounded_claim_matches_circuit_obligations(self) -> None:
        doc = self.claim.document
        operations = {entry["assert"] for entry in doc["require"]}
        self.assertEqual(
            operations,
            {
                "credential.authentic@1",
                "presentation.challenge-bound@1",
                "holder.signature-valid@1",
            },
        )
        self.assertNotIn("credential.expected-metadata@1", operations)
        self.assertNotIn("status.zero-at-reference@1", operations)
        self.assertNotIn("presentation.context-bound@1", operations)
        self.assertNotIn("credential.valid-at@1", operations)
        self.assertEqual(doc["where"]["predicate"], "date.yyyymmdd-age-at-least@1")
        self.assertEqual(doc["where"]["args"]["min_years"], {"const": "25"})
        self.assertEqual(doc["release"]["semantic_values"], ["acceptance"])
        self.assertEqual(doc["packages"]["assertions"], "platform.epfl-d10@1")

    def test_yyyymmdd_age_predicate_matches_circuit_rule(self) -> None:
        from semantics.predicates import evaluate_predicate

        ok = evaluate_predicate(
            "date.yyyymmdd-age-at-least@1",
            {"birthdate": "1988-06-19", "reference": 20240101, "min_years": "25"},
            {
                "birthdate": "swiyu.date@0",
                "reference": "swiyu.date-yyyymmdd@0",
                "min_years": "swiyu.unix-seconds@0",
            },
        )
        self.assertTrue(ok)
        boundary_fail = evaluate_predicate(
            "date.yyyymmdd-age-at-least@1",
            {"birthdate": "1988-06-19", "reference": 20130618, "min_years": "25"},
            {
                "birthdate": "swiyu.date@0",
                "reference": "swiyu.date-yyyymmdd@0",
                "min_years": "swiyu.unix-seconds@0",
            },
        )
        self.assertFalse(boundary_fail)

    def test_support_loads_after_manifest_exists(self) -> None:
        support_path = EPFL / "support.json"
        if not support_path.is_file():
            self.skipTest("support.json not yet published")
        support = load_support(support_path)
        verify_claim_supported(
            support,
            claim_id=self.claim.document["id"],
            statement_digest=self.claim.statement_digest,
            claim=self.claim,
            implementation_profile="epfl-d10-swiyu-jwt-age25-v0",
            circuit="d10_swiyu_jwt",
        )

    def test_support_also_registers_the_shared_age25_claim(self) -> None:
        shared = load_claim(SEMANTICS / "claims" / "age25-holder-challenge.json")
        support = load_support(EPFL / "support.json")
        verify_claim_supported(
            support,
            claim_id=shared.document["id"],
            statement_digest=shared.statement_digest,
            claim=shared,
            implementation_profile="epfl-d10-swiyu-jwt-age25-v0",
            circuit="d10_swiyu_jwt",
        )

    def test_claim_digest_drift_is_rejected(self) -> None:
        support_path = EPFL / "support.json"
        if not support_path.is_file():
            self.skipTest("support.json not yet published")
        original = load_claim(CLAIM_PATH)
        drifted_doc = copy.deepcopy(original.document)
        drifted_doc["where"]["args"]["min_years"] = {"const": "26"}
        dependencies = dict(original.dependencies)
        drifted_digest = hashlib.sha256(
            canonical_json_bytes({"claim": drifted_doc, "dependencies": dependencies})
        ).hexdigest()
        drifted = Claim(
            _document=drifted_doc,
            statement_digest=drifted_digest,
            _dependencies=dependencies,
        )
        support = load_support(support_path)
        with self.assertRaisesRegex(SupportError, "claim digest does not match"):
            verify_claim_supported(
                support,
                claim_id=drifted.document["id"],
                statement_digest=original.statement_digest,
                claim=drifted,
                implementation_profile="epfl-d10-swiyu-jwt-age25-v0",
                circuit="d10_swiyu_jwt",
            )


if __name__ == "__main__":
    unittest.main()

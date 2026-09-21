"""Public full-claim APIs validate hand-constructed Claim objects too."""
import unittest
from pathlib import Path

from semantics.assertions import evaluate_claim
from semantics.canonical import canonical_digest
from semantics.claims import Claim, ClaimError, load_claim
from semantics.fixtures import make_fixture


class TestClaimAdmission(unittest.TestCase):
    def setUp(self):
        self.claim = load_claim(Path(__file__).resolve().parents[1] / "claims/composed-status.json")
        self.bundle = make_fixture(self.claim)

    def forged(self):
        document = self.claim.document
        document["require"] = [a for a in document["require"] if a["assert"] == "credential.authentic@1"]
        dependencies = self.claim.dependencies
        return Claim(document, canonical_digest({"claim": document, "dependencies": dependencies}), dependencies)

    def test_forged_claim_cannot_remove_obligations_at_evaluation(self):
        result = evaluate_claim(self.forged(), self.bundle["fixture"], self.bundle["given"])
        self.assertEqual(result, {"status": "invalid_input"})

    def test_fixture_factory_requires_complete_claim(self):
        with self.assertRaises(ClaimError):
            make_fixture(self.forged())

    def test_fixture_factory_rejects_stale_identity(self):
        stale = Claim(self.claim.document, "0" * 64, self.claim.dependencies)
        with self.assertRaises(ClaimError):
            make_fixture(stale)

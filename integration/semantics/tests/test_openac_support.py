"""OpenAC fixed-profile semantic support bridge."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from semantics.claims import load_claim, validate_claim
from semantics.support import SupportError, load_support, verify_claim_supported

SEMANTICS = Path(__file__).resolve().parents[1]
CLAIM_PATH = SEMANTICS / "claims" / "openac-age18-status-2k.json"
OPENAC = SEMANTICS.parent / "providers" / "openac"


class TestOpenACSemanticBridge(unittest.TestCase):
    def test_fixed_profile_claim_states_every_obligation(self):
        claim = load_claim(CLAIM_PATH)

        operations = {entry["assert"] for entry in claim.document["require"]}
        self.assertEqual(
            operations,
            {
                "credential.authentic@1",
                "credential.expected-metadata@1",
                "credential.valid-at@1",
                "holder.signature-valid@1",
                "presentation.context-bound@1",
                "status.zero-at-reference@1",
            },
        )
        self.assertEqual(claim.document["where"]["predicate"], "date.on-or-before@1")
        self.assertEqual(claim.document["where"]["args"]["value"], {"attribute": "birthdate"})
        self.assertEqual(claim.document["where"]["args"]["limit"], {"given": "age18_cutoff"})

    def test_openac_support_loads_and_verifies_fixed_profile_claim(self):
        claim = load_claim(CLAIM_PATH)
        support = load_support(OPENAC / "support.json")

        verify_claim_supported(
            support,
            claim_id=claim.document["id"],
            statement_digest=claim.statement_digest,
            claim=claim,
            implementation_profile="swiyu-age18-status-2k-v0",
            circuit="swiyu_age18_status_2k",
        )

    def test_claim_digest_drift_is_rejected(self):
        original_claim = load_claim(CLAIM_PATH)
        claim_document = copy.deepcopy(original_claim.document)
        claim_document["release"]["semantic_values"] = list(reversed(claim_document["release"]["semantic_values"]))
        drifted_claim = validate_claim(claim_document)
        support = load_support(OPENAC / "support.json")

        with self.assertRaisesRegex(SupportError, "claim digest does not match"):
            verify_claim_supported(
                support,
                claim_id=drifted_claim.document["id"],
                statement_digest=original_claim.statement_digest,
                claim=drifted_claim,
                implementation_profile="swiyu-age18-status-2k-v0",
                circuit="swiyu_age18_status_2k",
            )

    def test_openac_support_requires_every_claim_obligation(self):
        claim = load_claim(CLAIM_PATH)
        support = copy.deepcopy(load_support(OPENAC / "support.json"))
        del support["supported_claims"][0]["enforcement"]["status_freshness_validity"]

        with self.assertRaisesRegex(SupportError, "missing enforcement obligations"):
            verify_claim_supported(
                support,
                claim_id=claim.document["id"],
                statement_digest=claim.statement_digest,
                claim=claim,
                implementation_profile="swiyu-age18-status-2k-v0",
                circuit="swiyu_age18_status_2k",
            )

    def test_openac_also_registers_the_shared_age25_claim(self):
        claim = load_claim(SEMANTICS / "claims" / "age25-holder-challenge.json")
        support = load_support(OPENAC / "support.json")
        verify_claim_supported(
            support,
            claim_id=claim.document["id"],
            statement_digest=claim.statement_digest,
            claim=claim,
            implementation_profile="openac-age25-jwt-v0",
            circuit="swiyu_age25_jwt",
        )

    def test_wrong_profile_or_circuit_is_rejected(self):
        claim = load_claim(CLAIM_PATH)
        support = load_support(OPENAC / "support.json")

        with self.assertRaisesRegex(SupportError, "claim not registered"):
            verify_claim_supported(
                support,
                claim_id=claim.document["id"],
                statement_digest=claim.statement_digest,
                claim=claim,
                implementation_profile="swiyu-age18-status-2k-v0",
                circuit="another_circuit",
            )


if __name__ == "__main__":
    unittest.main()

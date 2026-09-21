"""Common accept/reject corpus for two ZK backends of one age-25 claim."""

from __future__ import annotations

import base64
import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
SEMANTICS = ROOT / "semantics"
EPFL = ROOT / "providers" / "epfl"
OPENAC = ROOT / "providers" / "openac"

sys.path.insert(0, str(SEMANTICS))
sys.path.insert(0, str(EPFL))

from semantics.assertions import evaluate_claim  # noqa: E402
from semantics.claims import load_claim  # noqa: E402
from semantics.support import load_support, verify_claim_supported  # noqa: E402

from fixtures import (  # noqa: E402
    KEY_ID,
    VARIANT_A,
    VARIANT_B,
    _build_variant,
    _jwk_from_private,
    canonical_given,
    fixture_bundle,
    fresh_challenge_hex,
    sign_holder_challenge,
)

CLAIM_PATH = SEMANTICS / "claims" / "age25-holder-challenge.json"
SHARED_CLAIM_ID = "swiyu.shared.age25-holder-challenge.v0"
ENFORCEMENT = {
    "issuer_authentication": "both",
    "challenge_binding": "both",
    "holder_authorization": "proof",
    "where": "both",
}


class SharedAge25Conformance(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.claim = load_claim(CLAIM_PATH)
        cls.digest = cls.claim.statement_digest
        cls.challenge = fresh_challenge_hex(b"shared-age25-corpus-v1")
        cls.epfl_support = load_support(EPFL / "support.json")
        cls.openac_support = load_support(OPENAC / "support.json")

    def test_both_providers_register_the_same_claim_identity(self) -> None:
        self.assertEqual(self.claim.document["id"], SHARED_CLAIM_ID)
        verify_claim_supported(
            self.epfl_support,
            claim_id=SHARED_CLAIM_ID,
            statement_digest=self.digest,
            claim=self.claim,
            implementation_profile="epfl-d10-swiyu-jwt-age25-v0",
            circuit="d10_swiyu_jwt",
        )
        verify_claim_supported(
            self.openac_support,
            claim_id=SHARED_CLAIM_ID,
            statement_digest=self.digest,
            claim=self.claim,
            implementation_profile="openac-age25-jwt-v0",
            circuit="swiyu_age25_jwt",
        )

    def test_backends_are_different_implementations_of_that_claim(self) -> None:
        epfl = next(
            row
            for row in self.epfl_support["supported_claims"]
            if row["id"] == SHARED_CLAIM_ID
        )
        openac = next(
            row
            for row in self.openac_support["supported_claims"]
            if row["id"] == SHARED_CLAIM_ID
        )
        self.assertEqual(epfl["statement_digest"], openac["statement_digest"])
        self.assertNotEqual(epfl["circuit"], openac["circuit"])
        self.assertNotEqual(epfl["implementation_profile"], openac["implementation_profile"])
        self.assertEqual(epfl["enforcement"], ENFORCEMENT)
        self.assertEqual(openac["enforcement"], ENFORCEMENT)

    def test_valid_adult_variants_are_accepted(self) -> None:
        for variant_id in (VARIANT_A.variant_id, VARIANT_B.variant_id):
            bundle = fixture_bundle(variant_id, self.challenge)
            result = evaluate_claim(self.claim, bundle["fixture"], bundle["given"])
            self.assertTrue(result["value"], result)

    def test_equivalent_hidden_birth_dates_share_public_meaning(self) -> None:
        a = fixture_bundle(VARIANT_A.variant_id, self.challenge)
        b = fixture_bundle(VARIANT_B.variant_id, self.challenge)
        self.assertNotEqual(a["witness"].birth_date, b["witness"].birth_date)
        self.assertEqual(a["given"], b["given"])
        self.assertTrue(evaluate_claim(self.claim, a["fixture"], a["given"])["value"])
        self.assertTrue(evaluate_claim(self.claim, b["fixture"], b["given"])["value"])

    def test_underage_credential_is_rejected(self) -> None:
        young = _build_variant("underage", "2010-01-01", "U9nderageSalt00001")
        given = canonical_given(self.challenge)
        fixture = {
            "credential": young.compact_sd_jwt,
            "holder_signature": sign_holder_challenge(bytes.fromhex(self.challenge)),
            "presentation_context": self.challenge,
        }
        self.assertFalse(evaluate_claim(self.claim, fixture, given)["value"])

    def test_age_boundary_rejects_the_day_before_25(self) -> None:
        from semantics.predicates import evaluate_predicate

        types = {
            "birthdate": "swiyu.date@0",
            "reference": "swiyu.date-yyyymmdd@0",
            "min_years": "swiyu.unix-seconds@0",
        }
        self.assertTrue(
            evaluate_predicate(
                "date.yyyymmdd-age-at-least@1",
                {"birthdate": "1999-01-02", "reference": 20240102, "min_years": "25"},
                types,
            )
        )
        self.assertFalse(
            evaluate_predicate(
                "date.yyyymmdd-age-at-least@1",
                {"birthdate": "1999-01-02", "reference": 20240101, "min_years": "25"},
                types,
            )
        )

    def test_wrong_issuer_key_is_rejected(self) -> None:
        bundle = fixture_bundle(VARIANT_A.variant_id, self.challenge)
        bad = copy.deepcopy(bundle["given"])
        bad["issuer"] = copy.deepcopy(bad["issuer"])
        bad["issuer"]["public_key"] = _jwk_from_private(0x1234, KEY_ID)
        self.assertFalse(evaluate_claim(self.claim, bundle["fixture"], bad)["value"])

    def test_wrong_holder_signature_is_rejected(self) -> None:
        bundle = fixture_bundle(VARIANT_A.variant_id, self.challenge)
        bad = copy.deepcopy(bundle["fixture"])
        sig = bytearray(base64.urlsafe_b64decode(bad["holder_signature"] + "=="))
        sig[0] ^= 0x01
        bad["holder_signature"] = base64.urlsafe_b64encode(bytes(sig)).rstrip(b"=").decode()
        self.assertFalse(evaluate_claim(self.claim, bad, bundle["given"])["value"])

    def test_replayed_or_wrong_nonce_is_rejected(self) -> None:
        bundle = fixture_bundle(VARIANT_A.variant_id, self.challenge)
        bad = copy.deepcopy(bundle["fixture"])
        bad["presentation_context"] = fresh_challenge_hex(b"replayed-nonce")
        self.assertFalse(evaluate_claim(self.claim, bad, bundle["given"])["value"])

    def test_openac_manifest_declares_the_age25_circuit(self) -> None:
        import json

        manifest = json.loads((OPENAC / "manifest.json").read_text(encoding="utf-8"))
        self.assertIn("openac-age25-jwt-v0", manifest["profiles"])
        self.assertIn("swiyu_age25_jwt", manifest["circuits"])

    def test_epfl_manifest_keeps_the_d10_circuit(self) -> None:
        import json

        manifest = json.loads((EPFL / "manifest.json").read_text(encoding="utf-8"))
        self.assertIn("epfl-d10-swiyu-jwt-age25-v0", manifest["profiles"])
        self.assertIn("d10_swiyu_jwt", manifest["circuits"])


if __name__ == "__main__":
    unittest.main()

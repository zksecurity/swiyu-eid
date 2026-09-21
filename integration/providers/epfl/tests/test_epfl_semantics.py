"""EPFL semantic fixture classification (independent of provider verdict)."""
from __future__ import annotations

import base64
import copy
import unittest
from pathlib import Path

from semantics.assertions import evaluate_claim
from semantics.claims import load_claim
from semantics.credentials import authenticate

from fixtures import (
    KEY_ID,
    VARIANT_A,
    VARIANT_B,
    _build_variant,
    _jwk_from_private,
    canonical_given,
    fixture_bundle,
    fresh_challenge_hex,
)

CLAIM = Path(__file__).resolve().parents[3] / "semantics" / "claims" / "epfl-d10-age25-jwt.json"


class EpflSemanticFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.claim = load_claim(CLAIM)
        cls.challenge = fresh_challenge_hex(b"epfl-test-challenge-v1")

    def test_authentic_variants_classify_eligible(self) -> None:
        for vid in (VARIANT_A.variant_id, VARIANT_B.variant_id):
            bundle = fixture_bundle(vid, self.challenge)
            paths = {"birth_date": "birth_date"}
            auth = authenticate(bundle["credential"], bundle["given"]["issuer"], paths)
            self.assertEqual(auth.attributes["birth_date"], bundle["witness"].birth_date)
            result = evaluate_claim(self.claim, bundle["fixture"], bundle["given"])
            self.assertTrue(result["value"], result)

    def test_same_public_meaning_different_hidden_dob(self) -> None:
        a = fixture_bundle(VARIANT_A.variant_id, self.challenge)
        b = fixture_bundle(VARIANT_B.variant_id, self.challenge)
        self.assertNotEqual(a["witness"].birth_date, b["witness"].birth_date)
        self.assertEqual(a["given"], b["given"])
        ra = evaluate_claim(self.claim, a["fixture"], a["given"])
        rb = evaluate_claim(self.claim, b["fixture"], b["given"])
        self.assertTrue(ra["value"] and rb["value"])

    def test_wrong_issuer_key_rejected(self) -> None:
        bundle = fixture_bundle(VARIANT_A.variant_id, self.challenge)
        bad = copy.deepcopy(bundle["given"])
        bad["issuer"] = copy.deepcopy(bad["issuer"])
        forged = _jwk_from_private(0x1234, KEY_ID)
        bad["issuer"]["public_key"] = forged
        result = evaluate_claim(self.claim, bundle["fixture"], bad)
        self.assertFalse(result["value"])

    def test_age_boundary_ineligible(self) -> None:
        young = _build_variant("underage", "2010-01-01", "U9nderageSalt00001")
        given = canonical_given(self.challenge)
        challenge_bytes = bytes.fromhex(self.challenge)
        from fixtures import sign_holder_challenge

        fixture = {
            "credential": young.compact_sd_jwt,
            "holder_signature": sign_holder_challenge(challenge_bytes),
            "presentation_context": self.challenge,
        }
        result = evaluate_claim(self.claim, fixture, given)
        self.assertFalse(result["value"])

    def test_altered_nonce_rejected(self) -> None:
        bundle = fixture_bundle(VARIANT_A.variant_id, self.challenge)
        bad = copy.deepcopy(bundle["fixture"])
        bad["presentation_context"] = fresh_challenge_hex(b"wrong")
        result = evaluate_claim(self.claim, bad, bundle["given"])
        self.assertFalse(result["value"])

    def test_wrong_holder_signature_rejected(self) -> None:
        bundle = fixture_bundle(VARIANT_A.variant_id, self.challenge)
        bad = copy.deepcopy(bundle["fixture"])
        sig = bytearray(base64.urlsafe_b64decode(bad["holder_signature"] + "=="))
        sig[0] ^= 0x01
        bad["holder_signature"] = base64.urlsafe_b64encode(bytes(sig)).rstrip(b"=").decode()
        result = evaluate_claim(self.claim, bad, bundle["given"])
        self.assertFalse(result["value"])


if __name__ == "__main__":
    unittest.main()

"""Synthetic fixture factory tests."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from semantics.assertions import evaluate_claim, expected_transcript
from semantics.canonical import canonical_json_bytes
from semantics.claims import load_claim, validate_claim
from semantics.credentials import authenticate
from semantics.fixtures import make_fixture

from tests.test_claims import COMPOSED_CLAIM

CLAIMS_DIR = Path(__file__).resolve().parents[1] / "claims"


def _claim():
    return validate_claim(copy.deepcopy(COMPOSED_CLAIM))


class TestMakeFixture(unittest.TestCase):
    def test_fixture_is_coherently_signed(self) -> None:
        claim = _claim()
        bundle = make_fixture(claim, seed=3)
        fixture = bundle["fixture"]
        given = bundle["given"]

        paths = {
            alias: spec["path"][0]
            for alias, spec in claim.document["attributes"].items()
        }
        credential = authenticate(
            fixture["credential"],
            given["issuer"],
            paths,
        )
        self.assertEqual(credential.issuer_id, given["issuer"]["issuer_id"])
        transcript = expected_transcript(claim, given)
        self.assertEqual(fixture["presentation_context"], transcript.hex())

        result = evaluate_claim(claim, fixture, given)
        self.assertTrue(result["value"])

    def test_nbf_exp_keyword_controls_validity(self) -> None:
        claim = _claim()
        bundle = make_fixture(claim, seed=4, nbf=1_800_000_001, exp=1_900_000_000)
        result = evaluate_claim(claim, bundle["fixture"], bundle["given"])
        self.assertFalse(result["assertions"]["validity"]["value"])

        bundle2 = make_fixture(claim, seed=4, nbf=1_700_000_000, exp=1_800_000_000)
        result2 = evaluate_claim(claim, bundle2["fixture"], bundle2["given"])
        self.assertFalse(result2["assertions"]["validity"]["value"])

    def test_given_overrides_without_breaking_signatures(self) -> None:
        claim = _claim()
        bundle = make_fixture(
            claim,
            seed=5,
            given_overrides={"session": {"nonce": "campaign-nonce"}},
        )
        transcript = expected_transcript(claim, bundle["given"])
        self.assertEqual(bundle["fixture"]["presentation_context"], transcript.hex())
        self.assertEqual(bundle["given"]["session"]["nonce"], "campaign-nonce")
        result = evaluate_claim(claim, bundle["fixture"], bundle["given"])
        self.assertTrue(result["value"])

    def test_same_seed_is_byte_identical(self) -> None:
        claim = _claim()
        first = make_fixture(claim, seed=6)
        second = make_fixture(claim, seed=6)
        self.assertEqual(first["fixture"], second["fixture"])
        self.assertEqual(first["given"], second["given"])

    def test_hidden_attribute_change_preserves_given_identity(self) -> None:
        claim = _claim()
        base = make_fixture(claim, seed=6)
        variant = make_fixture(
            claim,
            attributes={"nationality": "DE"},
            seed=6,
        )
        self.assertEqual(
            canonical_json_bytes(base["given"]),
            canonical_json_bytes(variant["given"]),
        )
        self.assertNotEqual(base["fixture"]["credential"], variant["fixture"]["credential"])

    def test_cutoff_claim_does_not_invent_extra_given(self) -> None:
        claim = load_claim(CLAIMS_DIR / "cutoff-status.json")
        bundle = make_fixture(claim, seed=1)
        self.assertEqual(
            set(bundle["given"].keys()),
            set(claim.document["given"].keys()),
        )
        self.assertNotIn("allowed_nationalities", bundle["given"])

    def test_generic_date_alias_default_is_valid(self) -> None:
        document = copy.deepcopy(COMPOSED_CLAIM)
        document["attributes"]["issued_on"] = {
            "credential": "eid",
            "path": ["issued_on"],
            "type": "swiyu.date@0",
        }
        claim = validate_claim(document)
        bundle = make_fixture(claim, seed=2)
        paths = {alias: spec["path"][0] for alias, spec in claim.document["attributes"].items()}
        credential = authenticate(bundle["fixture"]["credential"], bundle["given"]["issuer"], paths)
        self.assertEqual(credential.attributes["issued_on"], "2000-01-01")

    def test_issuer_id_override_is_not_silently_replaced(self) -> None:
        claim = _claim()
        bundle = make_fixture(
            claim,
            seed=3,
            given_overrides={"issuer": {"issuer_id": "did:example:override"}},
        )
        self.assertEqual(bundle["given"]["issuer"]["issuer_id"], "did:example:override")


if __name__ == "__main__":
    unittest.main()

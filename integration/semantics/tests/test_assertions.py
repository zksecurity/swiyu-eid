"""Assertion evaluation and adversarial campaign tests."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature

from semantics.assertions import evaluate_claim, expected_transcript
from semantics.claims import load_claim, validate_claim
from semantics.fixtures import derive_fixture_private_key, make_fixture, reauthorize_fixture

from tests.helpers.sd_jwt_fixture import SdJwtFixtureBuilder
from tests.test_claims import COMPOSED_CLAIM

CLAIMS_DIR = Path(__file__).resolve().parents[1] / "claims"


def _b64url(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _composed() :
    return validate_claim(copy.deepcopy(COMPOSED_CLAIM))


def _cutoff():
    return load_claim(CLAIMS_DIR / "cutoff-status.json")


def _composed_file():
    return load_claim(CLAIMS_DIR / "composed-status.json")


def _no_status_claim():
    document = json.loads((CLAIMS_DIR / "cutoff-status.json").read_text(encoding="utf-8"))
    document["id"] = "test.cutoff-nostatus.v1"
    document["require"] = [
        entry for entry in document["require"] if entry["assert"] != "status.zero-at-reference@1"
    ]
    del document["given"]["status"]
    for entry in document["require"]:
        if entry["assert"] == "presentation.context-bound@1":
            entry["args"].pop("status", None)
    return validate_claim(document)


def _renamed_claim():
    document = json.loads((CLAIMS_DIR / "composed-status.json").read_text(encoding="utf-8"))
    raw = json.dumps(document)
    raw = raw.replace('"eid"', '"card"')
    raw = raw.replace("eid.", "card.")
    document = json.loads(raw)
    document["id"] = "test.renamed-aliases.v1"
    document["attributes"]["dob"] = document["attributes"].pop("birthdate")
    document["attributes"]["nat"] = document["attributes"].pop("nationality")
    document["attributes"]["home"] = document["attributes"].pop("residence")
    document["given"]["trusted_issuer"] = document["given"].pop("issuer")
    document["given"]["clock"] = document["given"].pop("now")
    document["given"]["age_limit"] = document["given"].pop("cutoff")
    document["given"]["status_ref"] = document["given"].pop("status")
    document["given"]["nats"] = document["given"].pop("allowed_nationalities")
    document["given"]["must_live"] = document["given"].pop("required_residence")
    rename_ids = {
        "issuer_authentication": "auth_gate",
        "metadata": "meta_gate",
        "validity": "time_gate",
        "holder_authorization": "holder_gate",
        "session_binding": "bind_gate",
        "status": "status_gate",
    }
    for entry in document["require"]:
        entry["id"] = rename_ids[entry["id"]]
        args = entry["args"]
        if "issuer" in args:
            args["issuer"] = {"given": "trusted_issuer"}
        if "time" in args:
            args["time"] = {"given": "clock"}
        if "reference" in args:
            args["reference"] = {"given": "status_ref"}
        if "transcript" in args:
            args["transcript"] = {"assertion": "bind_gate", "output": "expected_transcript"}
        if entry["assert"] == "presentation.context-bound@1":
            args["session"] = {"given": "session"}
            args["age_limit"] = {"given": "age_limit"}
            args["clock"] = {"given": "clock"}
            args["status_ref"] = {"given": "status_ref"}
            args["nats"] = {"given": "nats"}
            args["must_live"] = {"given": "must_live"}
            args.pop("cutoff", None)
            args.pop("time", None)
            args.pop("status", None)
            args.pop("allowed_nationalities", None)
            args.pop("required_residence", None)
    where = json.dumps(document["where"])
    where = (
        where.replace('"birthdate"', '"dob"')
        .replace('"nationality"', '"nat"')
        .replace('"residence"', '"home"')
        .replace('"cutoff"', '"age_limit"')
        .replace('"allowed_nationalities"', '"nats"')
        .replace('"required_residence"', '"must_live"')
    )
    document["where"] = json.loads(where)
    return validate_claim(document)


class TestExpectedTranscript(unittest.TestCase):
    def test_claim_context_recipe_is_deterministic(self) -> None:
        claim = _composed()
        bundle = make_fixture(claim, seed=1)
        first = expected_transcript(claim, bundle["given"])
        second = expected_transcript(claim, bundle["given"])
        self.assertEqual(first, second)
        self.assertEqual(len(first), 32)

    def test_every_given_field_binds_transcript(self) -> None:
        claim = _composed()
        bundle = make_fixture(claim, seed=2)
        base = expected_transcript(claim, bundle["given"])
        changed = copy.deepcopy(bundle["given"])
        changed["session"]["nonce"] = "nonce-2"
        self.assertNotEqual(base, expected_transcript(claim, changed))


class TestEvaluateClaimPositive(unittest.TestCase):
    def test_positive_control_composed_file(self) -> None:
        claim = _composed_file()
        bundle = make_fixture(claim, seed=7)
        result = evaluate_claim(claim, bundle["fixture"], bundle["given"])
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["value"])
        for entry in result["assertions"].values():
            self.assertEqual(entry["status"], "ok")
            self.assertTrue(entry["value"])

    def test_positive_control_cutoff_file(self) -> None:
        claim = _cutoff()
        bundle = make_fixture(claim, seed=8)
        result = evaluate_claim(claim, bundle["fixture"], bundle["given"])
        self.assertTrue(result["value"])
        self.assertNotIn("allowed_nationalities", bundle["given"])

    def test_reorder_require_still_authenticates_first(self) -> None:
        document = copy.deepcopy(COMPOSED_CLAIM)
        document["require"] = list(reversed(document["require"]))
        claim = validate_claim(document)
        bundle = make_fixture(claim, seed=9)
        result = evaluate_claim(claim, bundle["fixture"], bundle["given"])
        self.assertTrue(result["value"])
        self.assertTrue(result["assertions"]["issuer_authentication"]["value"])

    def test_renamed_aliases_credential_given_and_require_ids(self) -> None:
        claim = _renamed_claim()
        bundle = make_fixture(claim, seed=10)
        result = evaluate_claim(claim, bundle["fixture"], bundle["given"])
        self.assertTrue(result["value"])
        self.assertIn("auth_gate", result["assertions"])
        self.assertIn("trusted_issuer", bundle["given"])
        self.assertNotIn("issuer", bundle["given"])

    def test_no_status_claim_omits_witness_and_status_given(self) -> None:
        claim = _no_status_claim()
        bundle = make_fixture(claim, seed=11)
        self.assertNotIn("status_witness", bundle["fixture"])
        self.assertNotIn("status", bundle["given"])
        self.assertIn("~", bundle["fixture"]["credential"])
        result = evaluate_claim(claim, bundle["fixture"], bundle["given"])
        self.assertTrue(result["value"])


class TestEvaluateClaimAdversarial(unittest.TestCase):
    def setUp(self) -> None:
        self.claim = _composed()
        bundle = make_fixture(self.claim, seed=11)
        self.fixture = bundle["fixture"]
        self.given = bundle["given"]
        self.builder = SdJwtFixtureBuilder(seed=99)

    def test_issuer_key_substitution(self) -> None:
        other = self.builder.build()
        fixture = dict(self.fixture)
        fixture["credential"] = other.compact
        result = evaluate_claim(self.claim, fixture, self.given)
        self.assertEqual(result["status"], "ok")
        self.assertFalse(result["value"])
        self.assertFalse(result["assertions"]["issuer_authentication"]["value"])
        self.assertEqual(result["assertions"]["metadata"]["status"], "not_run")
        self.assertEqual(result["condition"]["status"], "not_run")

    def test_disclosure_transplantation(self) -> None:
        donor = self.builder.build(attributes={"birthdate": "1999-12-31"})
        recipient = make_fixture(self.claim, seed=12)
        fixture = dict(recipient["fixture"])
        fixture["credential"] = donor.compact
        result = evaluate_claim(self.claim, fixture, recipient["given"])
        self.assertFalse(result["value"])

    def test_duplicate_disclosure_names_rejected(self) -> None:
        parts = self.fixture["credential"].split("~")
        disclosures = parts[1:-1]
        corrupted = parts[0] + "~" + disclosures[0] + "~" + "~".join(disclosures) + "~"
        fixture = dict(self.fixture, credential=corrupted)
        result = evaluate_claim(self.claim, fixture, self.given)
        self.assertFalse(result["value"])

    def test_authentic_true_metadata_false_labeled_separately(self) -> None:
        given = copy.deepcopy(self.given)
        given["issuer"]["allowed_vcts"] = ["https://example.ch/vct/other"]
        result = evaluate_claim(self.claim, self.fixture, given)
        self.assertTrue(result["assertions"]["issuer_authentication"]["value"])
        self.assertFalse(result["assertions"]["metadata"]["value"])
        self.assertFalse(result["assertions"]["session_binding"]["value"])
        self.assertFalse(result["value"])

    def test_metadata_mismatch(self) -> None:
        given = copy.deepcopy(self.given)
        given["issuer"]["issuer_id"] = "wrong-issuer"
        result = evaluate_claim(self.claim, self.fixture, given)
        self.assertTrue(result["assertions"]["issuer_authentication"]["value"])
        self.assertFalse(result["assertions"]["metadata"]["value"])

    def test_validity_boundary_nbf_minus_one(self) -> None:
        bundle = make_fixture(self.claim, seed=13, nbf=1_800_000_001)
        result = evaluate_claim(self.claim, bundle["fixture"], bundle["given"])
        self.assertFalse(result["assertions"]["validity"]["value"])

    def test_validity_boundary_exp_exact(self) -> None:
        bundle = make_fixture(self.claim, seed=14, exp=1_800_000_000)
        result = evaluate_claim(self.claim, bundle["fixture"], bundle["given"])
        self.assertFalse(result["assertions"]["validity"]["value"])

    def test_wrong_holder_signature(self) -> None:
        fixture = dict(self.fixture)
        fixture["holder_signature"] = "A" * 86
        result = evaluate_claim(self.claim, fixture, self.given)
        self.assertEqual(result["status"], "ok")
        self.assertFalse(result["assertions"]["holder_authorization"]["value"])

    def test_invalid_holder_encoding_is_invalid_input(self) -> None:
        fixture = dict(self.fixture)
        fixture["holder_signature"] = self.fixture["holder_signature"] + "="
        result = evaluate_claim(self.claim, fixture, self.given)
        self.assertEqual(result, {"status": "invalid_input"})

    def test_invalid_context_encoding_is_invalid_input(self) -> None:
        fixture = dict(self.fixture)
        fixture["presentation_context"] = "F" * 64
        result = evaluate_claim(self.claim, fixture, self.given)
        self.assertEqual(result, {"status": "invalid_input"})

    def test_context_change(self) -> None:
        fixture = dict(self.fixture)
        fixture["presentation_context"] = "0" * 64
        result = evaluate_claim(self.claim, fixture, self.given)
        self.assertFalse(result["assertions"]["session_binding"]["value"])

    def test_status_wrong_root(self) -> None:
        given = copy.deepcopy(self.given)
        given["status"]["commitment"] = "f" * 64
        result = evaluate_claim(self.claim, self.fixture, given)
        self.assertFalse(result["assertions"]["status"]["value"])

    def test_status_stale_snapshot(self) -> None:
        given = copy.deepcopy(self.given)
        given["status"]["valid_before"] = "1"
        result = evaluate_claim(self.claim, self.fixture, given)
        self.assertFalse(result["assertions"]["status"]["value"])

    def test_status_bool_index_invalid_input(self) -> None:
        fixture = dict(self.fixture)
        fixture["status_witness"] = dict(self.fixture["status_witness"], index=True)
        result = evaluate_claim(self.claim, fixture, self.given)
        self.assertEqual(result, {"status": "invalid_input"})

    def test_or_whole_condition_false_with_valid_crypto(self) -> None:
        bundle = make_fixture(
            self.claim,
            attributes={"birthdate": "2010-01-01", "nationality": "FR", "residence": "FR"},
            seed=15,
        )
        result = evaluate_claim(self.claim, bundle["fixture"], bundle["given"])
        self.assertTrue(all(a["value"] for a in result["assertions"].values()))
        self.assertFalse(result["condition"]["value"])
        self.assertFalse(result["value"])

    def test_renamed_alias_resolution(self) -> None:
        document = copy.deepcopy(COMPOSED_CLAIM)
        document["attributes"]["domicile"] = document["attributes"].pop("residence")
        document["attributes"]["domicile"]["path"] = ["residence_country"]
        document["where"]["all"][1]["any"][1]["args"]["left"]["attribute"] = "domicile"
        claim = validate_claim(document)
        bundle = make_fixture(
            claim,
            attributes={"domicile": "CH"},
            seed=16,
        )
        result = evaluate_claim(claim, bundle["fixture"], bundle["given"])
        self.assertTrue(result["value"])

    def test_malformed_given_invalid_input(self) -> None:
        result = evaluate_claim(self.claim, self.fixture, {"now": 1})
        self.assertEqual(result, {"status": "invalid_input"})

    def test_malformed_fixture_invalid_input(self) -> None:
        result = evaluate_claim(self.claim, {"credential": "x"}, self.given)
        self.assertEqual(result, {"status": "invalid_input"})

    def test_simple_namespace_forged_claim_rejected(self) -> None:
        forged = SimpleNamespace(
            document={"require": []},
            statement_digest="0" * 64,
        )
        result = evaluate_claim(forged, self.fixture, self.given)
        self.assertEqual(result, {"status": "invalid_input"})

    def test_holder_double_hash_does_not_verify(self) -> None:
        digest = expected_transcript(self.claim, self.given)
        doubled = hashlib.sha256(digest).digest()
        holder_key = derive_fixture_private_key(11, "holder")
        der = holder_key.sign(doubled, ec.ECDSA(Prehashed(hashes.SHA256()), deterministic_signing=True))
        r, s = decode_dss_signature(der)
        fixture = dict(self.fixture)
        fixture["holder_signature"] = _b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
        result = evaluate_claim(self.claim, fixture, self.given)
        self.assertFalse(result["assertions"]["holder_authorization"]["value"])

    def test_not_run_assertions_never_drop_from_conjunction(self) -> None:
        other = self.builder.build()
        fixture = dict(self.fixture, credential=other.compact)
        result = evaluate_claim(self.claim, fixture, self.given)
        self.assertTrue(any(entry["status"] == "not_run" for entry in result["assertions"].values()))
        self.assertFalse(result["value"])

    def test_reauthorize_after_nonce_change(self) -> None:
        given = copy.deepcopy(self.given)
        given["session"]["nonce"] = "campaign-nonce"
        refreshed = reauthorize_fixture(self.claim, self.fixture, given, seed=11)
        result = evaluate_claim(self.claim, refreshed["fixture"], given)
        self.assertTrue(result["assertions"]["session_binding"]["value"])
        self.assertTrue(result["assertions"]["holder_authorization"]["value"])


class TestEvaluateClaimIntegration(unittest.TestCase):
    def test_real_loader_required(self) -> None:
        claim = load_claim(CLAIMS_DIR / "composed-status.json")
        bundle = make_fixture(claim, seed=21)
        result = evaluate_claim(claim, bundle["fixture"], bundle["given"])
        self.assertTrue(result["value"])


if __name__ == "__main__":
    unittest.main()

"""CORE claim loader, validation, and where evaluation tests."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from semantics.canonical import parse_json_strict
from semantics.claims import (
    ClaimError,
    evaluate_where,
    load_claim,
    validate_claim,
    validate_given,
)

CLAIMS_DIR = Path(__file__).resolve().parents[1] / "claims"

COMPOSED_CLAIM = {
    "schema": "swiyu.claim.v0",
    "id": "test.composed-cutoff-or-status.v1",
    "packages": {
        "format": "platform.sd-jwt-es256@1",
        "assertions": "platform.presentation@1",
        "predicates": "core.predicates@1",
    },
    "credential": {"id": "eid", "format": "platform.sd-jwt-es256@1"},
    "attributes": {
        "birthdate": {
            "credential": "eid",
            "path": ["birthdate"],
            "type": "swiyu.date@0",
        },
        "nationality": {
            "credential": "eid",
            "path": ["nationality"],
            "type": "ascii-code2@1",
        },
        "residence": {
            "credential": "eid",
            "path": ["residence_country"],
            "type": "ascii-code2@1",
        },
    },
    "given": {
        "issuer": {"type": "platform.expected-issuer@1"},
        "now": {"type": "swiyu.unix-seconds@0"},
        "cutoff": {"type": "swiyu.date@0"},
        "session": {"type": "platform.expected-session@1"},
        "status": {"type": "platform.expected-status@1"},
        "allowed_nationalities": {"type": "set<ascii-code2@1>", "max_items": 16},
        "required_residence": {"type": "ascii-code2@1"},
    },
    "require": [
        {
            "id": "issuer_authentication",
            "assert": "credential.authentic@1",
            "args": {
                "credential": {"credential": "eid"},
                "issuer": {"given": "issuer"},
            },
        },
        {
            "id": "metadata",
            "assert": "credential.expected-metadata@1",
            "args": {
                "credential": {"credential": "eid"},
                "issuer": {"given": "issuer"},
            },
        },
        {
            "id": "validity",
            "assert": "credential.valid-at@1",
            "args": {
                "credential": {"credential": "eid"},
                "time": {"given": "now"},
            },
        },
        {
            "id": "holder_authorization",
            "assert": "holder.signature-valid@1",
            "args": {
                "credential": {"credential": "eid"},
                "transcript": {
                    "assertion": "session_binding",
                    "output": "expected_transcript",
                },
            },
        },
        {
            "id": "session_binding",
            "assert": "presentation.context-bound@1",
            "recipe": "claim.context@1",
            "args": {
                "session": {"given": "session"},
                "cutoff": {"given": "cutoff"},
                "time": {"given": "now"},
                "status": {"given": "status"},
                "allowed_nationalities": {"given": "allowed_nationalities"},
                "required_residence": {"given": "required_residence"},
            },
        },
        {
            "id": "status",
            "assert": "status.zero-at-reference@1",
            "args": {
                "credential": {"credential": "eid"},
                "reference": {"given": "status"},
                "time": {"given": "now"},
            },
        },
    ],
    "where": {
        "all": [
            {
                "predicate": "date.on-or-before@1",
                "args": {
                    "value": {"attribute": "birthdate"},
                    "limit": {"given": "cutoff"},
                },
            },
            {
                "any": [
                    {
                        "predicate": "value.in-set@1",
                        "args": {
                            "value": {"attribute": "nationality"},
                            "set": {"given": "allowed_nationalities"},
                        },
                    },
                    {
                        "predicate": "value.equals@1",
                        "args": {
                            "left": {"attribute": "residence"},
                            "right": {"given": "required_residence"},
                        },
                    },
                ]
            },
        ]
    },
    "release": {
        "observer": "verifier",
        "semantic_values": [
            "acceptance",
            "eid.issuer",
            "eid.key_id",
            "eid.credential_type",
        ],
        "protocol_derived": ["claim.context@1"],
        "opaque_channels": ["proof"],
        "branch_identity": "hidden",
    },
}


class TestComposedClaimTracer(unittest.TestCase):
    def test_load_evaluate_where_and_reject_missing_authentication(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "composed.json"
            path.write_text(json.dumps(COMPOSED_CLAIM), encoding="utf-8")
            claim = load_claim(path)

        selectors = claim.document["attributes"]
        self.assertEqual(set(selectors), {"birthdate", "nationality", "residence"})
        for alias, spec in selectors.items():
            self.assertEqual(spec["credential"], "eid")
            self.assertIsInstance(spec["path"], list)

        # birthdate <= cutoff AND (nationality in set OR residence == required)
        self.assertTrue(
            evaluate_where(
                claim,
                {
                    "birthdate": "2000-01-01",
                    "nationality": "FR",
                    "residence": "CH",
                },
                {
                    "cutoff": "2008-01-01",
                    "allowed_nationalities": ["CH", "DE"],
                    "required_residence": "CH",
                },
            )
        )

        missing_auth = dict(COMPOSED_CLAIM)
        missing_auth["require"] = [
            entry
            for entry in COMPOSED_CLAIM["require"]
            if entry["assert"] != "credential.authentic@1"
        ]
        with self.assertRaises(ClaimError):
            validate_claim(missing_auth)


class TestClaimFiles(unittest.TestCase):
    def test_load_cutoff_status_claim(self):
        claim = load_claim(CLAIMS_DIR / "cutoff-status.json")
        self.assertEqual(claim.document["id"], "test.cutoff-status.v1")
        self.assertIn("packages.format", claim.dependencies)

    def test_load_composed_status_claim(self):
        claim = load_claim(CLAIMS_DIR / "composed-status.json")
        self.assertEqual(claim.document["id"], "test.composed-cutoff-or-status.v1")


class TestClaimValidation(unittest.TestCase):
    def test_reject_condition_fragment(self):
        fragment = {
            "schema": "swiyu.condition-fragment.v0",
            "attributes": {},
            "given": {},
            "where": {},
        }
        with self.assertRaises(ClaimError):
            validate_claim(fragment)

    def test_reject_unknown_top_level_field(self):
        doc = copy.deepcopy(COMPOSED_CLAIM)
        doc["extra"] = True
        with self.assertRaises(ClaimError):
            validate_claim(doc)

    def test_reject_duplicate_sibling_predicate(self):
        doc = copy.deepcopy(COMPOSED_CLAIM)
        duplicate = doc["where"]["all"][1]["any"][0]
        doc["where"]["all"][1]["any"].append(copy.deepcopy(duplicate))
        with self.assertRaises(ClaimError):
            validate_claim(doc)

    def test_reject_legacy_recipe_for_synthetic_package(self):
        doc = copy.deepcopy(COMPOSED_CLAIM)
        for entry in doc["require"]:
            if entry["id"] == "session_binding":
                entry["recipe"] = "swiyu.show-context@0"
        with self.assertRaises(ClaimError):
            validate_claim(doc)

    def test_reject_cyclic_assertion_dependencies(self):
        doc = copy.deepcopy(COMPOSED_CLAIM)
        for entry in doc["require"]:
            if entry["id"] == "session_binding":
                entry["args"]["holder"] = {
                    "assertion": "holder_authorization",
                    "output": "expected_transcript",
                }
        with self.assertRaises(ClaimError):
            validate_claim(doc)

    def test_reject_operand_type_mismatch(self):
        doc = copy.deepcopy(COMPOSED_CLAIM)
        doc["where"]["all"][1]["any"][1]["args"]["right"] = {"given": "cutoff"}
        with self.assertRaises(ClaimError):
            validate_claim(doc)

    def test_missing_inactive_or_attribute_rejects(self):
        claim = validate_claim(copy.deepcopy(COMPOSED_CLAIM))
        with self.assertRaises(ClaimError):
            evaluate_where(
                claim,
                {"birthdate": "2000-01-01", "nationality": "CH"},
                {
                    "cutoff": "2008-01-01",
                    "allowed_nationalities": ["CH"],
                    "required_residence": "CH",
                },
            )

    def test_renamed_alias_regression(self):
        doc = copy.deepcopy(COMPOSED_CLAIM)
        doc["attributes"]["country_of_birth"] = doc["attributes"].pop("nationality")
        doc["attributes"]["country_of_birth"]["path"] = ["nationality"]
        doc["where"]["all"][1]["any"][0]["args"]["value"]["attribute"] = (
            "country_of_birth"
        )
        claim = validate_claim(doc)
        self.assertTrue(
            evaluate_where(
                claim,
                {
                    "birthdate": "2000-01-01",
                    "country_of_birth": "CH",
                    "residence": "FR",
                },
                {
                    "cutoff": "2008-01-01",
                    "allowed_nationalities": ["CH"],
                    "required_residence": "CH",
                },
            )
        )


class TestValidateGiven(unittest.TestCase):
    def test_validate_given_enforces_full_record(self):
        claim = validate_claim(copy.deepcopy(COMPOSED_CLAIM))
        full = {
            "issuer": {
                "public_key": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "zESfNAEzsraxYQmWCqUnN9KrNPNIdTRfhOLrO1CzL3E",
                    "y": "OnC84AF6t8x1TGE20yoQ_BJadnMxjA4qSivIs5IE3Xc",
                    "kid": "kid-1",
                },
                "issuer_id": "issuer.example",
                "key_id": "kid-1",
                "allowed_vcts": ["eid.v1"],
            },
            "now": "1800000000",
            "cutoff": "2008-01-01",
            "session": {
                "nonce": "n",
                "client_id": "c",
                "response_uri": "https://example.com",
                "state": "s",
                "query_id": "q",
            },
            "status": {
                "id": "snap-1",
                "issuer_id": "issuer.example",
                "key_id": "kid-1",
                "subject": "https://status.example/list",
                "commitment": "a" * 64,
                "epoch": "1",
                "list_length": 8,
                "valid_before": "1900000000",
            },
            "allowed_nationalities": ["CH", "DE"],
            "required_residence": "CH",
        }
        validated = validate_given(claim, full)
        self.assertEqual(validated["cutoff"], "2008-01-01")
        partial = dict(full)
        del partial["issuer"]
        with self.assertRaises(ClaimError):
            validate_given(claim, partial)


class TestInterpreterContract(unittest.TestCase):
    def test_strict_json_duplicate_keys_rejected(self):
        with self.assertRaises(ValueError):
            parse_json_strict('{"a":1,"a":2}')


if __name__ == "__main__":
    unittest.main()

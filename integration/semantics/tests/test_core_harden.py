"""CORE hardening regression tests."""

from __future__ import annotations

import copy
import math
import tempfile
import unittest
from pathlib import Path

from semantics.catalog import load_catalog
from semantics.claim_types import ClaimError, validate_given_record
from semantics.claims import Claim, evaluate_where, load_claim, validate_claim, validate_given
from semantics.canonical import canonical_json_bytes

from tests.test_claims import COMPOSED_CLAIM

VALID_P256 = {
    "kty": "EC",
    "crv": "P-256",
    "x": "zESfNAEzsraxYQmWCqUnN9KrNPNIdTRfhOLrO1CzL3E",
    "y": "OnC84AF6t8x1TGE20yoQ_BJadnMxjA4qSivIs5IE3Xc",
    "kid": "kid-1",
}

VALID_ISSUER = {
    "public_key": VALID_P256,
    "issuer_id": "issuer.example",
    "key_id": "kid-1",
    "allowed_vcts": ["eid.v1"],
}


def _full_given() -> dict:
    return {
        "issuer": VALID_ISSUER,
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


class TestAssertionArgHardening(unittest.TestCase):
    def test_reject_missing_required_assertion_arg(self):
        doc = copy.deepcopy(COMPOSED_CLAIM)
        for entry in doc["require"]:
            if entry["assert"] == "credential.authentic@1":
                del entry["args"]["issuer"]
        with self.assertRaises(ClaimError):
            validate_claim(doc)

    def test_reject_authentic_issuer_pointing_to_session(self):
        doc = copy.deepcopy(COMPOSED_CLAIM)
        for entry in doc["require"]:
            if entry["assert"] == "credential.authentic@1":
                entry["args"]["issuer"] = {"given": "session"}
        with self.assertRaises(ClaimError):
            validate_claim(doc)

    def test_reject_unknown_require_field(self):
        doc = copy.deepcopy(COMPOSED_CLAIM)
        doc["require"][0]["extra"] = True
        with self.assertRaises(ClaimError):
            validate_claim(doc)

    def test_reject_legacy_recipe_on_non_context_assertion(self):
        doc = copy.deepcopy(COMPOSED_CLAIM)
        for entry in doc["require"]:
            if entry["assert"] == "credential.valid-at@1":
                entry["recipe"] = "swiyu.show-context@0"
        with self.assertRaises(ClaimError):
            validate_claim(doc)

    def test_reject_context_without_session_role(self):
        doc = copy.deepcopy(COMPOSED_CLAIM)
        for entry in doc["require"]:
            if entry["id"] == "session_binding":
                del entry["args"]["session"]
        with self.assertRaises(ClaimError):
            validate_claim(doc)

    def test_context_allows_extra_given_operands(self):
        doc = copy.deepcopy(COMPOSED_CLAIM)
        for entry in doc["require"]:
            if entry["id"] == "session_binding":
                entry["args"]["extra_cutoff"] = {"given": "cutoff"}
        claim = validate_claim(doc)
        self.assertEqual(claim.document["id"], doc["id"])

    def test_reject_undeclared_assertion_output(self):
        doc = copy.deepcopy(COMPOSED_CLAIM)
        for entry in doc["require"]:
            if entry["id"] == "holder_authorization":
                entry["args"]["transcript"]["output"] = "bogus"
        with self.assertRaises(ClaimError):
            validate_claim(doc)


class TestGivenTypeHardening(unittest.TestCase):
    def test_reject_noncanonical_p256_coordinates(self):
        bad = copy.deepcopy(VALID_ISSUER)
        bad["public_key"]["x"] = "A" * 43
        with self.assertRaises(ClaimError):
            validate_given_record("platform.expected-issuer@1", bad)

    def test_reject_nonstring_given_type_name(self):
        doc = copy.deepcopy(COMPOSED_CLAIM)
        doc["given"]["issuer"]["type"] = 123
        with self.assertRaises(ClaimError):
            validate_claim(doc)

    def test_reject_status_time_integers(self):
        status = copy.deepcopy(_full_given()["status"])
        status["epoch"] = 1
        with self.assertRaises(ClaimError):
            validate_given_record("platform.expected-status@1", status)

    def test_reject_allowlist_over_16(self):
        issuer = copy.deepcopy(VALID_ISSUER)
        issuer["allowed_vcts"] = [f"v{i}" for i in range(17)]
        with self.assertRaises(ClaimError):
            validate_given_record("platform.expected-issuer@1", issuer)

    def test_reject_invalid_max_items_values(self):
        for max_items in (0, True, 17, "16"):
            doc = copy.deepcopy(COMPOSED_CLAIM)
            doc["given"]["allowed_nationalities"]["max_items"] = max_items
            with self.assertRaises(ClaimError):
                validate_claim(doc)

    def test_reject_max_items_on_scalar(self):
        doc = copy.deepcopy(COMPOSED_CLAIM)
        doc["given"]["cutoff"]["max_items"] = 16
        with self.assertRaises(ClaimError):
            validate_claim(doc)

    def test_reject_unicode_surrogate_without_traceback(self):
        with self.assertRaises(ClaimError):
            validate_given_record("utf8@1", "\ud800")

    def test_given_record_is_deep_copied(self):
        issuer = copy.deepcopy(VALID_ISSUER)
        validated = validate_given_record("platform.expected-issuer@1", issuer)
        issuer["issuer_id"] = "mutated"
        self.assertNotEqual(validated["issuer_id"], "mutated")


class TestClaimBoundsAndIntegrity(unittest.TestCase):
    def test_validate_claim_enforces_size_bound(self):
        doc = copy.deepcopy(COMPOSED_CLAIM)
        doc["id"] = "x" * 70000
        with self.assertRaises(ClaimError):
            validate_claim(doc)

    def test_validate_given_enforces_size_bound(self):
        claim = validate_claim(copy.deepcopy(COMPOSED_CLAIM))
        given = _full_given()
        given["session"]["nonce"] = "n" * 50000
        with self.assertRaises(ClaimError):
            validate_given(claim, given)

    def test_reject_nonfinite_in_claim(self):
        doc = copy.deepcopy(COMPOSED_CLAIM)
        doc["marker"] = math.inf
        with self.assertRaises(ClaimError):
            validate_claim(doc)

    def test_reject_deeply_nested_claim_before_recursion(self):
        from semantics.claims import _validate_json_shape

        node: dict = {}
        current = node
        for _ in range(40):
            nxt: dict = {}
            current["child"] = nxt
            current = nxt
        with self.assertRaises(ClaimError):
            _validate_json_shape(node)

    def test_claim_document_is_defensive_copy(self):
        claim = validate_claim(copy.deepcopy(COMPOSED_CLAIM))
        claim.document["id"] = "mutated"
        self.assertNotEqual(claim.document["id"], "mutated")

    def test_mutated_claim_rejected_by_evaluate_where(self):
        claim = validate_claim(copy.deepcopy(COMPOSED_CLAIM))
        forged = Claim(
            _document={**claim._document, "id": "forged"},
            statement_digest=claim.statement_digest,
            _dependencies=claim._dependencies,
        )
        with self.assertRaises(ClaimError):
            evaluate_where(
                forged,
                {
                    "birthdate": "2000-01-01",
                    "nationality": "CH",
                    "residence": "CH",
                },
                {
                    "cutoff": "2008-01-01",
                    "allowed_nationalities": ["CH"],
                    "required_residence": "CH",
                },
            )

    def test_load_claim_rejects_oversize_before_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "big.json"
            path.write_bytes(b"{" + b'"x":' + b"1," * 70000 + b'"y":1}')
            with self.assertRaises(ClaimError):
                load_claim(path)


class TestCatalogHardening(unittest.TestCase):
    def test_catalog_includes_source_pins(self):
        catalog = load_catalog()
        self.assertEqual(
            set(catalog.sources.keys()),
            {"claims", "catalog", "claim_types", "predicates", "canonical", "credentials", "assertions"},
        )

    def test_claim_dependencies_include_source_pins(self):
        claim = validate_claim(copy.deepcopy(COMPOSED_CLAIM))
        self.assertIn("sources.claims", claim.dependencies)

    def test_reject_catalog_path_escape(self):
        import json

        catalog = load_catalog()
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "catalog.lock.json"
            lock = json.loads(catalog.lock_path.read_text(encoding="utf-8"))
            lock["packages"]["platform.sd-jwt-es256@1"]["path"] = "../../../etc/passwd"
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            with self.assertRaises(ClaimError):
                load_catalog(lock_path)


class TestPredicateHardening(unittest.TestCase):
    def test_reject_predicate_without_attribute_operand(self):
        doc = copy.deepcopy(COMPOSED_CLAIM)
        doc["given"]["g1"] = {"type": "ascii-code2@1"}
        doc["given"]["g2"] = {"type": "ascii-code2@1"}
        doc["where"] = {
            "predicate": "value.equals@1",
            "args": {
                "left": {"given": "g1"},
                "right": {"given": "g2"},
            },
        }
        with self.assertRaises(ClaimError):
            validate_claim(doc)

    def test_reject_duplicate_semantic_values(self):
        doc = copy.deepcopy(COMPOSED_CLAIM)
        doc["release"]["semantic_values"].append("acceptance")
        with self.assertRaises(ClaimError):
            validate_claim(doc)


class TestCanonicalHardening(unittest.TestCase):
    def test_validate_claim_rejects_non_string_object_keys(self):
        doc = copy.deepcopy(COMPOSED_CLAIM)
        doc[1] = "bad"  # type: ignore[index]
        with self.assertRaises(ClaimError):
            validate_claim(doc)

    def test_canonical_json_rejects_nonfinite(self):
        with self.assertRaises(ValueError):
            canonical_json_bytes({"x": math.nan})


if __name__ == "__main__":
    unittest.main()

"""A claim's local names cannot change or obscure its semantic roles."""
import unittest
from pathlib import Path

from semantics.claims import ClaimError, load_claim, validate_claim


class TestClaimDomain(unittest.TestCase):
    def setUp(self):
        self.document = load_claim(Path(__file__).resolve().parents[1] / "claims/clearance-status.json").document

    def test_statement_pins_authentication_and_assertion_evaluators(self):
        dependencies = validate_claim(self.document).dependencies
        self.assertIn("sources.credentials", dependencies)
        self.assertIn("sources.assertions", dependencies)

    def test_session_given_alias_is_independent_of_role(self):
        self.document["given"]["request"] = self.document["given"].pop("session")
        for assertion in self.document["require"]:
            for operand in assertion["args"].values():
                if operand == {"given": "session"}:
                    operand["given"] = "request"
        validate_claim(self.document)

    def test_attribute_alias_cannot_shadow_authenticated_metadata(self):
        for alias in ("issuer", "key_id", "credential_type"):
            with self.subTest(alias=alias):
                document = dict(self.document, attributes=dict(self.document["attributes"]))
                document["attributes"][alias] = {"credential": "eid", "path": ["department"], "type": "utf8@1"}
                with self.assertRaises(ClaimError):
                    validate_claim(document)

    def test_attributes_have_supported_scalar_types(self):
        for type_name in ("platform.expected-session@1", "set<utf8@1>"):
            with self.subTest(type_name=type_name):
                document = dict(self.document, attributes=dict(self.document["attributes"]))
                document["attributes"]["department"] = {"credential": "eid", "path": ["department"], "type": type_name}
                with self.assertRaises(ClaimError):
                    validate_claim(document)

    def test_given_sets_require_supported_scalar_elements(self):
        for element in ("platform.expected-session@1", "platform.expected-issuer@1", "platform.expected-status@1"):
            with self.subTest(element=element):
                document = dict(self.document, given=dict(self.document["given"]))
                document["given"]["extra"] = {"type": f"set<{element}>"}
                with self.assertRaises(ClaimError):
                    validate_claim(document)

"""Public-interface tests for semantics.credentials.authenticate()."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from semantics.credentials import CredentialError, authenticate

from tests.helpers.sd_jwt_fixture import SdJwtFixtureBuilder

SDK_FIXTURE = Path(__file__).resolve().parent / "helpers" / "sdk_issued_public.json"
INDEPENDENT_FIXTURE = Path(__file__).resolve().parent / "helpers" / "independent_issuer_public.json"


class TestAuthenticateSdJwt(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = SdJwtFixtureBuilder(seed=1)
        self.fixture = self.builder.build()

    def test_extracts_multiple_issuer_authenticated_attributes(self) -> None:
        credential = authenticate(
            self.fixture.compact,
            self.fixture.issuer_record,
            self.fixture.attribute_definitions,
        )

        self.assertEqual(
            credential.attributes,
            {
                "birthdate": "2000-01-01",
                "nationality": "CH",
                "residence": "CH",
            },
        )
        self.assertEqual(credential.issuer_id, self.fixture.issuer_record["issuer_id"])
        self.assertEqual(credential.key_id, self.fixture.issuer_record["key_id"])
        self.assertEqual(
            credential.credential_type,
            self.fixture.issuer_record["allowed_vcts"][0],
        )
        self.assertEqual(credential.nbf, 1_700_000_000)
        self.assertEqual(credential.exp, 1_900_000_000)
        self.assertEqual(credential.status_uri, "https://status.example/synthetic-list")
        self.assertEqual(credential.status_index, 2)
        self.assertIn("kty", credential.holder_key)
        self.assertEqual(credential.holder_key["crv"], "P-256")

    def test_rejects_tampered_disclosure_value(self) -> None:
        tampered = self.builder.tamper_disclosure_value(
            self.fixture.compact,
            "birthdate",
            "1999-12-31",
        )

        with self.assertRaises(CredentialError):
            authenticate(
                tampered,
                self.fixture.issuer_record,
                self.fixture.attribute_definitions,
            )

    def test_rejects_unreachable_disclosure(self) -> None:
        unreachable = self.builder.build(include_unreachable="shadow_claim")

        with self.assertRaises(CredentialError):
            authenticate(
                unreachable.compact,
                unreachable.issuer_record,
                unreachable.attribute_definitions,
            )

    def test_rejects_issuer_key_substitution(self) -> None:
        other = SdJwtFixtureBuilder(seed=2).build()
        with self.assertRaises(CredentialError):
            authenticate(
                self.fixture.compact,
                other.issuer_record,
                self.fixture.attribute_definitions,
            )

    def test_rejects_duplicate_disclosed_names(self) -> None:
        parts = self.fixture.compact.split("~")
        disclosures = parts[1:-1]
        corrupted = parts[0] + "~" + disclosures[0] + "~" + "~".join(disclosures) + "~"
        with self.assertRaises(CredentialError):
            authenticate(
                corrupted,
                self.fixture.issuer_record,
                self.fixture.attribute_definitions,
            )

    def test_rejects_oversized_compact(self) -> None:
        with self.assertRaises(CredentialError):
            authenticate(
                "x" * 70000,
                self.fixture.issuer_record,
                self.fixture.attribute_definitions,
            )

    def test_does_not_enforce_expected_iss_vct_allowlist(self) -> None:
        record = dict(self.fixture.issuer_record)
        record["issuer_id"] = "other-issuer"
        record["allowed_vcts"] = ["https://example.ch/vct/other"]
        credential = authenticate(
            self.fixture.compact,
            record,
            self.fixture.attribute_definitions,
        )
        self.assertEqual(credential.issuer_id, self.fixture.issuer_record["issuer_id"])
        self.assertEqual(credential.credential_type, self.fixture.issuer_record["allowed_vcts"][0])

    def test_optional_iat_is_accepted_when_typed(self) -> None:
        fixture = self.builder.build(iat=1_700_000_100)
        credential = authenticate(
            fixture.compact,
            fixture.issuer_record,
            fixture.attribute_definitions,
        )
        self.assertEqual(credential.iat, 1_700_000_100)

    def test_rejects_bool_nbf(self) -> None:
        fixture = self.builder.build(bool_nbf=True)
        with self.assertRaises(CredentialError):
            authenticate(fixture.compact, fixture.issuer_record, fixture.attribute_definitions)

    def test_rejects_duplicate_sd_hashes(self) -> None:
        fixture = self.builder.build(duplicate_sd=True)
        with self.assertRaises(CredentialError):
            authenticate(fixture.compact, fixture.issuer_record, fixture.attribute_definitions)

    def test_rejects_nested_disclosure_values(self) -> None:
        fixture = self.builder.build(nested_value=True)
        with self.assertRaises(CredentialError):
            authenticate(fixture.compact, fixture.issuer_record, fixture.attribute_definitions)

    def test_rejects_padded_base64url(self) -> None:
        parts = self.fixture.compact.split(".")
        padded = parts[0] + "=" + "." + ".".join(parts[1:])
        with self.assertRaises(CredentialError):
            authenticate(padded, self.fixture.issuer_record, self.fixture.attribute_definitions)

    def test_sdk_fixture_parses_under_expected_record(self) -> None:
        document = json.loads(SDK_FIXTURE.read_text(encoding="utf-8"))
        public_key = document["issuerPublicKey"]
        record = {
            "public_key": public_key,
            "issuer_id": "did:example:issuer",
            "key_id": public_key["kid"],
            "allowed_vcts": ["https://example.ch/vct/person"],
        }
        credential = authenticate(
            document["compactSdJwt"],
            record,
            {"birthdate": "birthdate"},
        )
        self.assertEqual(credential.attributes["birthdate"], "2000-02-29")
        self.assertEqual(credential.issuer_id, "did:example:issuer")
        self.assertEqual(credential.key_id, public_key["kid"])
        self.assertEqual(credential.credential_type, "https://example.ch/vct/person")

    def test_independent_public_signature_fixture(self) -> None:
        document = json.loads(INDEPENDENT_FIXTURE.read_text(encoding="utf-8"))
        credential = authenticate(
            document["compact"],
            document["issuer_record"],
            document["attribute_definitions"],
        )
        self.assertEqual(credential.attributes, document["attributes"])
        self.assertNotIn("d", document["issuer_record"]["public_key"])


if __name__ == "__main__":
    unittest.main()

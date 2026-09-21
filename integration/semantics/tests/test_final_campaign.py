"""Final campaign RED — claim-aware support, given leakage, pair eligibility."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from semantics.claims import load_claim
from semantics.leakage import (
    FINDING_DISCLOSURE,
    FINDING_HIDDEN_FIELD,
    analyze_pair,
    analyze_presentation_leakage,
)
from semantics.support import SupportError, load_support, verify_claim_supported

CLAIMS = Path(__file__).resolve().parents[1] / "claims"
REFERENCE = (
    Path(__file__).resolve().parents[2]
    / "providers"
    / "semantic-reference"
)
PROFILE = "swiyu.semantic-reference.v0"


def _pin_provider(tmp: Path, doc: dict) -> Path:
    (tmp / "provider.py").write_bytes((REFERENCE / "provider.py").read_bytes())
    doc = copy.deepcopy(doc)
    doc["approved_roots"] = []
    doc["artifact_pins"] = [
        {
            "path": "provider.py",
            "sha256": hashlib.sha256((tmp / "provider.py").read_bytes()).hexdigest(),
        }
    ]
    path = tmp / "support.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _release():
    return {
        "semantic_values": ["acceptance"],
        "protocol_derived": ["claim.context@1"],
        "opaque_channels": ["proof"],
    }


class TestClaimAwareSupport(unittest.TestCase):
    def test_renamed_require_ids_load_and_match_selected_roster(self):
        src = json.loads((CLAIMS / "clearance-status.json").read_text(encoding="utf-8"))
        for entry in src["require"]:
            if entry["id"] == "issuer_authentication":
                entry["id"] = "issuer_auth_renamed"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            claim_path = tmp_p / "claim.json"
            claim_path.write_text(json.dumps(src), encoding="utf-8")
            claim = load_claim(claim_path)
            required = {e["id"] for e in claim.document["require"]}
            required.add("where")
            self.assertIn("issuer_auth_renamed", required)
            doc = json.loads((REFERENCE / "support.json").read_text(encoding="utf-8"))
            doc["supported_claims"] = [
                {
                    "id": claim.document["id"],
                    "statement_digest": claim.statement_digest,
                    "enforcement": {oid: "verifier" for oid in required},
                }
            ]
            doc["enforcement"] = {
                "issuer_authentication": "verifier",
                "metadata": "verifier",
                "validity": "verifier",
                "holder_authorization": "verifier",
                "session_binding": "verifier",
                "status": "verifier",
                "where": "verifier",
            }
            loaded = load_support(_pin_provider(tmp_p, doc))
            verify_claim_supported(
                loaded,
                claim_id=claim.document["id"],
                statement_digest=claim.statement_digest,
                claim=claim,
            )

    def test_extra_and_missing_ids_rejected_against_selected_claim(self):
        claim = load_claim(CLAIMS / "clearance-status.json")
        required = {e["id"] for e in claim.document["require"]}
        required.add("where")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            doc = json.loads((REFERENCE / "support.json").read_text(encoding="utf-8"))
            doc["enforcement"]["bonus_unused"] = "verifier"
            loaded = load_support(_pin_provider(tmp_p, doc))
            with self.assertRaises(SupportError):
                verify_claim_supported(
                    loaded,
                    claim_id=claim.document["id"],
                    statement_digest=claim.statement_digest,
                    claim=claim,
                )
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            doc = json.loads((REFERENCE / "support.json").read_text(encoding="utf-8"))
            del doc["enforcement"]["validity"]
            loaded = load_support(_pin_provider(tmp_p, doc))
            with self.assertRaises(SupportError):
                verify_claim_supported(
                    loaded,
                    claim_id=claim.document["id"],
                    statement_digest=claim.statement_digest,
                    claim=claim,
                )
            self.assertEqual(set(loaded["enforcement"]) | {"validity"}, required | {"validity"})

    def test_load_rejects_unknown_stage_duplicate_keys_nonfinite_nonhex(self):
        base = json.loads((REFERENCE / "support.json").read_text(encoding="utf-8"))
        with self.subTest("unknown_stage"):
            with tempfile.TemporaryDirectory() as tmp:
                tmp_p = Path(tmp)
                doc = copy.deepcopy(base)
                doc["enforcement"]["where"] = "prover"
                with self.assertRaises(SupportError):
                    load_support(_pin_provider(tmp_p, doc))
        with self.subTest("duplicate_keys"):
            with tempfile.TemporaryDirectory() as tmp:
                tmp_p = Path(tmp)
                (tmp_p / "provider.py").write_bytes((REFERENCE / "provider.py").read_bytes())
                sha = hashlib.sha256((tmp_p / "provider.py").read_bytes()).hexdigest()
                digest = "aa" * 32
                raw = (
                    '{"schema":"swiyu.claim-support.v0","schema":"swiyu.claim-support.v0",'
                    '"supported_claims":[{"id":"dup","id":"dup","statement_digest":"%s"}],'
                    '"enforcement":{"where":"verifier"},'
                    '"artifact_pins":[{"path":"provider.py","sha256":"%s"}]}'
                ) % (digest, sha)
                path = tmp_p / "support.json"
                path.write_text(raw, encoding="utf-8")
                with self.assertRaises(SupportError):
                    load_support(path)
        with self.subTest("nonfinite"):
            with tempfile.TemporaryDirectory() as tmp:
                tmp_p = Path(tmp)
                doc = copy.deepcopy(base)
                path = _pin_provider(tmp_p, doc)
                path.write_text(
                    path.read_text(encoding="utf-8").replace("{", '{"n": Infinity, ', 1),
                    encoding="utf-8",
                )
                with self.assertRaises(SupportError):
                    load_support(path)
        with self.subTest("nonhex"):
            with tempfile.TemporaryDirectory() as tmp:
                tmp_p = Path(tmp)
                doc = copy.deepcopy(base)
                doc["supported_claims"][0]["statement_digest"] = "g" * 64
                with self.assertRaises(SupportError):
                    load_support(_pin_provider(tmp_p, doc))


class TestLeakageGivenProjectionAndPairs(unittest.TestCase):
    def test_trusted_given_is_not_private_altered_given_is_finding(self):
        trusted = {"session": {"nonce": "n1"}, "required_clearance": "x"}
        matched = json.dumps(
            {"acceptance": True, "given": trusted, "proof": "p", "fixture": {"k": 1}}
        ).encode()
        result = analyze_presentation_leakage(
            raw_bytes=matched,
            release=_release(),
            expected_given=trusted,
        )
        fields = {(f.get("kind"), f.get("field")) for f in result["findings"]}
        self.assertIn((FINDING_DISCLOSURE, "fixture"), fields)
        self.assertNotIn((FINDING_DISCLOSURE, "given"), fields)

        altered = json.dumps(
            {
                "acceptance": True,
                "given": {"session": {"nonce": "other"}, "required_clearance": "x"},
                "proof": "p",
            }
        ).encode()
        leaked = analyze_presentation_leakage(
            raw_bytes=altered,
            release=_release(),
            expected_given=trusted,
        )
        leak_fields = {f.get("field") for f in leaked["findings"]}
        self.assertIn("given", leak_fields)
        self.assertEqual(leaked["status"], "findings")

    def test_permitted_projection_values_and_context_mapping(self):
        digest = "ab" * 32
        derived = "cd" * 32
        raw = json.dumps(
            {
                "acceptance": True,
                "profile": PROFILE,
                "statement_digest": digest,
                "protocol_derived_digest": derived,
                "proof": "p",
            }
        ).encode()
        clean = analyze_presentation_leakage(
            raw_bytes=raw,
            release=_release(),
            expected_derived_digest=derived,
            permitted_projection={
                "acceptance": True,
                "profile": PROFILE,
                "statement_digest": digest,
            },
        )
        unknown = {
            f.get("field")
            for f in clean["findings"]
            if f.get("kind") == "unknown_structured_field"
        }
        self.assertNotIn("profile", unknown)
        self.assertNotIn("statement_digest", unknown)

        mismatch = analyze_presentation_leakage(
            raw_bytes=raw,
            release=_release(),
            permitted_projection={"acceptance": False},
        )
        self.assertEqual(mismatch["status"], "findings")
        self.assertTrue(mismatch["findings"])

    def test_pair_eligibility_requires_stage_and_statement_identity(self):
        given = {"session": {"nonce": "n"}}
        projection = {"acceptance": True}
        proof_a = json.dumps({"acceptance": True, "proof": "opaque-aaa"}).encode()
        proof_b = json.dumps({"acceptance": True, "proof": "opaque-bbb"}).encode()
        missing = analyze_pair(
            left={
                "raw_bytes": proof_a,
                "given": given,
                "outcome": True,
                "permitted_projection": projection,
                "release": _release(),
            },
            right={
                "raw_bytes": proof_b,
                "given": given,
                "outcome": True,
                "permitted_projection": projection,
                "release": _release(),
            },
        )
        self.assertNotEqual(missing.get("eligibility"), "eligible")

        identity = "stmt-1"
        opaque = analyze_pair(
            left={
                "raw_bytes": proof_a,
                "given": given,
                "outcome": True,
                "permitted_projection": projection,
                "release": _release(),
                "stage": "accepted",
                "statement_identity": identity,
            },
            right={
                "raw_bytes": proof_b,
                "given": given,
                "outcome": True,
                "permitted_projection": projection,
                "release": _release(),
                "stage": "accepted",
                "statement_identity": identity,
            },
        )
        self.assertEqual(opaque.get("eligibility"), "eligible")
        self.assertEqual(opaque.get("status"), "inconclusive")

        hidden_a = json.dumps(
            {"acceptance": True, "proof": "p", "branch_selector": "left"}
        ).encode()
        hidden_b = json.dumps(
            {"acceptance": True, "proof": "p", "branch_selector": "right"}
        ).encode()
        hidden = analyze_pair(
            left={
                "raw_bytes": hidden_a,
                "given": given,
                "outcome": True,
                "permitted_projection": projection,
                "release": _release(),
                "stage": "accepted",
                "statement_identity": identity,
            },
            right={
                "raw_bytes": hidden_b,
                "given": given,
                "outcome": True,
                "permitted_projection": projection,
                "release": _release(),
                "stage": "accepted",
                "statement_identity": identity,
            },
        )
        self.assertEqual(hidden.get("eligibility"), "eligible")
        self.assertEqual(hidden.get("status"), "findings")
        kinds = {f.get("kind") for f in hidden.get("findings", [])}
        self.assertIn(FINDING_HIDDEN_FIELD, kinds)

        mismatched_stage = analyze_pair(
            left={
                "raw_bytes": proof_a,
                "given": given,
                "outcome": True,
                "permitted_projection": projection,
                "release": _release(),
                "stage": "accepted",
                "statement_identity": identity,
            },
            right={
                "raw_bytes": proof_b,
                "given": given,
                "outcome": True,
                "permitted_projection": projection,
                "release": _release(),
                "stage": "verifier_reject",
                "statement_identity": identity,
            },
        )
        self.assertEqual(mismatched_stage.get("eligibility"), "ineligible")

    def test_equal_given_mismatch_and_altered_allowed_output(self):
        trusted = {"session": {"nonce": "n1"}}
        matched = json.dumps(
            {"acceptance": True, "given": trusted, "proof": "p"}
        ).encode()
        clean_given = analyze_presentation_leakage(
            raw_bytes=matched,
            release=_release(),
            expected_given=trusted,
            permitted_projection={"acceptance": True},
        )
        fields = {f.get("field") for f in clean_given["findings"]}
        self.assertNotIn("given", fields)

        altered_output = analyze_presentation_leakage(
            raw_bytes=matched,
            release=_release(),
            expected_given=trusted,
            permitted_projection={"acceptance": False},
        )
        kinds = {f.get("kind") for f in altered_output["findings"]}
        self.assertEqual(altered_output["status"], "findings")
        self.assertIn("structured_output_mismatch", kinds)

    def test_independent_pair_eligibility_rejects_given_or_projection_mismatch(self):
        identity = "stmt-2"
        given_a = {"session": {"nonce": "n"}}
        given_b = {"session": {"nonce": "other"}}
        projection = {"acceptance": True}
        proof_a = json.dumps({"acceptance": True, "proof": "opaque-aaa"}).encode()
        proof_b = json.dumps({"acceptance": True, "proof": "opaque-bbb"}).encode()
        given_mismatch = analyze_pair(
            left={
                "raw_bytes": proof_a,
                "given": given_a,
                "outcome": True,
                "permitted_projection": projection,
                "release": _release(),
                "stage": "accepted",
                "statement_identity": identity,
            },
            right={
                "raw_bytes": proof_b,
                "given": given_b,
                "outcome": True,
                "permitted_projection": projection,
                "release": _release(),
                "stage": "accepted",
                "statement_identity": identity,
            },
        )
        self.assertEqual(given_mismatch.get("eligibility"), "ineligible")

        projection_mismatch = analyze_pair(
            left={
                "raw_bytes": proof_a,
                "given": given_a,
                "outcome": True,
                "permitted_projection": projection,
                "release": _release(),
                "stage": "accepted",
                "statement_identity": identity,
            },
            right={
                "raw_bytes": proof_b,
                "given": given_a,
                "outcome": True,
                "permitted_projection": {"acceptance": False},
                "release": _release(),
                "stage": "accepted",
                "statement_identity": identity,
            },
        )
        self.assertEqual(projection_mismatch.get("eligibility"), "ineligible")


if __name__ == "__main__":
    unittest.main()

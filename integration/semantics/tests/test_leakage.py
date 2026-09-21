"""Leakage detector library tests."""

import base64
import json
import unittest

from semantics.leakage import (
    FINDING_DISCLOSURE,
    FINDING_HIDDEN_FIELD,
    analyze_presentation_leakage,
)


class TestLeakageDetector(unittest.TestCase):
    def _release(self):
        return {
            "semantic_values": ["acceptance", "eid.issuer"],
            "protocol_derived": ["claim.context@1"],
            "opaque_channels": ["proof"],
        }

    def test_hidden_branch_selector_reported(self):
        raw = json.dumps({"branch_selector": "x", "acceptance": True}).encode()
        result = analyze_presentation_leakage(raw_bytes=raw, release=self._release())
        kinds = {f["kind"] for f in result["findings"]}
        self.assertEqual(result["status"], "findings")
        self.assertIn(FINDING_HIDDEN_FIELD, kinds)

    def test_fixture_disclosure_reported(self):
        raw = json.dumps({"fixture": {"credential": "x"}, "proof": "p"}).encode()
        result = analyze_presentation_leakage(raw_bytes=raw, release=self._release())
        kinds = {f["kind"] for f in result["findings"]}
        self.assertIn(FINDING_DISCLOSURE, kinds)

    def test_allowed_output_difference_excluded(self):
        raw = json.dumps({"acceptance": True, "proof": "p"}).encode()
        result = analyze_presentation_leakage(
            raw_bytes=raw,
            release=self._release(),
            permitted_projection={"acceptance": False},
        )
        kinds = {f["kind"] for f in result["findings"]}
        self.assertNotIn(FINDING_DISCLOSURE, kinds)
        self.assertNotIn("fixture_material_disclosed", kinds)

    def test_random_proof_noise_inconclusive(self):
        from semantics.leakage import analyze_pair

        given = {"session": {"nonce": "n"}}
        projection = {"acceptance": True}
        left = json.dumps({"acceptance": True, "proof": "aaa"}).encode()
        right = json.dumps({"acceptance": True, "proof": "bbb"}).encode()
        result = analyze_pair(
            left={
                "raw_bytes": left,
                "given": given,
                "outcome": True,
                "permitted_projection": projection,
                "release": self._release(),
                "stage": "accepted",
                "statement_identity": "stmt-noise",
            },
            right={
                "raw_bytes": right,
                "given": given,
                "outcome": True,
                "permitted_projection": projection,
                "release": self._release(),
                "stage": "accepted",
                "statement_identity": "stmt-noise",
            },
        )
        self.assertEqual(result.get("eligibility"), "eligible")
        self.assertEqual(result.get("status"), "inconclusive")

    def test_unknown_codec_not_run(self):
        result = analyze_presentation_leakage(raw_bytes=b"\xff\xfe\xfd", release=self._release())
        self.assertEqual(result["status"], "not_run")

    def test_base64_envelope_decoded(self):
        envelope = {"fixture": {"credential": "x"}, "proof": "p"}
        raw = base64.urlsafe_b64encode(json.dumps(envelope).encode())
        result = analyze_presentation_leakage(raw_bytes=raw, release=self._release())
        self.assertEqual(result["status"], "findings")


if __name__ == "__main__":
    unittest.main()

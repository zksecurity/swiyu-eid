"""CAMPAIGN harden RED — planner, support, leakage pair contracts."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from semantics.claims import load_claim
from semantics.planner import plan_campaign_cases
from semantics.support import SupportError, load_support, verify_claim_supported

CLAIMS = Path(__file__).resolve().parents[1] / "claims"
REFERENCE = (
    Path(__file__).resolve().parents[2]
    / "providers"
    / "semantic-reference"
)
SIX_ASSERTIONS = (
    "issuer_authentication",
    "metadata",
    "validity",
    "holder_authorization",
    "session_binding",
    "status",
)


class TestPlannerHardening(unittest.TestCase):
    def test_six_assertions_have_generated_failure_cases(self):
        claim = load_claim(CLAIMS / "clearance-status.json")
        cases = plan_campaign_cases(claim, seed=1, max_cases=64)
        recipes = " ".join(c.recipe for c in cases)
        for assertion_id in SIX_ASSERTIONS:
            matching = [
                c
                for c in cases
                if assertion_id in c.recipe
                and c.expectation_basis == "assertion_failure"
                and c.expected_verdict is False
            ]
            self.assertTrue(
                matching,
                f"missing generated failure case for {assertion_id}; recipes={recipes}",
            )
            ref = matching[0].reference_outcome
            self.assertEqual(ref.get("status"), "ok")
            self.assertIs(ref.get("value"), False)
            self.assertIs(ref["assertions"][assertion_id].get("value"), False)

    def test_false_where_keeps_crypto_obligations_valid(self):
        claim = load_claim(CLAIMS / "clearance-status.json")
        cases = plan_campaign_cases(claim, seed=1, max_cases=64)
        false_where = [
            c for c in cases if c.expectation_basis == "where_false" and c.expected_verdict is False
        ]
        self.assertTrue(false_where, "missing independently signed false-where case")
        for case in false_where:
            ref = case.reference_outcome
            self.assertEqual(ref.get("status"), "ok")
            self.assertIs(ref.get("value"), False)
            self.assertIs(ref.get("condition", {}).get("value"), False)
            for assertion_id in SIX_ASSERTIONS:
                entry = ref["assertions"][assertion_id]
                self.assertEqual(entry.get("status"), "ok")
                self.assertIs(entry.get("value"), True, assertion_id)

    def test_composed_or_true_branch_coverage_tt_tf_ft_ff(self):
        claim = load_claim(CLAIMS / "composed-status.json")
        cases = plan_campaign_cases(claim, seed=1, max_cases=64)
        labels = ("or_tt", "or_tf", "or_ft", "or_ff")
        found = {
            label: [c for c in cases if label in c.recipe]
            for label in labels
        }
        for label in labels:
            self.assertTrue(found[label], f"missing constructible OR branch {label}")
        self.assertTrue(found["or_tt"][0].expected_verdict)
        self.assertTrue(found["or_tf"][0].expected_verdict)
        self.assertTrue(found["or_ft"][0].expected_verdict)
        self.assertFalse(found["or_ff"][0].expected_verdict)

    def test_max_cases_records_unrun_recipes_instead_of_dropping(self):
        claim = load_claim(CLAIMS / "clearance-status.json")
        limited = plan_campaign_cases(claim, seed=1, max_cases=2)
        self.assertTrue(
            any(c.expectation_basis == "not_run" for c in limited),
            "max_cases must not silently hide unrun cryptographic recipes",
        )


class TestSupportHardening(unittest.TestCase):
    def _claim(self):
        return load_claim(CLAIMS / "clearance-status.json")

    def test_enforces_all_manifest_obligations_for_claim(self):
        claim = self._claim()
        support = load_support(REFERENCE / "support.json")
        verify_claim_supported(
            support,
            claim_id=claim.document["id"],
            statement_digest=claim.statement_digest,
            claim=claim,
        )
        required = {entry["id"] for entry in claim.document["require"]}
        required.add("where")
        self.assertTrue(required.issubset(set(support["enforcement"])))

        with tempfile.TemporaryDirectory() as tmp:
            doc = json.loads((REFERENCE / "support.json").read_text(encoding="utf-8"))
            del doc["enforcement"]["validity"]
            path = Path(tmp) / "support.json"
            (Path(tmp) / "provider.py").write_bytes((REFERENCE / "provider.py").read_bytes())
            doc["approved_roots"] = []
            doc["artifact_pins"] = [
                {
                    "path": "provider.py",
                    "sha256": __import__("hashlib").sha256(
                        (Path(tmp) / "provider.py").read_bytes()
                    ).hexdigest(),
                }
            ]
            path.write_text(json.dumps(doc), encoding="utf-8")
            loaded = load_support(path)
            with self.assertRaises(SupportError):
                verify_claim_supported(
                    loaded,
                    claim_id=claim.document["id"],
                    statement_digest=claim.statement_digest,
                    claim=claim,
                )

    def test_unknown_and_duplicate_obligations_rejected(self):
        claim = self._claim()
        with tempfile.TemporaryDirectory() as tmp:
            doc = json.loads((REFERENCE / "support.json").read_text(encoding="utf-8"))
            doc["enforcement"]["not-a-real-obligation"] = "verifier"
            path = Path(tmp) / "support.json"
            (Path(tmp) / "provider.py").write_bytes((REFERENCE / "provider.py").read_bytes())
            doc["approved_roots"] = []
            doc["artifact_pins"] = [
                {
                    "path": "provider.py",
                    "sha256": __import__("hashlib").sha256(
                        (Path(tmp) / "provider.py").read_bytes()
                    ).hexdigest(),
                }
            ]
            path.write_text(json.dumps(doc), encoding="utf-8")
            loaded = load_support(path)
            with self.assertRaises(SupportError):
                verify_claim_supported(
                    loaded,
                    claim_id=claim.document["id"],
                    statement_digest=claim.statement_digest,
                    claim=claim,
                )

        with tempfile.TemporaryDirectory() as tmp:
            doc = json.loads((REFERENCE / "support.json").read_text(encoding="utf-8"))
            doc["supported_claims"].append(copy.deepcopy(doc["supported_claims"][0]))
            path = Path(tmp) / "support.json"
            (Path(tmp) / "provider.py").write_bytes((REFERENCE / "provider.py").read_bytes())
            doc["approved_roots"] = []
            doc["artifact_pins"] = [
                {
                    "path": "provider.py",
                    "sha256": __import__("hashlib").sha256(
                        (Path(tmp) / "provider.py").read_bytes()
                    ).hexdigest(),
                }
            ]
            path.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaises(SupportError):
                load_support(path)

    def test_stale_artifact_not_autohealed(self):
        original = (REFERENCE / "support.json").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            doc = json.loads(original)
            doc["artifact_pins"] = [{"path": "provider.py", "sha256": "0" * 64}]
            doc["approved_roots"] = []
            (Path(tmp) / "provider.py").write_text("# stale\n", encoding="utf-8")
            path = Path(tmp) / "support.json"
            path.write_text(json.dumps(doc), encoding="utf-8")
            before = path.read_text(encoding="utf-8")
            with self.assertRaises(SupportError):
                load_support(path)
            self.assertEqual(path.read_text(encoding="utf-8"), before)


class TestLeakagePairHardening(unittest.TestCase):
    def _release(self):
        return {
            "semantic_values": ["acceptance"],
            "protocol_derived": ["claim.context@1"],
            "opaque_channels": ["proof"],
        }

    def test_analyze_pair_eligibility_and_random_proof_bytes_without_marker(self):
        from semantics.leakage import analyze_pair

        given = {"session": {"nonce": "n1"}}
        projection = {"acceptance": True}
        allowed_left = json.dumps({"acceptance": True, "proof": "aa"}).encode()
        allowed_right = json.dumps({"acceptance": False, "proof": "aa"}).encode()
        ineligible = analyze_pair(
            left={
                "raw_bytes": allowed_left,
                "given": given,
                "outcome": True,
                "permitted_projection": projection,
                "release": self._release(),
                "stage": "accepted",
                "statement_identity": "stmt-pair",
            },
            right={
                "raw_bytes": allowed_right,
                "given": given,
                "outcome": False,
                "permitted_projection": {"acceptance": False},
                "release": self._release(),
                "stage": "verifier_reject",
                "statement_identity": "stmt-pair",
            },
        )
        self.assertEqual(ineligible.get("eligibility"), "ineligible")
        self.assertNotEqual(ineligible.get("status"), "findings")

        proof_a = json.dumps({"acceptance": True, "proof": "opaque-aaa"}).encode()
        proof_b = json.dumps({"acceptance": True, "proof": "opaque-bbb"}).encode()
        self.assertNotIn(b"_random_proof_noise", proof_a + proof_b)
        inconclusive = analyze_pair(
            left={
                "raw_bytes": proof_a,
                "given": given,
                "outcome": True,
                "permitted_projection": projection,
                "release": self._release(),
                "stage": "accepted",
                "statement_identity": "stmt-pair",
            },
            right={
                "raw_bytes": proof_b,
                "given": given,
                "outcome": True,
                "permitted_projection": projection,
                "release": self._release(),
                "stage": "accepted",
                "statement_identity": "stmt-pair",
            },
        )
        self.assertEqual(inconclusive.get("eligibility"), "eligible")
        self.assertEqual(inconclusive.get("status"), "inconclusive")
        kinds = {f.get("kind") for f in inconclusive.get("findings", [])}
        self.assertNotIn("fixture_material_disclosed", kinds)

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
                "release": self._release(),
                "stage": "accepted",
                "statement_identity": "stmt-pair",
            },
            right={
                "raw_bytes": hidden_b,
                "given": given,
                "outcome": True,
                "permitted_projection": projection,
                "release": self._release(),
                "stage": "accepted",
                "statement_identity": "stmt-pair",
            },
        )
        self.assertEqual(hidden.get("eligibility"), "eligible")
        self.assertEqual(hidden.get("status"), "findings")


class TestCliAndSupportHardening(unittest.TestCase):
    def test_five_artifact_pins_verified_on_load(self):
        support = load_support(REFERENCE / "support.json")
        self.assertEqual(len(support["artifact_pins"]), 5)

    def test_cli_rejects_duplicate_and_nonfinite_json(self):
        import os
        import subprocess
        import sys

        semantics_root = Path(__file__).resolve().parents[1]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(semantics_root)
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "fixture.json"
            given = Path(tmp) / "given.json"
            fixture.write_text('{"a": 1, "a": 2}', encoding="utf-8")
            given.write_text('{"now": Infinity}', encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "semantics.claim_cli",
                    "evaluate",
                    "--claim",
                    str(CLAIMS / "clearance-status.json"),
                    "--fixture",
                    str(fixture),
                    "--given",
                    str(given),
                ],
                cwd="/",
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertNotIn("Traceback", proc.stderr)
            self.assertNotIn("Traceback", proc.stdout)

    def test_cli_isolated_missing_cryptography_has_no_traceback(self):
        import os
        import subprocess
        import sys

        semantics_root = Path(__file__).resolve().parents[1]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(semantics_root)
        proc = subprocess.run(
            [
                sys.executable,
                "-S",
                "-m",
                "semantics.claim_cli",
                "check",
                "--claim",
                str(CLAIMS / "clearance-status.json"),
            ],
            cwd="/",
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn("Traceback", proc.stderr)
        self.assertNotIn("Traceback", proc.stdout)
        self.assertIn("cryptography", proc.stderr.lower() + proc.stdout.lower())


if __name__ == "__main__":
    unittest.main()

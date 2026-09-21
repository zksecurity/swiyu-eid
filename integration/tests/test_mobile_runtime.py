import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))

from mobile_runtime import MobileRuntimeError, run_facade


def valid_request() -> dict:
    return {
        "schema": "swiyu.mobile-runtime-facade.v1",
        "provider_manifest": str(ROOT / "providers" / "test-stub" / "manifest.json"),
        "profile": "swiyu-test-age18-v0",
        "credential": {
            "format": "dc+sd-jwt",
            "data": '{"birthdate":"2000-06-15","holder":"alice"}',
        },
        "request_context": {"nonce": "mobile-nonce-1", "audience": "verifier.test"},
        "inputs": {"cutoff_date": "2024-01-01"},
    }


class TestMobileRuntimeFacade(unittest.TestCase):
    def test_request_validation_names_missing_field(self):
        with self.assertRaises(MobileRuntimeError) as caught:
            run_facade({"schema": "swiyu.mobile-runtime-facade.v1"})

        self.assertEqual(caught.exception.code, "invalid_request")
        self.assertIn("provider_manifest", str(caught.exception))

    def test_successful_local_run_returns_presentation_token_and_verifier_result(self):
        result = run_facade(valid_request())

        self.assertEqual(set(result), {"schema", "presentation", "verifier"})
        self.assertEqual(result["schema"], "swiyu.mobile-runtime-result.v1")
        self.assertIsInstance(result["presentation"], str)
        self.assertGreater(len(result["presentation"]), 0)
        self.assertEqual(result["verifier"], {"verified": True, "reason": None})

    def test_wrong_challenge_is_rejected_by_verifier(self):
        request = valid_request()
        request["verification_context"] = {
            "nonce": "different-nonce",
            "audience": "verifier.test",
        }

        result = run_facade(request)

        self.assertEqual(result["verifier"], {
            "verified": False,
            "reason": "binding_or_predicate_failed",
        })

    def test_unavailable_provider_has_clear_facade_error(self):
        request = valid_request()
        request["provider_manifest"] = "/missing/provider/manifest.json"

        with self.assertRaises(MobileRuntimeError) as caught:
            run_facade(request)

        self.assertEqual(caught.exception.code, "provider_unavailable")
        self.assertIn("manifest not found", str(caught.exception))

    def test_cli_executes_golden_fixture(self):
        fixture_path = ROOT / "contracts" / "fixtures" / "local-mobile-runtime-v1.json"
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "runtime" / "mobile_runtime.py"),
                str(fixture_path),
            ],
            cwd=ROOT.parent,
            check=True,
            capture_output=True,
            text=True,
        )

        result = json.loads(completed.stdout)
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        self.assertEqual(result, fixture["expected"])


if __name__ == "__main__":
    unittest.main()

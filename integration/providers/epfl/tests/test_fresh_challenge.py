"""Fresh-challenge native present tests for synthetic EPFL fixtures."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

PROVIDER_DIR = Path(__file__).resolve().parents[1]
TOOLCHAIN = Path("/tmp/swiyu-epfl-20260915/owned/scratch/toolchain/bin")
D10_PROFILE = "epfl-d10-swiyu-jwt-age25-v0"

sys.path.insert(0, str(PROVIDER_DIR))
from fixtures import VARIANT_A, fresh_challenge_hex  # noqa: E402


def _load_tests():
    spec = importlib.util.spec_from_file_location("epfl_tests", PROVIDER_DIR / "tests" / "test_provider.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class EpflFreshChallengeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        mod = _load_tests()
        if not mod._have_toolchain():
            raise unittest.SkipTest("toolchain missing")
        cls.client = mod.ProviderProcess()
        init = cls.client.call("initialize", {})
        if init.get("status") != "ok":
            raise RuntimeError(init)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()

    def test_synthetic_sd_jwt_present_rotates_challenge(self) -> None:
        prep = self.client.call("prepare", {
            "profile": D10_PROFILE,
            "credential": {"format": "epfl-variant", "variant": VARIANT_A.variant_id},
        })
        self.assertEqual(prep["status"], "ok", prep)
        nonce_a = list(bytes.fromhex(fresh_challenge_hex(b"session-a")))
        nonce_b = list(bytes.fromhex(fresh_challenge_hex(b"session-b")))
        ctx = {
            "issuer_pub_x": VARIANT_A.issuer_pub_x,
            "issuer_pub_y": VARIANT_A.issuer_pub_y,
            "now_date": 20240101,
            "challenge_nonce": nonce_a,
        }
        present_a = self.client.call("present", {
            "profile": D10_PROFILE,
            "handle": prep["result"]["handle"],
            "request_context": ctx,
        })
        self.assertEqual(present_a["status"], "ok", present_a)
        self.assertEqual(
            present_a["result"]["public_outputs"]["challenge_binding"],
            "fresh-request-context-nonce",
        )
        verify_a = self.client.call("verify", {
            "profile": D10_PROFILE,
            "presentation": present_a["result"]["presentation"],
            "request_context": ctx,
        })
        self.assertTrue(verify_a["result"]["verified"])
        ctx_b = {**ctx, "challenge_nonce": nonce_b}
        present_b = self.client.call("present", {
            "profile": D10_PROFILE,
            "handle": prep["result"]["handle"],
            "request_context": ctx_b,
        })
        self.assertEqual(present_b["status"], "ok", present_b)
        self.assertNotEqual(
            json.loads(present_a["result"]["presentation"])["proof_b64"],
            json.loads(present_b["result"]["presentation"])["proof_b64"],
        )
        self.assertNotIn("public_inputs_b64", json.loads(present_a["result"]["presentation"]))

    def test_wrong_challenge_nonce_rejected_on_verify(self) -> None:
        prep = self.client.call("prepare", {
            "profile": D10_PROFILE,
            "credential": {"format": "epfl-variant", "variant": VARIANT_A.variant_id},
        })
        nonce = list(bytes.fromhex(fresh_challenge_hex(b"good-challenge")))
        ctx = {
            "issuer_pub_x": VARIANT_A.issuer_pub_x,
            "issuer_pub_y": VARIANT_A.issuer_pub_y,
            "now_date": 20240101,
            "challenge_nonce": nonce,
        }
        present = self.client.call("present", {
            "profile": D10_PROFILE,
            "handle": prep["result"]["handle"],
            "request_context": ctx,
        })
        self.assertEqual(present["status"], "ok", present)
        bad_nonce = list(nonce)
        bad_nonce[0] = (bad_nonce[0] + 1) % 256
        verify = self.client.call("verify", {
            "profile": D10_PROFILE,
            "presentation": present["result"]["presentation"],
            "request_context": {**ctx, "challenge_nonce": bad_nonce},
        })
        self.assertEqual(verify["status"], "ok", verify)
        self.assertFalse(verify["result"]["verified"])

    def test_underage_variant_cannot_present(self) -> None:
        from fixtures import _build_variant, write_prover_toml

        young = _build_variant("underage-native", "2010-01-01", "U9nderageSalt00001")
        nonce = list(bytes.fromhex(fresh_challenge_hex(b"age-boundary")))
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as handle:
            prover_path = Path(handle.name)
            write_prover_toml(young, nonce, prover_path)
        try:
            prep = self.client.call("prepare", {
                "profile": D10_PROFILE,
                "credential": {"format": "epfl-d10-prover-toml", "path": str(prover_path)},
            })
            self.assertEqual(prep["status"], "ok", prep)
            present = self.client.call("present", {
                "profile": D10_PROFILE,
                "handle": prep["result"]["handle"],
                "request_context": {
                    "issuer_pub_x": young.issuer_pub_x,
                    "issuer_pub_y": young.issuer_pub_y,
                    "now_date": 20240101,
                    "challenge_nonce": nonce,
                },
            })
            self.assertEqual(present["status"], "error", present)
            self.assertEqual(present["error"]["code"], "predicate_unsatisfied")
            self.assertIn("older", present["error"]["message"].lower())
        finally:
            prover_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()

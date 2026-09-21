"""EPFL transcript sidecar and challenge-binding tests."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

PROVIDER_DIR = Path(__file__).resolve().parents[1]
TOOLCHAIN = Path("/tmp/swiyu-epfl-20260915/owned/scratch/toolchain/bin")
SCRATCH_PROVER = Path("/tmp/swiyu-epfl-20260915/d10/circuit/Prover.toml")
PYTHON = PROVIDER_DIR.parents[1] / "semantics" / ".venv" / "bin" / "python"


def _load_challenge():
    spec = importlib.util.spec_from_file_location("epfl_challenge", PROVIDER_DIR / "epfl_challenge.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _load_provider_tests():
    spec = importlib.util.spec_from_file_location("epfl_provider_tests", PROVIDER_DIR / "tests" / "test_provider.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class EpflChallengeBindingTests(unittest.TestCase):
    def test_deterministic_vector_matches_java(self) -> None:
        challenge = _load_challenge()
        policy_inputs = challenge.policy_inputs_json(
            "d10_swiyu_jwt",
            "853657d2e701215a65c5d97ab3cf5640e9aa8379ac6d106b7c82dc9b9d078e79",
            "9b45cc7462a236b1056d21c19e1e4dfc2cf52fd20538d43fbe072d9ed106e9d6",
            20240101,
        )
        digest = challenge.digest_hex(
            "nonce-alpha",
            "did:example:verifier",
            "https://example.test/oid4vp/api/request-object/00000000-0000-4000-8000-000000000001/response-data",
            "state-beta",
            "birth_date",
            challenge.PROFILE,
            policy_inputs,
        )
        self.assertEqual(
            "71904c78267613800be90ce2b62f3ef571de0a94eb2f41d2053d8aa58f528f90",
            digest,
        )


@unittest.skipUnless(
    TOOLCHAIN.joinpath("bb").is_file() and SCRATCH_PROVER.is_file() and PYTHON.is_file(),
    "native toolchain and static d10 fixture required",
)
class EpflTranscriptSidecarTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.challenge = _load_challenge()
        cls.provider_tests = _load_provider_tests()
        cls.client = cls.provider_tests.ProviderProcess()
        cls.public = cls.provider_tests._d10_public(SCRATCH_PROVER)
        proved = cls.client.call(
            "present",
            {
                "profile": "epfl-d10-swiyu-jwt-age25-v0",
                "handle": cls.client.call(
                    "prepare",
                    {
                        "profile": "epfl-d10-swiyu-jwt-age25-v0",
                        "credential": {"format": "epfl-d10-prover-toml", "path": str(SCRATCH_PROVER)},
                    },
                )["result"]["handle"],
                "request_context": cls.public,
            },
        )
        if proved.get("status") != "ok":
            raise RuntimeError(proved)
        cls.presentation = proved["result"]["presentation"]
        cls.expected = {
            "binding_mode": "native-static-v0",
            "nonce": "nonce-sidecar",
            "client_id": "did:example:verifier",
            "response_uri": "https://example.test/response-data",
            "state": "state-sidecar",
            "query_id": "birth_date",
            "profile": cls.challenge.PROFILE,
            "circuit_id": cls.challenge.CIRCUIT_ID,
            "issuer_pub_x": cls.public["issuer_pub_x"],
            "issuer_pub_y": cls.public["issuer_pub_y"],
            "now_date": cls.public["now_date"],
            "challenge_nonce": "".join(f"{b:02x}" for b in cls.public["challenge_nonce"]),
        }

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()

    def test_static_native_binding_via_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "fixture.json"
            ready = Path(tmp) / "ready.json"
            fixture.write_text(
                json.dumps({"schema": "swiyu.transcript-fixture.v1", "variants": []}),
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["PATH"] = f"{TOOLCHAIN}:{env.get('PATH', '')}"
            env["SWIYU_EPFL_TOOLCHAIN"] = str(TOOLCHAIN)
            proc = subprocess.Popen(
                [str(PYTHON), str(PROVIDER_DIR / "transcript-sidecar.py"),
                 "--fixture", str(fixture), "--ready-file", str(ready)],
                cwd=PROVIDER_DIR,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                for _ in range(120):
                    if ready.is_file():
                        break
                    if proc.poll() is not None:
                        err = proc.stderr.read() if proc.stderr else ""
                        self.fail(f"sidecar exited early: {err}")
                    import time
                    time.sleep(2)
                ready_doc = json.loads(ready.read_text(encoding="utf-8"))
                body = json.dumps({"proof_envelope": self.presentation, "expected": self.expected}).encode("utf-8")
                request = urllib.request.Request(
                    ready_doc["url"],
                    data=body,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=180) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                self.assertTrue(payload["verified"])
                self.assertTrue(payload["predicate_satisfied"])
            finally:
                proc.terminate()
                proc.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()

"""OpenAC age-25 session-bound envelope is OpenAC-shaped and Java-session bound."""

from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

HARNESS = Path(__file__).resolve().parents[1]
OPENAC = Path(__file__).resolve().parents[2] / "providers" / "openac"
for path in (str(HARNESS), str(OPENAC)):
    if path not in sys.path:
        sys.path.insert(0, path)

from age25_transcript_wallet import (  # noqa: E402
    CIRCUIT_ID,
    ENVELOPE_VERSION,
    PROFILE,
    Age25TranscriptWallet,
    parse_envelope,
)
from transcript_shared import default_backends  # noqa: E402


class Age25TranscriptWalletTests(unittest.TestCase):
    def test_envelope_matches_openac_wire_and_binds_session(self):
        wallet = Age25TranscriptWallet()
        prepared = wallet.call(
            "prepare",
            {
                "profile": PROFILE,
                "credential": {"format": "dc+sd-jwt", "data": "unused"},
                "context": {
                    "lookup": {
                        "issuer": "did:example:epfl-test-issuer",
                        "kid": "epfl-test-key-1",
                        "vct": "https://example.ch/vct/epfl-d10-test",
                    }
                },
            },
        )
        first = wallet.call(
            "present",
            {
                "profile": PROFILE,
                "handle": prepared["handle"],
                "request_context": {
                    "nonce": "nonce-a",
                    "clientId": "did:example:verifier",
                    "responseUri": "http://127.0.0.1:9/oid4vp/api/request-object/1/response-data",
                    "state": "state-a",
                    "now_date": 20240101,
                },
            },
        )
        second = wallet.call(
            "present",
            {
                "profile": PROFILE,
                "handle": prepared["handle"],
                "request_context": {
                    "nonce": "nonce-b",
                    "clientId": "did:example:verifier",
                    "responseUri": "http://127.0.0.1:9/oid4vp/api/request-object/1/response-data",
                    "state": "state-b",
                    "now_date": 20240101,
                },
            },
        )
        envelope = parse_envelope(first["presentation"])
        self.assertEqual(envelope["version"], ENVELOPE_VERSION)
        self.assertEqual(set(envelope), {"version", "profile", "circuitId", "proof", "lookup"})
        self.assertEqual(set(envelope["lookup"]), {"issuer", "kid", "vct"})
        self.assertNotEqual(first["presentation"], second["presentation"])
        dumped = json.dumps(envelope)
        self.assertNotIn("1988-06-19", dumped)
        self.assertNotIn("birth_date", dumped)
        self.assertEqual(first["artifact_sizes"]["proof"], 32768)

    def test_sidecar_accepts_bound_envelope_and_rejects_replay(self):
        document = {
            "schema": "swiyu.transcript-fixture.v1",
            "variants": [
                {
                    "given": {
                        "issuer": {
                            "issuer_id": "did:example:epfl-test-issuer",
                            "key_id": "epfl-test-key-1",
                            "allowed_vcts": ["https://example.ch/vct/epfl-d10-test"],
                        }
                    },
                    "prepare": {
                        "context": {
                            "lookup": {
                                "issuer": "did:example:epfl-test-issuer",
                                "kid": "epfl-test-key-1",
                                "vct": "https://example.ch/vct/epfl-d10-test",
                            }
                        }
                    },
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "fixture.json"
            ready = Path(tmp) / "ready.json"
            fixture.write_text(json.dumps(document))
            proc = __import__("subprocess").Popen(
                [sys.executable, str(OPENAC / "transcript-sidecar-age25.py"),
                 "--fixture", str(fixture), "--ready-file", str(ready)],
                stdout=__import__("subprocess").DEVNULL,
                stderr=__import__("subprocess").DEVNULL,
                start_new_session=True,
            )
            try:
                url = None
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if ready.exists():
                        url = json.loads(ready.read_text())["url"]
                        break
                    time.sleep(0.05)
                self.assertIsNotNone(url)
                wallet = Age25TranscriptWallet()
                prepared = wallet.call(
                    "prepare",
                    {
                        "profile": PROFILE,
                        "context": {
                            "lookup": {
                                "issuer": "did:example:epfl-test-issuer",
                                "kid": "epfl-test-key-1",
                                "vct": "https://example.ch/vct/epfl-d10-test",
                            }
                        },
                    },
                )
                session = {
                    "nonce": "nonce-live",
                    "clientId": "did:example:verifier",
                    "responseUri": "http://127.0.0.1:9/response-data",
                    "state": "state-live",
                    "now_date": 20240101,
                }
                presented = wallet.call(
                    "present",
                    {"profile": PROFILE, "handle": prepared["handle"], "request_context": session},
                )
                expected = {
                    "nonce": session["nonce"],
                    "client_id": session["clientId"],
                    "response_uri": session["responseUri"],
                    "state": session["state"],
                    "query_id": "birth_date",
                    "profile": PROFILE,
                    "circuit_id": CIRCUIT_ID,
                    "now_date": 20240101,
                }
                body = json.dumps(
                    {"proof_envelope": presented["presentation"], "expected": expected},
                    separators=(",", ":"),
                ).encode("utf-8")
                request = urllib.request.Request(
                    url, data=body, method="POST", headers={"Content-Type": "application/json"}
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    accepted = json.loads(response.read().decode("utf-8"))
                self.assertTrue(accepted["verified"])
                self.assertEqual(accepted["profile"], PROFILE)
                replay = json.dumps(expected | {"nonce": "other-nonce"}, separators=(",", ":")).encode()
                # rebuild expected with mutated nonce
                mutated = dict(expected)
                mutated["nonce"] = "other-nonce"
                replay_body = json.dumps(
                    {"proof_envelope": presented["presentation"], "expected": mutated},
                    separators=(",", ":"),
                ).encode("utf-8")
                replay_request = urllib.request.Request(
                    url, data=replay_body, method="POST", headers={"Content-Type": "application/json"}
                )
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    urllib.request.urlopen(replay_request, timeout=5)
                self.assertEqual(raised.exception.code, 400)
            finally:
                proc.terminate()
                proc.wait(timeout=5)

    def test_default_backends_point_at_matching_sidecars(self):
        backends = {item["id"]: item for item in default_backends()}
        self.assertTrue(Path(backends["epfl"]["sidecar"]).is_file())
        self.assertTrue(Path(backends["openac"]["sidecar"]).is_file())
        self.assertEqual(backends["openac"]["proofs"], "openac-age25-synthetic-envelope")
        self.assertEqual(backends["epfl"]["proofs"], "native-ultrahonk")


if __name__ == "__main__":
    unittest.main()

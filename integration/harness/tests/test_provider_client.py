"""ProviderClient lifecycle tests (T06)."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

from manifest import ManifestError
from provider_client import ProviderClient, ProviderError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROVIDERS = os.path.abspath(os.path.join(ROOT, "..", "providers"))
STUB_MANIFEST = os.path.join(PROVIDERS, "test-stub", "manifest.json")

ADULT_CRED = json.dumps({"birthdate": "2000-06-15", "holder": "alice"})
UNDERAGE_CRED = json.dumps({"birthdate": "2015-03-01", "holder": "bob"})


def _prepare_payload(cred_data: str) -> dict:
    return {
        "profile": "swiyu-test-age18-v0",
        "credential": {"format": "dc+sd-jwt", "data": cred_data},
        "context": {},
    }


class TestProviderClient(unittest.TestCase):
    def test_lifecycle_adult(self):
        with ProviderClient(STUB_MANIFEST, timeout=5.0) as client:
            caps = client.call("initialize", {})
            self.assertIn("profiles", caps)
            prep = client.call("prepare", _prepare_payload(ADULT_CRED))
            handle = prep["handle"]
            pres = client.call("present", {
                "profile": "swiyu-test-age18-v0",
                "handle": handle,
                "request_context": {"nonce": "n1", "audience": "verifier.test"},
                "inputs": {},
            })
            self.assertIn("presentation", pres)
            ver = client.call("verify", {
                "profile": "swiyu-test-age18-v0",
                "presentation": pres["presentation"],
                "request_context": {"nonce": "n1", "audience": "verifier.test"},
                "inputs": {"cutoff_date": "2024-01-01"},
            })
            self.assertTrue(ver["verified"])
            client.call("cleanup", {})

    def test_underage_rejected(self):
        with ProviderClient(STUB_MANIFEST, timeout=5.0) as client:
            client.call("initialize", {})
            prep = client.call("prepare", _prepare_payload(UNDERAGE_CRED))
            pres = client.call("present", {
                "profile": "swiyu-test-age18-v0",
                "handle": prep["handle"],
                "request_context": {"nonce": "n2", "audience": "v"},
                "inputs": {},
            })
            ver = client.call("verify", {
                "profile": "swiyu-test-age18-v0",
                "presentation": pres["presentation"],
                "request_context": {"nonce": "n2", "audience": "v"},
                "inputs": {"cutoff_date": "2024-01-01"},
            })
            self.assertFalse(ver["verified"])

    def test_wrong_nonce_rejected(self):
        with ProviderClient(STUB_MANIFEST, timeout=5.0) as client:
            client.call("initialize", {})
            prep = client.call("prepare", _prepare_payload(ADULT_CRED))
            pres = client.call("present", {
                "profile": "swiyu-test-age18-v0",
                "handle": prep["handle"],
                "request_context": {"nonce": "good", "audience": "v"},
                "inputs": {},
            })
            ver = client.call("verify", {
                "profile": "swiyu-test-age18-v0",
                "presentation": pres["presentation"],
                "request_context": {"nonce": "bad", "audience": "v"},
                "inputs": {"cutoff_date": "2024-01-01"},
            })
            self.assertFalse(ver["verified"])

    def test_unknown_profile_unsupported(self):
        with ProviderClient(STUB_MANIFEST, timeout=5.0) as client:
            client.call("initialize", {})
            with self.assertRaises(ProviderError) as ctx:
                client.call("prepare", {
                    "profile": "unknown-profile",
                    "credential": {"format": "dc+sd-jwt", "data": ADULT_CRED},
                    "context": {},
                })
            self.assertEqual(ctx.exception.status, "unsupported")

    def test_cleanup_on_exit(self):
        proc = None
        with ProviderClient(STUB_MANIFEST, timeout=5.0) as client:
            proc = client._proc
            client.call("initialize", {})
        self.assertIsNotNone(proc)
        self.assertIsNotNone(proc.poll())

    def test_bad_manifest_path(self):
        with self.assertRaises(ManifestError):
            ProviderClient("/nonexistent/manifest.json")

    def test_uses_start_new_session(self):
        with ProviderClient(STUB_MANIFEST, timeout=5.0) as client:
            proc = client._proc
            self.assertIsNotNone(proc)
            self.assertEqual(os.getpgid(proc.pid), proc.pid)
            client.call("initialize", {})


if __name__ == "__main__":
    unittest.main()

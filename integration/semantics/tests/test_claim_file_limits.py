"""Untrusted claim files fail through the public validation error interface."""
import tempfile
import unittest
from pathlib import Path

from semantics.claims import ClaimError, load_claim


class TestClaimFileLimits(unittest.TestCase):
    def test_deep_json_rejected_as_claim_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "deep.json"
            path.write_text('{"value":' + '[' * 3000 + '0' + ']' * 3000 + '}')
            with self.assertRaises(ClaimError):
                load_claim(path)

    def test_oversized_claim_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.json"
            path.write_bytes(b' ' * 65537)
            with self.assertRaises(ClaimError):
                load_claim(path)

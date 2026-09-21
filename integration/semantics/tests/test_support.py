"""Support manifest validation tests."""

import json
import tempfile
import unittest
from pathlib import Path

from semantics.support import SupportError, load_support, verify_claim_supported

ROOT = Path(__file__).resolve().parents[2] / "providers" / "semantic-reference"
SUPPORT = ROOT / "support.json"


class TestSupportManifest(unittest.TestCase):
    def test_load_reference_support(self):
        support = load_support(SUPPORT)
        self.assertEqual(support["schema"], "swiyu.claim-support.v0")
        self.assertGreaterEqual(len(support["supported_claims"]), 3)

    def test_manifest_support_mismatch_rejected(self):
        support = load_support(SUPPORT)
        with self.assertRaises(SupportError):
            verify_claim_supported(
                support,
                claim_id="test.clearance-status.v1",
                statement_digest="0" * 64,
            )

    def test_stale_artifact_pin_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "support.json"
            doc = json.loads(SUPPORT.read_text(encoding="utf-8"))
            doc["artifact_pins"] = [{"path": "provider.py", "sha256": "0" * 64}]
            (Path(tmp) / "provider.py").write_text("# stale\n", encoding="utf-8")
            bad.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaises(SupportError):
                load_support(bad)


if __name__ == "__main__":
    unittest.main()

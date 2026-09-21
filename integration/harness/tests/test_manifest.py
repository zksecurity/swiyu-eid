"""Manifest validation tests (T06/T17 subset)."""
import json
import os
import tempfile
import unittest

from manifest import ManifestError, load_manifest, validate_manifest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROVIDERS = os.path.abspath(os.path.join(ROOT, "..", "providers"))
STUB = os.path.join(PROVIDERS, "test-stub", "manifest.json")
FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "bad_manifests")


class TestManifest(unittest.TestCase):
    def test_valid_stub_manifest(self):
        m = load_manifest(STUB)
        self.assertEqual(m["schema"], "swiyu.provider-manifest.v1")
        self.assertEqual(m["kind"], "test-only")
        self.assertIn("swiyu-test-age18-v0", m["profiles"])

    def test_reject_missing_schema(self):
        with self.assertRaises(ManifestError):
            validate_manifest({"id": "x", "title": "t", "kind": "test-only",
                               "profiles": ["p"], "command": ["python3", "p.py"]})

    def test_reject_bad_kind(self):
        with self.assertRaises(ManifestError):
            validate_manifest({
                "schema": "swiyu.provider-manifest.v1", "id": "x", "title": "t",
                "kind": "bogus", "profiles": ["p"], "command": ["python3", "p.py"],
            })

    def test_reject_empty_command(self):
        with self.assertRaises(ManifestError):
            validate_manifest({
                "schema": "swiyu.provider-manifest.v1", "id": "x", "title": "t",
                "kind": "test-only", "profiles": ["p"], "command": [],
            })

    def test_reject_non_list_profiles(self):
        with self.assertRaises(ManifestError):
            validate_manifest({
                "schema": "swiyu.provider-manifest.v1", "id": "x", "title": "t",
                "kind": "test-only", "profiles": "not-a-list",
                "command": ["python3", "p.py"],
            })

    def test_reject_invalid_circuit_declarations(self):
        with self.assertRaises(ManifestError):
            validate_manifest({
                "schema": "swiyu.provider-manifest.v1", "id": "x", "title": "t",
                "kind": "implementation", "profiles": ["p"],
                "circuits": ["valid", ""],
                "command": ["python3", "p.py"],
            })

    def test_reject_duplicate_id_fields(self):
        path = os.path.join(FIXTURES, "duplicate_fields.json")
        with open(path, "w") as f:
            f.write(
                '{"schema":"swiyu.provider-manifest.v1","id":"attacker","id":"legit",'
                '"title":"t","kind":"test-only","profiles":["p"],"command":["true"]}'
            )
        with self.assertRaises(ManifestError):
            load_manifest(path)


if __name__ == "__main__":
    unittest.main()

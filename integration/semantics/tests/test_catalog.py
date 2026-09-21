"""Catalog loader and digest pin tests."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from semantics.catalog import load_catalog
from semantics.claim_types import ClaimError
from semantics.canonical import canonical_digest

SEMANTICS_ROOT = Path(__file__).resolve().parents[1]


class TestCatalog(unittest.TestCase):
    def test_load_default_catalog(self):
        catalog = load_catalog()
        self.assertEqual(
            set(catalog.packages.keys()),
            {
                "platform.sd-jwt-es256@1",
                "platform.presentation@1",
                "platform.epfl-d10@1",
                "core.predicates@1",
            },
        )
        for entry in catalog.packages.values():
            self.assertTrue(entry.path.is_file())
            self.assertEqual(len(entry.digest), 64)

    def test_reject_changed_package_content(self):
        catalog = load_catalog()
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "catalog.lock.json"
            lock = json.loads(
                (SEMANTICS_ROOT / "catalog.lock.json").read_text(encoding="utf-8")
            )
            tampered = copy.deepcopy(lock)
            tampered["packages"]["core.predicates@1"]["digest"] = "0" * 64
            lock_path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaises(ClaimError):
                load_catalog(lock_path)

    def test_digest_changes_when_evaluator_meaning_changes(self):
        catalog = load_catalog()
        original = catalog.package("core.predicates@1").document
        changed = copy.deepcopy(original)
        changed["predicates"]["date.on-or-before@1"]["description"] = "changed"
        self.assertNotEqual(
            canonical_digest(original),
            canonical_digest(changed),
        )

    def test_source_pins_present(self):
        catalog = load_catalog()
        self.assertIn("claims", catalog.sources)
        self.assertEqual(len(catalog.sources["claims"]), 64)


if __name__ == "__main__":
    unittest.main()

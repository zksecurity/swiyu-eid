"""Tests for predicate loader and registry."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from semantics.canonical import canonical_digest
from semantics.loader import (
    PINNED_DIGESTS,
    PREDICATE_DIR,
    load_builtin_registry,
    load_predicate_file,
)


class TestCanonicalDigest(unittest.TestCase):
    def test_builtin_descriptor_digest_stable(self):
        path = PREDICATE_DIR / "age-at-least.v1.json"
        digest1 = canonical_digest(json.loads(path.read_text(encoding="utf-8")))
        digest2 = canonical_digest(json.loads(path.read_text(encoding="utf-8")))
        self.assertEqual(digest1, digest2)
        self.assertEqual(len(digest1), 64)

    def test_key_order_irrelevant(self):
        a = {"b": 1, "a": 2}
        b = {"a": 2, "b": 1}
        self.assertEqual(canonical_digest(a), canonical_digest(b))


class TestLoader(unittest.TestCase):
    def test_load_builtin(self):
        registry = load_builtin_registry()
        self.assertIn("age-at-least.v1", registry)
        entry = registry["age-at-least.v1"]
        self.assertEqual(entry.descriptor["id"], "age-at-least.v1")
        self.assertEqual(entry.descriptor["schema"], "swiyu.semantic-predicate.v1")

    def test_unknown_schema_rejected(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"schema": "unknown", "id": "x.v1"}, f)
            path = Path(f.name)
        with self.assertRaises(ValueError):
            load_predicate_file(path)
        path.unlink()

    def test_id_mismatch_rejected(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(
                {
                    "schema": "swiyu.semantic-predicate.v1",
                    "id": "wrong-id.v1",
                    "private_inputs": {},
                    "parameters": {},
                    "rule": "x",
                },
                f,
            )
            path = Path(f.name)
        with self.assertRaises(ValueError):
            load_predicate_file(path, expected_id="age-at-least.v1")
        path.unlink()

    def test_duplicate_keys_rejected(self):
        raw = '{"schema":"swiyu.semantic-predicate.v1","id":"age-at-least.v1","id":"dup"}'
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write(raw)
            path = Path(f.name)
        with self.assertRaises(ValueError):
            load_predicate_file(path)
        path.unlink()

    def test_mutated_descriptor_changes_digest(self):
        registry = load_builtin_registry()
        original = registry["age-at-least.v1"].digest
        mutated = dict(registry["age-at-least.v1"].descriptor)
        mutated["rule"] = mutated["rule"] + " mutated"
        self.assertNotEqual(canonical_digest(mutated), original)

    def test_builtin_digest_matches_pin(self):
        registry = load_builtin_registry()
        entry = registry["age-at-least.v1"]
        self.assertEqual(
            entry.digest,
            PINNED_DIGESTS["age-at-least.v1"],
        )

    def _write_descriptor(self, descriptor: dict) -> Path:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(descriptor, f)
            return Path(f.name)

    def test_mutated_rule_rejected_under_same_id(self):
        registry = load_builtin_registry()
        mutated = copy.deepcopy(registry["age-at-least.v1"].descriptor)
        mutated["rule"] = mutated["rule"] + " mutated"
        path = self._write_descriptor(mutated)
        with self.assertRaises(ValueError):
            load_predicate_file(path, expected_id="age-at-least.v1")
        path.unlink()

    def test_mutated_private_inputs_rejected_under_same_id(self):
        registry = load_builtin_registry()
        mutated = copy.deepcopy(registry["age-at-least.v1"].descriptor)
        mutated["private_inputs"]["birthdate"]["range"] = "1900-01-01..2100-12-31"
        path = self._write_descriptor(mutated)
        with self.assertRaises(ValueError):
            load_predicate_file(path, expected_id="age-at-least.v1")
        path.unlink()

    def test_mutated_parameters_rejected_under_same_id(self):
        registry = load_builtin_registry()
        mutated = copy.deepcopy(registry["age-at-least.v1"].descriptor)
        mutated["parameters"]["min_age"]["range"] = "0..200"
        path = self._write_descriptor(mutated)
        with self.assertRaises(ValueError):
            load_predicate_file(path, expected_id="age-at-least.v1")
        path.unlink()


if __name__ == "__main__":
    unittest.main()

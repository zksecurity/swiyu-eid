"""Adversarial boundary tests."""

import json
import math
import tempfile
import unittest
from pathlib import Path

from semantics.age import evaluate_age_at_least
from semantics.canonical import canonical_digest, parse_json_strict
from semantics.evaluate import evaluate
from semantics.loader import load_predicate_file


class TestAdversarialOracle(unittest.TestCase):
    def test_unicode_lookalike_date_rejected(self):
        result = evaluate_age_at_least("1990-01-0１", "2020-01-01", 18)
        self.assertEqual(result, {"status": "invalid_input"})

    def test_feb30_rejected(self):
        result = evaluate_age_at_least("1990-02-30", "2020-01-01", 18)
        self.assertEqual(result, {"status": "invalid_input"})

    def test_negative_min_age_rejected(self):
        result = evaluate_age_at_least("1990-01-01", "2020-01-01", -1)
        self.assertEqual(result, {"status": "invalid_input"})

    def test_year_10000_rejected(self):
        result = evaluate_age_at_least("10000-01-01", "2020-01-01", 18)
        self.assertEqual(result, {"status": "invalid_input"})


class TestAdversarialCanonical(unittest.TestCase):
    def test_nonfinite_rejected(self):
        with self.assertRaises(ValueError):
            canonical_digest({"x": math.inf})

    def test_duplicate_keys_in_file_rejected(self):
        raw = '{"schema":"swiyu.semantic-predicate.v1","a":1,"a":2}'
        with self.assertRaises(ValueError):
            parse_json_strict(raw)


class TestAdversarialLoader(unittest.TestCase):
    def test_inconsistent_filename_id_rejected(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(
                {
                    "schema": "swiyu.semantic-predicate.v1",
                    "id": "age-at-least.v1",
                    "private_inputs": {"birthdate": {}},
                    "parameters": {"reference_date": {}, "min_age": {}},
                    "rule": "test",
                },
                f,
            )
            path = Path(f.name)
        with self.assertRaises(ValueError):
            load_predicate_file(path, expected_id="other.v1")
        path.unlink()


class TestAdversarialEvaluate(unittest.TestCase):
    def test_non_string_birthdate(self):
        result = evaluate(
            "age-at-least.v1",
            {"birthdate": 19900101},
            {"reference_date": "2020-01-01", "min_age": 18},
        )
        self.assertEqual(result, {"status": "invalid_input"})


if __name__ == "__main__":
    unittest.main()

"""Tests for public evaluate() helper."""

import unittest

from semantics.evaluate import evaluate


class TestEvaluate(unittest.TestCase):
    def test_known_predicate_ok(self):
        result = evaluate(
            "age-at-least.v1",
            {"birthdate": "1990-06-15"},
            {"reference_date": "2020-06-15", "min_age": 18},
        )
        self.assertEqual(result, {"status": "ok", "value": True})

    def test_unknown_predicate(self):
        result = evaluate(
            "unknown.v1",
            {"birthdate": "1990-01-01"},
            {"reference_date": "2020-01-01", "min_age": 18},
        )
        self.assertEqual(result, {"status": "unsupported"})

    def test_missing_private_key(self):
        result = evaluate(
            "age-at-least.v1",
            {},
            {"reference_date": "2020-01-01", "min_age": 18},
        )
        self.assertEqual(result, {"status": "invalid_input"})

    def test_extra_private_key(self):
        result = evaluate(
            "age-at-least.v1",
            {"birthdate": "1990-01-01", "extra": "x"},
            {"reference_date": "2020-01-01", "min_age": 18},
        )
        self.assertEqual(result, {"status": "invalid_input"})

    def test_missing_parameter(self):
        result = evaluate(
            "age-at-least.v1",
            {"birthdate": "1990-01-01"},
            {"reference_date": "2020-01-01"},
        )
        self.assertEqual(result, {"status": "invalid_input"})

    def test_extra_parameter(self):
        result = evaluate(
            "age-at-least.v1",
            {"birthdate": "1990-01-01"},
            {"reference_date": "2020-01-01", "min_age": 18, "extra": 1},
        )
        self.assertEqual(result, {"status": "invalid_input"})

    def test_unknown_version_string(self):
        result = evaluate(
            "age-at-least.v2",
            {"birthdate": "1990-01-01"},
            {"reference_date": "2020-01-01", "min_age": 18},
        )
        self.assertEqual(result, {"status": "unsupported"})


if __name__ == "__main__":
    unittest.main()

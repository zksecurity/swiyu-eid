"""Core predicate evaluation tests."""

import unittest

from semantics.claim_types import ClaimError
from semantics.predicates import evaluate_predicate


class TestPredicates(unittest.TestCase):
    def test_date_on_or_before(self):
        self.assertTrue(
            evaluate_predicate(
                "date.on-or-before@1",
                {"value": "2000-01-01", "limit": "2008-01-01"},
                {"value": "swiyu.date@0", "limit": "swiyu.date@0"},
            )
        )
        self.assertFalse(
            evaluate_predicate(
                "date.on-or-before@1",
                {"value": "2010-01-01", "limit": "2008-01-01"},
                {"value": "swiyu.date@0", "limit": "swiyu.date@0"},
            )
        )

    def test_value_in_set(self):
        self.assertTrue(
            evaluate_predicate(
                "value.in-set@1",
                {"value": "CH", "set": ["CH", "DE"]},
                {"value": "ascii-code2@1", "set": "set<ascii-code2@1>"},
            )
        )
        self.assertFalse(
            evaluate_predicate(
                "value.in-set@1",
                {"value": "FR", "set": ["CH", "DE"]},
                {"value": "ascii-code2@1", "set": "set<ascii-code2@1>"},
            )
        )

    def test_value_equals(self):
        self.assertTrue(
            evaluate_predicate(
                "value.equals@1",
                {"left": "CH", "right": "CH"},
                {"left": "ascii-code2@1", "right": "ascii-code2@1"},
            )
        )
        self.assertFalse(
            evaluate_predicate(
                "value.equals@1",
                {"left": "CH", "right": "DE"},
                {"left": "ascii-code2@1", "right": "ascii-code2@1"},
            )
        )

    def test_operand_type_mismatch_rejected(self):
        with self.assertRaises(ClaimError):
            evaluate_predicate(
                "value.equals@1",
                {"left": "CH", "right": "CH"},
                {"left": "ascii-code2@1", "right": "swiyu.date@0"},
            )

    def test_invalid_date_rejected(self):
        with self.assertRaises(ClaimError):
            evaluate_predicate(
                "date.on-or-before@1",
                {"value": "1899-01-01", "limit": "2008-01-01"},
                {"value": "swiyu.date@0", "limit": "swiyu.date@0"},
            )


if __name__ == "__main__":
    unittest.main()

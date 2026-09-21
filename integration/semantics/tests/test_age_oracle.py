"""Tests for age-at-least.v1 oracle behavior."""

import unittest

from semantics.age import compute_age, evaluate_age_at_least


class TestComputeAge(unittest.TestCase):
    def test_same_day_birthday(self):
        self.assertEqual(compute_age("1990-06-15", "2020-06-15"), 30)

    def test_day_before_birthday(self):
        self.assertEqual(compute_age("1990-06-15", "2020-06-14"), 29)

    def test_day_after_birthday(self):
        self.assertEqual(compute_age("1990-06-15", "2020-06-16"), 30)

    def test_leap_birthday_on_leap_day(self):
        self.assertEqual(compute_age("2000-02-29", "2024-02-29"), 24)

    def test_leap_birthday_nonleap_before_march1(self):
        self.assertEqual(compute_age("2000-02-29", "2025-02-28"), 24)

    def test_leap_birthday_nonleap_on_march1(self):
        self.assertEqual(compute_age("2000-02-29", "2025-03-01"), 25)

    def test_year_boundary(self):
        self.assertEqual(compute_age("1999-12-31", "2000-01-01"), 0)

    def test_year_0001(self):
        self.assertEqual(compute_age("0001-01-01", "0002-01-01"), 1)


class TestEvaluateAgeAtLeast(unittest.TestCase):
    def test_meets_threshold(self):
        result = evaluate_age_at_least("1990-01-01", "2020-01-01", 18)
        self.assertEqual(result, {"status": "ok", "value": True})

    def test_below_threshold(self):
        result = evaluate_age_at_least("2010-01-01", "2020-01-01", 18)
        self.assertEqual(result, {"status": "ok", "value": False})

    def test_future_birthdate_min_age_zero(self):
        result = evaluate_age_at_least("2030-01-01", "2020-01-01", 0)
        self.assertEqual(result, {"status": "ok", "value": False})

    def test_invalid_birthdate(self):
        result = evaluate_age_at_least("1990-13-01", "2020-01-01", 18)
        self.assertEqual(result, {"status": "invalid_input"})

    def test_invalid_reference_date(self):
        result = evaluate_age_at_least("1990-01-01", "2020-02-30", 18)
        self.assertEqual(result, {"status": "invalid_input"})

    def test_bool_min_age_rejected(self):
        result = evaluate_age_at_least("1990-01-01", "2020-01-01", True)
        self.assertEqual(result, {"status": "invalid_input"})

    def test_min_age_out_of_range(self):
        result = evaluate_age_at_least("1990-01-01", "2020-01-01", 151)
        self.assertEqual(result, {"status": "invalid_input"})

    def test_malformed_date_string(self):
        result = evaluate_age_at_least("90-01-01", "2020-01-01", 18)
        self.assertEqual(result, {"status": "invalid_input"})

    def test_no_private_echo_on_invalid(self):
        bad = "1990-13-40"
        result = evaluate_age_at_least(bad, "2020-01-01", 18)
        self.assertNotIn(bad, str(result))


class TestIndependentVectors(unittest.TestCase):
    """Independently calculated vectors with fixed seed pairs."""

    SEED_PAIRS = [
        ("1985-03-10", "2025-03-09", 40, False),
        ("1985-03-10", "2025-03-09", 39, True),
        ("1985-03-10", "2025-03-10", 40, True),
        ("1985-03-10", "2025-03-11", 40, True),
        ("2004-02-29", "2024-02-28", 20, False),
        ("2004-02-29", "2024-02-29", 20, True),
        ("2004-02-29", "2025-02-28", 21, False),
        ("2004-02-29", "2025-03-01", 21, True),
        ("9999-12-31", "9999-12-30", 0, False),
        ("0001-01-01", "9999-12-31", 0, True),
    ]

    def test_independent_age_vectors(self):
        for birth, ref, min_age, expected in self.SEED_PAIRS:
            result = evaluate_age_at_least(birth, ref, min_age)
            self.assertEqual(
                result,
                {"status": "ok", "value": expected},
                msg=f"birth={birth} ref={ref} min_age={min_age}",
            )


if __name__ == "__main__":
    unittest.main()

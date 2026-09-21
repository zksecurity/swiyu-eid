"""Gregorian age-at-least.v1 reference oracle."""

from __future__ import annotations

import calendar
import re
from typing import Any

_DATE_RE = re.compile(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})$")
_MIN_AGE = 0
_MAX_AGE = 150


def _parse_strict_date(value: Any) -> tuple[int, int, int] | None:
    if not isinstance(value, str):
        return None
    match = _DATE_RE.fullmatch(value)
    if not match:
        return None
    year, month, day = (int(match.group(i)) for i in range(1, 4))
    if year < 1 or year > 9999:
        return None
    if month < 1 or month > 12:
        return None
    max_day = calendar.monthrange(year, month)[1]
    if day < 1 or day > max_day:
        return None
    return year, month, day


def _is_leap(year: int) -> bool:
    return calendar.isleap(year)


def _effective_birthday(birth: tuple[int, int, int], ref_year: int) -> tuple[int, int]:
    month, day = birth[1], birth[2]
    if month == 2 and day == 29 and not _is_leap(ref_year):
        return 3, 1
    return month, day


def compute_age(birthdate: str, reference_date: str) -> int:
    """Return completed Gregorian age; assumes valid date strings."""
    by, bm, bd = _parse_strict_date(birthdate)  # type: ignore[misc]
    ry, rm, rd = _parse_strict_date(reference_date)  # type: ignore[misc]
    eff_m, eff_d = _effective_birthday((by, bm, bd), ry)
    age = ry - by
    if (rm, rd) < (eff_m, eff_d):
        age -= 1
    return age


def _parse_min_age(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < _MIN_AGE or value > _MAX_AGE:
        return None
    return value


def evaluate_age_at_least(
    birthdate: Any, reference_date: Any, min_age: Any
) -> dict[str, Any]:
    birth = _parse_strict_date(birthdate)
    ref = _parse_strict_date(reference_date)
    age_min = _parse_min_age(min_age)
    if birth is None or ref is None or age_min is None:
        return {"status": "invalid_input"}

    if (birth[0], birth[1], birth[2]) > (ref[0], ref[1], ref[2]):
        return {"status": "ok", "value": False}

    age = compute_age(birthdate, reference_date)
    return {"status": "ok", "value": age >= age_min}

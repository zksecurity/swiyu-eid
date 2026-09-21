"""Reference evaluation for core claim predicates."""

from __future__ import annotations

from typing import Any

from semantics.claim_types import ClaimError, validate_scalar


def _compare_dates(left: str, right: str) -> int:
    """Return -1/0/1 comparing YYYY-MM-DD strings."""
    if left == right:
        return 0
    return -1 if left < right else 1


def evaluate_predicate(
    predicate_id: str,
    args: dict[str, Any],
    operand_types: dict[str, str],
) -> bool:
    if predicate_id == "value.equals@1":
        left_type = operand_types.get("left")
        right_type = operand_types.get("right")
        if left_type is None or right_type is None or left_type != right_type:
            raise ClaimError("operand type mismatch")
        left = validate_scalar(left_type, args["left"])
        right = validate_scalar(right_type, args["right"])
        return left == right

    if predicate_id == "value.in-set@1":
        value_type = operand_types.get("value")
        set_type = operand_types.get("set")
        if value_type is None or set_type is None:
            raise ClaimError("operand type mismatch")
        base, element, _ = _parse_set_type(set_type)
        if base != "set":
            raise ClaimError("operand type mismatch")
        value = validate_scalar(value_type, args["value"])
        members = args["set"]
        if not isinstance(members, list):
            raise ClaimError("invalid set operand")
        validated = [validate_scalar(element, item) for item in members]
        return value in validated

    if predicate_id == "date.on-or-before@1":
        value = validate_scalar("swiyu.date@0", args["value"])
        limit = validate_scalar("swiyu.date@0", args["limit"])
        return _compare_dates(value, limit) <= 0

    if predicate_id == "date.yyyymmdd-age-at-least@1":
        birthdate = validate_scalar("swiyu.date@0", args["birthdate"])
        reference = validate_scalar("swiyu.date-yyyymmdd@0", args["reference"])
        min_years = validate_scalar("swiyu.unix-seconds@0", args["min_years"])
        birth = _date_to_yyyymmdd(birthdate)
        return reference >= birth + int(min_years) * 10_000

    raise ClaimError("unknown predicate")


def _date_to_yyyymmdd(date_str: str) -> int:
    year, month, day = date_str.split("-")
    return int(year) * 10_000 + int(month) * 100 + int(day)


def _parse_set_type(type_name: str) -> tuple[str, str | None, int | None]:
    if type_name.startswith("set<") and type_name.endswith(">"):
        return ("set", type_name[4:-1], None)
    return (type_name, None, None)

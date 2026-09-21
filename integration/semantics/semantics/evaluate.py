"""Public evaluate() helper."""

from __future__ import annotations

from typing import Any

from semantics.age import evaluate_age_at_least
from semantics.loader import load_builtin_registry

_REGISTRY = None

AGE_PRIVATE_KEYS = frozenset({"birthdate"})
AGE_PARAMETER_KEYS = frozenset({"reference_date", "min_age"})


def _registry() -> dict:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = load_builtin_registry()
    return _REGISTRY


def _exact_keys(payload: dict[str, Any], expected: frozenset[str]) -> bool:
    return isinstance(payload, dict) and set(payload.keys()) == set(expected)


def evaluate(
    predicate_id: str,
    private_inputs: dict[str, Any],
    parameters: dict[str, Any],
) -> dict[str, Any]:
    if predicate_id not in _registry():
        return {"status": "unsupported"}

    if predicate_id == "age-at-least.v1":
        if not _exact_keys(private_inputs, AGE_PRIVATE_KEYS):
            return {"status": "invalid_input"}
        if not _exact_keys(parameters, AGE_PARAMETER_KEYS):
            return {"status": "invalid_input"}
        return evaluate_age_at_least(
            private_inputs["birthdate"],
            parameters["reference_date"],
            parameters["min_age"],
        )

    return {"status": "unsupported"}

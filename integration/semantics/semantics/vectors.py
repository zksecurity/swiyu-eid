"""Public synthetic test vectors for supported predicates."""

from __future__ import annotations

from typing import Any

from semantics.evaluate import evaluate

PUBLIC_VECTORS: list[dict[str, Any]] = [
    {
        "id": "adult-on-birthday",
        "predicate": "age-at-least.v1",
        "private_inputs": {"birthdate": "2000-01-01"},
        "parameters": {"reference_date": "2018-01-01", "min_age": 18},
        "expected": {"status": "ok", "value": True},
    },
    {
        "id": "minor-day-before",
        "predicate": "age-at-least.v1",
        "private_inputs": {"birthdate": "2010-06-15"},
        "parameters": {"reference_date": "2020-06-14", "min_age": 18},
        "expected": {"status": "ok", "value": False},
    },
    {
        "id": "leap-nonleap-march1",
        "predicate": "age-at-least.v1",
        "private_inputs": {"birthdate": "2000-02-29"},
        "parameters": {"reference_date": "2025-03-01", "min_age": 25},
        "expected": {"status": "ok", "value": True},
    },
    {
        "id": "future-birthdate",
        "predicate": "age-at-least.v1",
        "private_inputs": {"birthdate": "2030-01-01"},
        "parameters": {"reference_date": "2020-01-01", "min_age": 0},
        "expected": {"status": "ok", "value": False},
    },
    {
        "id": "invalid-month",
        "predicate": "age-at-least.v1",
        "private_inputs": {"birthdate": "1990-13-01"},
        "parameters": {"reference_date": "2020-01-01", "min_age": 18},
        "expected": {"status": "invalid_input"},
    },
    {
        "id": "bool-min-age",
        "predicate": "age-at-least.v1",
        "private_inputs": {"birthdate": "1990-01-01"},
        "parameters": {"reference_date": "2020-01-01", "min_age": True},
        "expected": {"status": "invalid_input"},
    },
    {
        "id": "unknown-predicate",
        "predicate": "age-at-least.v2",
        "private_inputs": {"birthdate": "1990-01-01"},
        "parameters": {"reference_date": "2020-01-01", "min_age": 18},
        "expected": {"status": "unsupported"},
    },
]


def build_vectors_document() -> dict[str, Any]:
    verified = []
    for item in PUBLIC_VECTORS:
        result = evaluate(
            item["predicate"],
            item["private_inputs"],
            item["parameters"],
        )
        verified.append(
            {
                "id": item["id"],
                "predicate": item["predicate"],
                "private_inputs": item["private_inputs"],
                "parameters": item["parameters"],
                "expected": item["expected"],
                "oracle_result": result,
            }
        )
    return {
        "schema": "swiyu.semantic-vectors.v1",
        "note": (
            "Synthetic public corpus; all birthdates are invented fixture data. "
            "private_inputs names a predicate schema role, not a secrecy requirement "
            "for these public vectors."
        ),
        "vectors": verified,
    }

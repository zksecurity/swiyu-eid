"""Load and validate built-in semantic predicate descriptors."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from semantics.canonical import canonical_digest, parse_json_strict

PREDICATE_DIR = Path(__file__).resolve().parents[1] / "predicates"
SUPPORTED_SCHEMA = "swiyu.semantic-predicate.v1"
SUPPORTED_IDS = frozenset({"age-at-least.v1"})

# Pinned canonical digests for published predicate versions.
# A changed definition under the same ID is rejected; new semantics need a new ID and pin.
PINNED_DIGESTS: dict[str, str] = {
    "age-at-least.v1": (
        "4cf5db011bb6a6524b90c0e69b80e93d42a869689f5c5b5293d51687c0242241"
    ),
}


@dataclass(frozen=True)
class PredicateEntry:
    predicate_id: str
    descriptor: dict[str, Any]
    digest: str
    path: Path


def _validate_descriptor(descriptor: dict[str, Any], expected_id: str | None = None) -> str:
    schema = descriptor.get("schema")
    if schema != SUPPORTED_SCHEMA:
        raise ValueError("unknown schema")
    predicate_id = descriptor.get("id")
    if not isinstance(predicate_id, str) or predicate_id not in SUPPORTED_IDS:
        raise ValueError("unknown predicate id")
    if expected_id is not None and predicate_id != expected_id:
        raise ValueError("descriptor id mismatch")
    required = ("private_inputs", "parameters", "rule")
    for key in required:
        if key not in descriptor:
            raise ValueError(f"missing descriptor field: {key}")
    return predicate_id


def load_predicate_file(path: Path, expected_id: str | None = None) -> PredicateEntry:
    text = path.read_text(encoding="utf-8")
    descriptor = parse_json_strict(text)
    if not isinstance(descriptor, dict):
        raise ValueError("descriptor must be a JSON object")
    predicate_id = _validate_descriptor(descriptor, expected_id)
    digest = canonical_digest(descriptor)
    pinned = PINNED_DIGESTS.get(predicate_id)
    if pinned is not None and digest != pinned:
        raise ValueError("descriptor digest mismatch")
    return PredicateEntry(
        predicate_id=predicate_id,
        descriptor=descriptor,
        digest=digest,
        path=path,
    )


def load_builtin_registry() -> dict[str, PredicateEntry]:
    registry: dict[str, PredicateEntry] = {}
    for predicate_id in sorted(SUPPORTED_IDS):
        path = PREDICATE_DIR / f"{predicate_id}.json"
        if not path.is_file():
            raise FileNotFoundError(path)
        entry = load_predicate_file(path, expected_id=predicate_id)
        if entry.predicate_id in registry:
            raise ValueError("duplicate predicate id")
        registry[entry.predicate_id] = entry
    return registry

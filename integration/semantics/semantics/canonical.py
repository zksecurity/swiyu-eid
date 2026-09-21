"""Deterministic JSON canonicalization and SHA-256 digest."""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any


def _reject_nonfinite(value: Any) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("nonfinite number")


def _canonicalize(value: Any) -> Any:
    _reject_nonfinite(value)
    if isinstance(value, dict):
        if not isinstance(value, dict):
            raise ValueError("invalid object")
        return {k: _canonicalize(value[k]) for k in sorted(value)}
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        if value.is_integer():
            return int(value)
        return value
    if isinstance(value, str):
        return value
    raise ValueError(f"unsupported JSON type: {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize value to deterministic UTF-8 JSON bytes."""
    canonical = _canonicalize(value)
    return json.dumps(
        canonical,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_digest(value: Any) -> str:
    """Return lowercase hex SHA-256 over canonical JSON bytes."""
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def parse_json_strict(text: str) -> Any:
    """Parse JSON rejecting duplicate object keys and non-string keys."""

    def check_duplicates(pairs):
        seen: set[str] = set()
        obj: dict[str, Any] = {}
        for key, val in pairs:
            if not isinstance(key, str):
                raise ValueError("non-string JSON object key")
            if key in seen:
                raise ValueError("duplicate JSON object key")
            seen.add(key)
            obj[key] = val
        return obj

    return json.loads(text, object_pairs_hook=check_duplicates)

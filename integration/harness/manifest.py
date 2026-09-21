"""Provider manifest loading and validation (T06/T17 subset)."""
import json
import os
from typing import Any

SCHEMA = "swiyu.provider-manifest.v1"
VALID_KINDS = frozenset({"test-only", "implementation"})


class ManifestError(Exception):
    """Invalid or unreadable provider manifest."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    seen: set[str] = set()
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise ManifestError(f"duplicate key: {key}")
        seen.add(key)
        obj[key] = value
    return obj


def validate_manifest(data: dict[str, Any]) -> None:
    if data.get("schema") != SCHEMA:
        raise ManifestError(f"unsupported schema: {data.get('schema')}")
    for field, typ in (
        ("id", str),
        ("title", str),
        ("kind", str),
        ("profiles", list),
        ("command", list),
    ):
        if field not in data:
            raise ManifestError(f"missing field: {field}")
        if not isinstance(data[field], typ):
            raise ManifestError(f"{field} must be {typ.__name__}")
    if not data["id"].strip():
        raise ManifestError("id must be non-empty")
    if not data["title"].strip():
        raise ManifestError("title must be non-empty")
    if data["kind"] not in VALID_KINDS:
        raise ManifestError(f"invalid kind: {data['kind']}")
    if not data["profiles"]:
        raise ManifestError("profiles must be non-empty")
    if not all(isinstance(p, str) and p for p in data["profiles"]):
        raise ManifestError("profiles must be non-empty strings")
    if not data["command"]:
        raise ManifestError("command must be non-empty argv list")
    if not all(isinstance(c, str) for c in data["command"]):
        raise ManifestError("command entries must be strings")
    circuits = data.get("circuits")
    if circuits is not None:
        if not isinstance(circuits, list):
            raise ManifestError("circuits must be a list when present")
        if not all(isinstance(circuit, str) and circuit for circuit in circuits):
            raise ManifestError("circuits must contain non-empty strings")
    src = data.get("source")
    if src is not None and not isinstance(src, dict):
        raise ManifestError("source must be an object when present")
    if isinstance(src, dict):
        for key in ("circuit", "circuit_id", "native_circuit"):
            value = src.get(key)
            if value is not None and (not isinstance(value, str) or not value):
                raise ManifestError(f"source.{key} must be a non-empty string when present")


def load_manifest(path: str) -> dict[str, Any]:
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise ManifestError(f"manifest not found: {path}")
    with open(path, encoding="utf-8") as f:
        try:
            data = json.load(f, object_pairs_hook=_reject_duplicate_keys)
        except json.JSONDecodeError as exc:
            raise ManifestError(f"invalid JSON: {exc}") from exc
        except ManifestError:
            raise
        except ValueError as exc:
            raise ManifestError(str(exc)) from exc
    if not isinstance(data, dict):
        raise ManifestError("manifest must be a JSON object")
    validate_manifest(data)
    data["_manifest_dir"] = os.path.dirname(path)
    data["_manifest_path"] = path
    return data

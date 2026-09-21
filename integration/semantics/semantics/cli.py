"""CLI: check, evaluate, vectors."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from semantics.canonical import canonical_digest, parse_json_strict
from semantics.evaluate import evaluate
from semantics.loader import load_builtin_registry
from semantics.vectors import build_vectors_document

PAYLOAD_ROOT_KEYS = frozenset({"predicate", "private_inputs", "parameters"})


def _load_payload(path: str | None) -> dict[str, Any]:
    try:
        if path:
            text = Path(path).read_text(encoding="utf-8")
        else:
            text = sys.stdin.read()
    except OSError:
        raise ValueError("payload unavailable")
    payload = parse_json_strict(text)
    if not isinstance(payload, dict):
        raise ValueError("payload must be a JSON object")
    if set(payload.keys()) != PAYLOAD_ROOT_KEYS:
        raise ValueError("invalid payload root keys")
    canonical_digest(payload)
    return payload


def cmd_check() -> int:
    registry = load_builtin_registry()
    for entry in registry.values():
        if entry.descriptor["id"] != entry.predicate_id:
            print("descriptor id mismatch", file=sys.stderr)
            return 1
    print(json.dumps({"status": "ok", "predicates": sorted(registry.keys())}))
    return 0


def cmd_evaluate(path: str | None) -> int:
    try:
        payload = _load_payload(path)
        result = evaluate(
            payload["predicate"],
            payload["private_inputs"],
            payload["parameters"],
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        print(json.dumps({"status": "invalid_input"}))
        return 1
    print(json.dumps(result))
    return 0 if result.get("status") in {"ok", "unsupported"} else 1


def cmd_vectors() -> int:
    print(json.dumps(build_vectors_document(), indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="semantics")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check", help="validate built-in predicate descriptors")

    evaluate_parser = sub.add_parser("evaluate", help="evaluate a predicate payload")
    evaluate_parser.add_argument(
        "--input",
        help="JSON payload file; omit to read stdin",
    )

    sub.add_parser("vectors", help="emit public synthetic test corpus")

    args = parser.parse_args(argv)
    if args.command == "check":
        return cmd_check()
    if args.command == "evaluate":
        return cmd_evaluate(args.input)
    if args.command == "vectors":
        return cmd_vectors()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Public claim campaign CLI: check, explain, evaluate, plan."""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any


def _require_crypto() -> None:
    try:
        import cryptography  # noqa: F401
    except ImportError:
        print(
            json.dumps(
                {
                    "status": "error",
                    "message": "pyca cryptography required; install cryptography>=50.0.1",
                }
            ),
            file=sys.stderr,
        )
        raise SystemExit(2)


def _reject_nonfinite(value: Any) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("nonfinite JSON number")
    if isinstance(value, dict):
        for item in value.values():
            _reject_nonfinite(item)
    elif isinstance(value, list):
        for item in value:
            _reject_nonfinite(item)


def _load_json(path: str) -> dict[str, Any]:
    from semantics.canonical import parse_json_strict

    parsed = parse_json_strict(Path(path).read_text(encoding="utf-8"))
    _reject_nonfinite(parsed)
    if not isinstance(parsed, dict):
        raise ValueError("JSON input must be an object")
    return parsed


def cmd_check(claim_path: str) -> int:
    _require_crypto()
    from semantics.claims import ClaimError, load_claim, validate_claim

    try:
        claim = load_claim(claim_path)
        validate_claim(claim.document)
    except ClaimError as exc:
        print(json.dumps({"status": "invalid", "message": str(exc)}))
        return 1
    print(
        json.dumps(
            {
                "status": "ok",
                "id": claim.document["id"],
                "statement_digest": claim.statement_digest,
            }
        )
    )
    return 0


def cmd_explain(claim_path: str) -> int:
    _require_crypto()
    from semantics.claims import load_claim

    claim = load_claim(claim_path)
    document = claim.document
    print(
        json.dumps(
            {
                "status": "ok",
                "id": document["id"],
                "statement_digest": claim.statement_digest,
                "attributes": sorted(document.get("attributes", {}).keys()),
                "given": sorted(document.get("given", {}).keys()),
                "require": [entry["id"] for entry in document.get("require", [])],
                "where": document.get("where"),
                "release": document.get("release"),
            },
            indent=2,
        )
    )
    return 0


def cmd_evaluate(claim_path: str, fixture_path: str, given_path: str) -> int:
    _require_crypto()
    from semantics.assertions import evaluate_claim
    from semantics.claims import load_claim

    claim = load_claim(claim_path)
    fixture = _load_json(fixture_path)
    given = _load_json(given_path)
    result = evaluate_claim(claim, fixture, given)
    public = {
        "status": result.get("status"),
        "value": result.get("value"),
        "condition": result.get("condition"),
        "assertions": {
            key: {"status": val.get("status"), "value": val.get("value")}
            for key, val in result.get("assertions", {}).items()
        },
    }
    print(json.dumps(public, indent=2))
    return 0 if result.get("status") == "ok" else 1


def cmd_plan(claim_path: str, *, seed: int, max_cases: int) -> int:
    _require_crypto()
    from semantics.claims import load_claim
    from semantics.planner import plan_campaign_cases

    claim = load_claim(claim_path)
    cases = plan_campaign_cases(claim, seed=seed, max_cases=max_cases)
    public = [
        {
            "id": case.id,
            "recipe": case.recipe,
            "expectation_basis": case.expectation_basis,
            "expected_verdict": case.expected_verdict,
        }
        for case in cases
    ]
    print(json.dumps({"status": "ok", "cases": public}, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="semantics.claim_cli")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check")
    check.add_argument("--claim", required=True)

    explain = sub.add_parser("explain")
    explain.add_argument("--claim", required=True)

    evaluate = sub.add_parser("evaluate")
    evaluate.add_argument("--claim", required=True)
    evaluate.add_argument("--fixture", required=True)
    evaluate.add_argument("--given", required=True)

    plan = sub.add_parser("plan")
    plan.add_argument("--claim", required=True)
    plan.add_argument("--seed", type=int, default=1)
    plan.add_argument("--max-cases", type=int, default=64)

    try:
        args = parser.parse_args(argv)
        if args.command == "check":
            return cmd_check(args.claim)
        if args.command == "explain":
            return cmd_explain(args.claim)
        if args.command == "evaluate":
            return cmd_evaluate(args.claim, args.fixture, args.given)
        if args.command == "plan":
            return cmd_plan(args.claim, seed=args.seed, max_cases=args.max_cases)
        return 2
    except SystemExit as exc:
        raise exc
    except Exception as exc:
        print(json.dumps({"status": "error", "message": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

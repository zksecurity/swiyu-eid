#!/usr/bin/env python3
"""Laptop implementation of the mobile runtime boundary."""

import argparse
import json
import sys
from pathlib import Path
from typing import Any


_INTEGRATION_ROOT = Path(__file__).resolve().parents[1]
_HARNESS = str(_INTEGRATION_ROOT / "harness")
if _HARNESS not in sys.path:
    sys.path.insert(0, _HARNESS)

from manifest import ManifestError
from provider_client import ProviderClient, ProviderError


SCHEMA = "swiyu.mobile-runtime-facade.v1"


class MobileRuntimeError(Exception):
    """Stable facade error suitable for CLI and future emulator callers."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _required_object(request: dict, name: str) -> dict[str, Any]:
    value = request.get(name)
    if not isinstance(value, dict):
        raise MobileRuntimeError("invalid_request", f"{name} must be a JSON object")
    return value


def run_facade(request: dict) -> dict:
    """Execute one presentation lifecycle through a provider manifest."""
    if not isinstance(request, dict):
        raise MobileRuntimeError("invalid_request", "request must be a JSON object")
    if request.get("schema") != SCHEMA:
        raise MobileRuntimeError("invalid_request", f"schema must be {SCHEMA}")
    required_strings = ("provider_manifest", "profile")
    for name in required_strings:
        if not isinstance(request.get(name), str) or not request[name]:
            raise MobileRuntimeError("invalid_request", f"missing required field: {name}")
    credential = _required_object(request, "credential")
    request_context = _required_object(request, "request_context")
    inputs = _required_object(request, "inputs")
    if not isinstance(credential.get("format"), str) or not isinstance(credential.get("data"), str):
        raise MobileRuntimeError(
            "invalid_request", "credential requires string format and data fields"
        )
    for name in ("nonce", "audience"):
        if not isinstance(request_context.get(name), str) or not request_context[name]:
            raise MobileRuntimeError(
                "invalid_request", f"request_context requires non-empty {name}"
            )

    profile = request["profile"]
    verification_context = request.get("verification_context", request_context)
    if not isinstance(verification_context, dict):
        raise MobileRuntimeError("invalid_request", "verification_context must be a JSON object")

    try:
        with ProviderClient(request["provider_manifest"]) as provider:
            provider.call("initialize", {})
            prepared = provider.call("prepare", {
                "profile": profile,
                "credential": credential,
                "context": request_context,
            })
            presented = provider.call("present", {
                "profile": profile,
                "handle": prepared["handle"],
                "request_context": request_context,
                "inputs": inputs,
            })
            verifier = provider.call("verify", {
                "profile": profile,
                "presentation": presented["presentation"],
                "request_context": verification_context,
                "inputs": inputs,
            })
    except ManifestError as exc:
        raise MobileRuntimeError(
            "provider_unavailable", "provider manifest not found or invalid"
        ) from None
    except ProviderError as exc:
        unavailable = {"launch", "crashed", "io", "timeout", "state"}
        code = "provider_unavailable" if exc.code in unavailable else "provider_error"
        # Provider text may contain a credential, witness, or arbitrary input.
        # The facade is a public boundary, including its CLI error output.
        message = "provider unavailable" if code == "provider_unavailable" else "provider operation failed"
        raise MobileRuntimeError(code, message) from None
    return {
        "schema": "swiyu.mobile-runtime-result.v1",
        "presentation": presented["presentation"],
        "verifier": {
            "verified": verifier["verified"],
            "reason": None if verifier["verified"] else (
                "binding_or_predicate_failed"
                if verifier.get("reason") == "binding_or_predicate_failed"
                else "presentation_rejected"
            ),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the mobile-runtime facade through a local provider process."
    )
    parser.add_argument("request", help="JSON request/fixture path, or - for stdin")
    args = parser.parse_args(argv)
    try:
        if args.request == "-":
            document = json.load(sys.stdin)
            base_dir = Path.cwd()
        else:
            request_path = Path(args.request).resolve()
            with request_path.open(encoding="utf-8") as stream:
                document = json.load(stream)
            base_dir = request_path.parent
        request = document.get("request", document) if isinstance(document, dict) else document
        if isinstance(request, dict):
            manifest = request.get("provider_manifest")
            if isinstance(manifest, str) and not Path(manifest).is_absolute():
                request = dict(request)
                request["provider_manifest"] = str((base_dir / manifest).resolve())
        result = run_facade(request)
    except (OSError, json.JSONDecodeError, MobileRuntimeError) as exc:
        code = exc.code if isinstance(exc, MobileRuntimeError) else "invalid_request"
        print(json.dumps({"error": {"code": code, "message": str(exc)}}), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

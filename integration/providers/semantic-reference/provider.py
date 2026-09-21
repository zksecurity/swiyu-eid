#!/usr/bin/env python3
"""Transparent reference provider — test-only, discloses fixture material by design."""
from __future__ import annotations

import base64
import json
import math
import os
import sys
import uuid
from typing import Any

PROTOCOL = "swiyu.provider.v1"
PROFILE = "swiyu.semantic-reference.v0"
HANDLES: dict[str, dict[str, Any]] = {}


def _semantics_root() -> str:
    return os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "semantics")
    )


def _ensure_path() -> None:
    root = _semantics_root()
    if root not in sys.path:
        sys.path.insert(0, root)


def _reject_nonfinite(value: Any) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("nonfinite JSON number")
    if isinstance(value, dict):
        for item in value.values():
            _reject_nonfinite(item)
    elif isinstance(value, list):
        for item in value:
            _reject_nonfinite(item)


def _parse_json_strict(raw: str) -> Any:
    def check_duplicates(pairs: list[tuple[Any, Any]]) -> dict[str, Any]:
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

    def parse_constant(name: str) -> None:
        raise ValueError(f"nonfinite JSON: {name}")

    parsed = json.loads(raw, object_pairs_hook=check_duplicates, parse_constant=parse_constant)
    _reject_nonfinite(parsed)
    return parsed


def reply(req_id: str, status: str, result: dict | None = None, error: dict | None = None) -> None:
    msg: dict[str, Any] = {"protocol": PROTOCOL, "id": req_id, "status": status}
    if status == "ok":
        msg["result"] = result or {}
    else:
        msg["error"] = error or {"code": status, "message": status}
    sys.stdout.write(json.dumps(msg, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _inject_mode(payload: dict[str, Any]) -> str | None:
    mode = payload.get("inject_mode") or os.environ.get("SWIYU_PROVIDER_INJECT")
    if mode in {"accept-all", "inject-leak"}:
        return mode
    return None


def _fixture_from_envelope(envelope: dict[str, Any]) -> dict[str, Any] | None:
    if isinstance(envelope.get("fixture"), dict):
        nested = dict(envelope["fixture"])
        for key in ("credential", "holder_signature", "presentation_context", "status_witness"):
            if key in envelope and key not in nested:
                nested[key] = envelope[key]
        return nested
    fixture: dict[str, Any] = {}
    for key in ("credential", "holder_signature", "presentation_context", "status_witness"):
        if key in envelope:
            fixture[key] = envelope[key]
    return fixture or None


def handle_initialize(req_id: str, _payload: dict[str, Any]) -> None:
    reply(
        req_id,
        "ok",
        {
            "profiles": [PROFILE],
            "operations": ["initialize", "prepare", "present", "verify", "cleanup"],
        },
    )


def handle_prepare(req_id: str, payload: dict[str, Any]) -> None:
    if payload.get("profile") != PROFILE:
        reply(
            req_id,
            "unsupported",
            error={"code": "unsupported_profile", "message": str(payload.get("profile"))},
        )
        return
    fixture = payload.get("fixture")
    given = payload.get("given")
    statement_digest = payload.get("statement_digest")
    if not isinstance(fixture, dict) or not isinstance(given, dict):
        reply(req_id, "error", error={"code": "bad_input", "message": "fixture and given required"})
        return
    if not isinstance(statement_digest, str):
        reply(req_id, "error", error={"code": "bad_input", "message": "statement_digest required"})
        return
    handle = str(uuid.uuid4())
    HANDLES[handle] = {
        "statement_digest": statement_digest,
        "fixture": fixture,
        "given": given,
        "release": payload.get("release", {}),
        "inject_mode": _inject_mode(payload),
    }
    reply(req_id, "ok", {"handle": handle})


def handle_present(req_id: str, payload: dict[str, Any]) -> None:
    if payload.get("profile") != PROFILE:
        reply(
            req_id,
            "unsupported",
            error={"code": "unsupported_profile", "message": str(payload.get("profile"))},
        )
        return
    state = HANDLES.get(payload.get("handle", ""))
    if state is None:
        reply(req_id, "error", error={"code": "bad_handle", "message": "unknown handle"})
        return
    envelope = {
        "profile": PROFILE,
        "statement_digest": state["statement_digest"],
        "acceptance": None,
        "protocol_derived_digest": state["fixture"].get("presentation_context"),
        "fixture": state["fixture"],
        "given": state["given"],
        "credential": state["fixture"].get("credential"),
        "holder_signature": state["fixture"].get("holder_signature"),
        "presentation_context": state["fixture"].get("presentation_context"),
        "proof": "transparent-reference",
    }
    if state.get("inject_mode") == "inject-leak":
        envelope["branch_selector"] = "hidden-branch"
        envelope["_hidden_attribute"] = "leak-canary"
    encoded = base64.urlsafe_b64encode(
        json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    ).decode().rstrip("=")
    reply(req_id, "ok", {"presentation": encoded})


def handle_verify(req_id: str, payload: dict[str, Any]) -> None:
    if payload.get("profile") != PROFILE:
        reply(
            req_id,
            "unsupported",
            error={"code": "unsupported_profile", "message": str(payload.get("profile"))},
        )
        return
    try:
        raw = base64.urlsafe_b64decode(payload.get("presentation", "") + "==")
        envelope = _parse_json_strict(raw.decode("utf-8"))
        if not isinstance(envelope, dict):
            raise ValueError("envelope must be object")
    except Exception:
        reply(req_id, "error", error={"code": "bad_presentation", "message": "decode failed"})
        return

    inject_mode = _inject_mode(payload)
    if inject_mode == "accept-all":
        reply(req_id, "ok", {"verified": True, "reason": "injected_accept_all"})
        return

    expected_given = payload.get("given")
    if not isinstance(expected_given, dict):
        reply(req_id, "error", error={"code": "bad_input", "message": "expected given required"})
        return

    fixture = _fixture_from_envelope(envelope)
    if not isinstance(fixture, dict):
        reply(req_id, "ok", {"verified": False, "reason": "missing_fixture_material"})
        return

    _ensure_path()
    from semantics.assertions import evaluate_claim
    from semantics.claims import load_claim

    claim_path = payload.get("claim_path")
    if not isinstance(claim_path, str):
        reply(req_id, "error", error={"code": "bad_input", "message": "claim_path required"})
        return
    claim = load_claim(claim_path)
    if claim.statement_digest != envelope.get("statement_digest"):
        reply(req_id, "ok", {"verified": False, "reason": "statement_digest_mismatch"})
        return
    result = evaluate_claim(claim, fixture, expected_given)
    verified = result.get("status") == "ok" and result.get("value") is True
    reply(
        req_id,
        "ok",
        {
            "verified": verified,
            "reason": None if verified else "reference_evaluate_claim_false",
        },
    )


def handle_cleanup(req_id: str, _payload: dict[str, Any]) -> None:
    HANDLES.clear()
    reply(req_id, "ok", {})


def main() -> None:
    handlers = {
        "initialize": handle_initialize,
        "prepare": handle_prepare,
        "present": handle_present,
        "verify": handle_verify,
        "cleanup": handle_cleanup,
    }
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = _parse_json_strict(line)
        except (ValueError, json.JSONDecodeError):
            continue
        if not isinstance(req, dict) or req.get("protocol") != PROTOCOL:
            continue
        op = req.get("operation")
        fn = handlers.get(op)
        if fn is None:
            reply(
                req.get("id", ""),
                "unsupported",
                error={"code": "unknown_operation", "message": str(op)},
            )
        else:
            fn(req.get("id", ""), req.get("payload", {}) if isinstance(req.get("payload"), dict) else {})


if __name__ == "__main__":
    main()

"""Empirical privacy/leakage observations for transparent reference envelopes."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

FINDING_DISCLOSURE = "fixture_material_disclosed"
FINDING_HIDDEN_FIELD = "hidden_field_present"
FINDING_UNKNOWN_FIELD = "unknown_structured_field"
FINDING_DERIVED_DIGEST = "derived_digest_mismatch"
FINDING_STRUCTURE = "structured_output_mismatch"

_PRIVATE_MATERIAL = {
    "fixture",
    "given",
    "credential",
    "holder_signature",
    "status_witness",
}

_DERIVED_WIRE_KEYS = {
    "claim.context@1": "protocol_derived_digest",
}

_CONTEXT_WIRE_ALIASES = frozenset({"protocol_derived_digest", "presentation_context"})

_PAIR_REQUIRED = ("statement_identity", "stage", "given", "outcome", "permitted_projection")


def _decode_envelope(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
        if text.startswith("{"):
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    try:
        padded = raw + b"=" * (-len(raw) % 4)
        text = base64.urlsafe_b64decode(padded).decode("utf-8")
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        pass
    raise ValueError("unknown codec")


def _allowed_projection(release: dict[str, Any]) -> set[str]:
    allowed: set[str] = set(release.get("semantic_values", []))
    allowed.update(release.get("protocol_derived", []))
    allowed.update(release.get("opaque_channels", []))
    allowed.add("acceptance")
    for name in release.get("protocol_derived", []):
        wire = _DERIVED_WIRE_KEYS.get(name)
        if wire:
            allowed.add(wire)
        if name == "claim.context@1":
            allowed.update(_CONTEXT_WIRE_ALIASES)
    return allowed


def _dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in findings:
        marker = (str(item.get("kind")), str(item.get("field")))
        if marker in seen:
            continue
        seen.add(marker)
        unique.append(item)
    return unique


def _inspect_envelope(
    envelope: dict[str, Any],
    *,
    release: dict[str, Any],
    expected_derived_digest: str | None = None,
    expected_given: dict[str, Any] | None = None,
    permitted_projection: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    allowed = _allowed_projection(release)
    opaque = set(release.get("opaque_channels", []))
    permitted = permitted_projection or {}
    for key, value in envelope.items():
        if key == "given" and expected_given is not None:
            if value == expected_given:
                continue
            findings.append(
                {
                    "kind": FINDING_DISCLOSURE,
                    "field": "given",
                    "detail": "wire given differed from trusted verifier given",
                }
            )
            continue
        if key in _PRIVATE_MATERIAL:
            findings.append(
                {
                    "kind": FINDING_DISCLOSURE,
                    "field": key,
                    "detail": "transparent provider disclosed private fixture material",
                }
            )
            continue
        if key in _CONTEXT_WIRE_ALIASES:
            if key in permitted:
                if value != permitted[key]:
                    findings.append(
                        {
                            "kind": FINDING_STRUCTURE,
                            "field": key,
                            "detail": "declared output value differed from harness expected projection",
                        }
                    )
            elif expected_derived_digest is not None and value != expected_derived_digest:
                findings.append(
                    {
                        "kind": FINDING_DERIVED_DIGEST,
                        "field": key,
                        "detail": "derived digest mismatch",
                    }
                )
            continue
        if key.startswith("_hidden") or key == "branch_selector":
            findings.append(
                {
                    "kind": FINDING_HIDDEN_FIELD,
                    "field": key,
                    "detail": "hidden branch/attribute field observed on wire",
                }
            )
            continue
        if key in permitted:
            if value != permitted[key]:
                findings.append(
                    {
                        "kind": FINDING_STRUCTURE,
                        "field": key,
                        "detail": "declared output value differed from harness expected projection",
                    }
                )
            continue
        if key in opaque or key in allowed:
            continue
        findings.append(
            {
                "kind": FINDING_UNKNOWN_FIELD,
                "field": key,
                "detail": "structured field outside allowed projection",
            }
        )

    return _dedupe_findings(findings)


def analyze_presentation_leakage(
    *,
    raw_bytes: bytes,
    release: dict[str, Any],
    expected_derived_digest: str | None = None,
    permitted_projection: dict[str, Any] | None = None,
    expected_given: dict[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        envelope = _decode_envelope(raw_bytes)
    except ValueError:
        return {
            "status": "not_run",
            "reason": "unknown codec unavailable",
            "findings": [],
        }
    findings = _inspect_envelope(
        envelope,
        release=release,
        expected_derived_digest=expected_derived_digest,
        expected_given=expected_given,
        permitted_projection=permitted_projection,
    )
    return {"status": "findings" if findings else "clean", "findings": findings}


def _pair_ineligible(reason: str) -> dict[str, Any]:
    return {
        "eligibility": "ineligible",
        "status": "ineligible",
        "reason": reason,
        "findings": [],
    }


def _identity_complete(observation: dict[str, Any]) -> bool:
    for key in _PAIR_REQUIRED:
        if key not in observation:
            return False
        value = observation[key]
        if key in {"statement_identity", "stage"} and not value:
            return False
        if value is None:
            return False
    return True


def analyze_pair(*, left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Compare two raw observations. Eligibility is independent of leakage findings."""
    if not _identity_complete(left) or not _identity_complete(right):
        return _pair_ineligible("missing statement, stage, given, outcome, or expected projection")
    same_statement = left.get("statement_identity") == right.get("statement_identity")
    same_stage = left.get("stage") == right.get("stage")
    same_given = left.get("given") == right.get("given")
    same_outcome = left.get("outcome") == right.get("outcome")
    same_projection = left.get("permitted_projection") == right.get("permitted_projection")
    if not (same_statement and same_stage and same_given and same_outcome and same_projection):
        return _pair_ineligible("pair inputs differ")

    raw_l = left.get("raw_bytes") or b""
    raw_r = right.get("raw_bytes") or b""
    lengths = {"left": len(raw_l), "right": len(raw_r)}
    release = left.get("release") or right.get("release") or {}
    try:
        env_l = _decode_envelope(left["raw_bytes"])
        env_r = _decode_envelope(right["raw_bytes"])
    except (ValueError, KeyError):
        return {
            "eligibility": "eligible",
            "status": "not_run",
            "reason": "unknown codec unavailable",
            "findings": [],
            "raw_lengths": lengths,
            "field_counts": {"left": 0, "right": 0},
        }

    counts = {"left": len(env_l), "right": len(env_r)}
    findings: list[dict[str, Any]] = []
    expected_given = left.get("given")
    permitted = left.get("permitted_projection")
    expected_derived = permitted.get("protocol_derived_digest") if permitted else None
    findings.extend(
        _inspect_envelope(
            env_l,
            release=release,
            expected_given=expected_given,
            permitted_projection=permitted,
            expected_derived_digest=expected_derived,
        )
    )
    findings.extend(
        _inspect_envelope(
            env_r,
            release=release,
            expected_given=expected_given,
            permitted_projection=permitted,
            expected_derived_digest=expected_derived,
        )
    )

    opaque = set(release.get("opaque_channels", []))
    semantic = set(release.get("semantic_values", []))
    keys = set(env_l) | set(env_r)
    opaque_diff_only = True
    for key in keys:
        left_v = env_l.get(key, object())
        right_v = env_r.get(key, object())
        if left_v == right_v:
            continue
        if key in opaque:
            continue
        opaque_diff_only = False
        if key in semantic or key == "acceptance":
            findings.append(
                {
                    "kind": FINDING_STRUCTURE,
                    "field": key,
                    "detail": "declared semantic output mismatch on eligible pair",
                }
            )
        elif key in _PRIVATE_MATERIAL:
            findings.append(
                {
                    "kind": FINDING_DISCLOSURE,
                    "field": key,
                    "detail": "private material differed across paired transcripts",
                }
            )
        elif key in _CONTEXT_WIRE_ALIASES:
            findings.append(
                {
                    "kind": FINDING_STRUCTURE,
                    "field": key,
                    "detail": "declared semantic output mismatch on eligible pair",
                }
            )
        elif key.startswith("_hidden") or key == "branch_selector":
            findings.append(
                {
                    "kind": FINDING_HIDDEN_FIELD,
                    "field": key,
                    "detail": "hidden branch/attribute field differed on wire",
                }
            )
        else:
            findings.append(
                {
                    "kind": FINDING_UNKNOWN_FIELD,
                    "field": key,
                    "detail": "unknown structured field differed on wire",
                }
            )

    unique = _dedupe_findings(findings)
    if unique:
        status = "findings"
    elif raw_l != raw_r:
        status = "inconclusive"
        if not opaque_diff_only:
            status = "inconclusive"
    else:
        status = "clean"
    return {
        "eligibility": "eligible",
        "status": status,
        "findings": unique,
        "raw_lengths": lengths,
        "field_counts": counts,
    }


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

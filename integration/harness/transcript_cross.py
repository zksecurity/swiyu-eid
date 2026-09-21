"""Cross-implementation observer transcript differential.

Same pinned claim, two ZK backends, complete selected OID4VP HTTP traces.
Implementation identity (profile, circuit, issuer coordinates, proof length,
and message size) may differ. Hidden fixture markers and extra siblings may not.
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any

from semantics.claims import ClaimError, load_claim
from transcript_equivalence import (
    CRYPTO_ASSUMPTIONS,
    ClassifyError,
    SCHEMA,
    _alpha_value,
    _class_key,
    _classify,
    _dedupe,
    _diff_views,
    _fresh_provenance,
    _method,
    _normalize_session,
    _oracle_scope,
    _overall,
    _scrub,
    _validate_policy,
)
from transcript_policy import IMPLEMENTATION_KEYS

CROSS_SCHEMA = "swiyu.transcript-cross-impl.v1"
ENVELOPE_IMPLEMENTATION_KEYS = (
    "profile",
    "circuit",
    "circuit_id",
    "circuitId",
    "scheme",
    "version",
    "proof",
    "proof_b64",
)
LOOKUP_IMPLEMENTATION_KEYS = ("issuer", "kid", "vct")
LOOPBACK_URL = re.compile(r"https?://(?:127\.0\.0\.1|localhost):\d+", re.I)
LOOPBACK_HOST = re.compile(r"^(?:127\.0\.0\.1|localhost):\d+$", re.I)
LOOPBACK_URL_ENCODED = re.compile(r"https?%3A%2F%2F(?:127\.0\.0\.1|localhost)%3A\d+", re.I)


def _project_loopback(value: str, key: str | None) -> Any:
    if key and key.lower() == "host" and LOOPBACK_HOST.match(value):
        return {"implementation_channel": "loopback-host"}
    if LOOPBACK_URL.search(value) or LOOPBACK_URL_ENCODED.search(value):
        rewritten = LOOPBACK_URL.sub("http://127.0.0.1:<port>", value)
        rewritten = LOOPBACK_URL_ENCODED.sub("http%3A%2F%2F127.0.0.1%3A%3Cport%3E", rewritten)
        return rewritten
    return value


def _is_proof_envelope(value: dict[str, Any]) -> bool:
    return any(key in value for key in ("proof", "proof_b64", "circuitId", "circuit"))


def _project_lookup(value: Any) -> Any:
    if not isinstance(value, dict):
        return {"implementation_channel": "lookup"}
    extras = {
        key: _project_implementation(child, key)
        for key, child in value.items()
        if key not in LOOKUP_IMPLEMENTATION_KEYS
    }
    if not extras:
        return {"implementation_channel": "lookup"}
    return {"implementation_channel": "lookup", **extras}


def _project_implementation(value: Any, parent: str | None = None) -> Any:
    if isinstance(value, dict):
        if value.get("channel") == "proof" and "length" in value:
            projected = copy.deepcopy(value)
            projected["length"] = {"implementation_channel": "proof-length"}
            return projected
        out: dict[str, Any] = {}
        for key, child in value.items():
            if key == "body_size":
                out[key] = {"implementation_channel": "size"}
            elif key in IMPLEMENTATION_KEYS or key in ENVELOPE_IMPLEMENTATION_KEYS:
                out[key] = {"implementation_channel": key}
            elif key == "lookup":
                out[key] = _project_lookup(child)
            else:
                out[key] = _project_implementation(child, key)
        if parent == "x_swiyu_zkp" or _is_proof_envelope(value):
            for key in (*IMPLEMENTATION_KEYS, *ENVELOPE_IMPLEMENTATION_KEYS):
                out.setdefault(key, {"implementation_channel": key})
            out.setdefault("lookup", {"implementation_channel": "lookup"})
        return out
    if isinstance(value, list):
        if value and all(
            isinstance(item, list) and len(item) == 2 and isinstance(item[0], str)
            for item in value
        ):
            return [
                [
                    item[0],
                    (
                        {"implementation_channel": "size"}
                        if item[0].lower() == "content-length"
                        else _project_implementation(item[1], item[0])
                    ),
                ]
                for item in value
            ]
        return [_project_implementation(item, parent) for item in value]
    if isinstance(value, str):
        return _project_loopback(value, parent)
    return value


def project_implementation_views(views: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [_project_implementation(view) for view in views]


def analyze_cross_implementation(
    claim_path: str | Any,
    sessions: list[dict[str, Any]],
    policy: dict[str, Any],
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    try:
        claim = load_claim(claim_path)
    except (ClaimError, OSError) as exc:
        return {
            "schema": CROSS_SCHEMA,
            "status": "error",
            "findings": [{"kind": "policy_error", "explanation": str(exc)}],
            "pairs": [],
            "coverage": {"sessions": 0},
            "oracle_scope": {
                "note": "Claim could not be loaded.",
                "crypto_assumptions": list(CRYPTO_ASSUMPTIONS),
            },
            "method": _cross_method(),
            "exceptions": ["policy_error"],
        }
    policy_err = _validate_policy(policy, claim)
    if policy_err:
        return {
            "schema": CROSS_SCHEMA,
            "status": "error",
            "findings": [{"kind": "policy_error", "explanation": policy_err}],
            "pairs": [],
            "coverage": {"sessions": 0},
            "oracle_scope": _oracle_scope(claim),
            "method": _cross_method(),
            "exceptions": ["policy_error"],
        }

    rows = []
    all_markers: list[str] = []
    fresh_secrets: list[str] = []
    statuses = []
    for session in sessions:
        implementation = session.get("implementation")
        if not isinstance(implementation, str) or not implementation:
            findings.append(
                {
                    "kind": "policy_error",
                    "session": session.get("id"),
                    "explanation": "cross-implementation session is missing implementation",
                }
            )
            statuses.append("error")
            continue
        try:
            classification, markers = _classify(
                claim_path, session["credential"], session["given"]
            )
        except ClassifyError:
            findings.append(
                {
                    "kind": "invalid_auth",
                    "session": session.get("id"),
                    "explanation": "credential or given could not be classified",
                }
            )
            statuses.append("error")
            continue
        all_markers.extend(markers)
        fresh = session.get("fresh") or {}
        if isinstance(fresh, dict):
            fresh_secrets.extend(v for v in fresh.values() if isinstance(v, str))
        prov = _fresh_provenance(
            claim,
            session.get("given") or {},
            fresh if isinstance(fresh, dict) else {},
            markers,
            session.get("session_meta") if isinstance(session.get("session_meta"), dict) else None,
        )
        if prov:
            findings.append({"kind": "policy_error", "session": session.get("id"), "explanation": prov})
            statuses.append("error")
            findings.extend(_normalize_session(session, policy, markers)["findings"])
            continue
        classification = dict(classification)
        classification["public_context"] = _alpha_value(
            classification["public_context"], fresh if isinstance(fresh, dict) else {}
        )
        normalized = _normalize_session(session, policy, markers)
        findings.extend(normalized["findings"])
        accepted = session.get("accepted")
        if not isinstance(accepted, bool):
            findings.append(
                {
                    "kind": "invalid_accepted",
                    "session": session.get("id"),
                    "explanation": "accepted must be a JSON boolean",
                }
            )
            statuses.append("error")
            continue
        if accepted != classification["acceptance"]:
            findings.append(
                {
                    "kind": "unexpected_reject"
                    if classification["acceptance"] and not accepted
                    else "unexpected_accept",
                    "session": session.get("id"),
                    "explanation": "session accepted flag disagreed with claim classification",
                }
            )
            statuses.append("findings")
            continue
        if not normalized["ok"]:
            statuses.append(normalized["status"])
            continue
        rows.append(
            {
                "id": session.get("id"),
                "variant": session.get("variant"),
                "implementation": implementation,
                "classification": classification,
                "views": project_implementation_views(normalized["views"]),
            }
        )
        statuses.append("ok")

    pairs = []
    for i, left in enumerate(rows):
        for right in rows[i + 1 :]:
            if left["implementation"] == right["implementation"]:
                continue
            same = _class_key(left) == _class_key(right)
            if not same:
                pairs.append(
                    {
                        "left": left["id"],
                        "right": right["id"],
                        "left_implementation": left["implementation"],
                        "right_implementation": right["implementation"],
                        "eligibility": "input_non_equivalent",
                        "status": "not_compared",
                        "diffs": [],
                    }
                )
                continue
            diffs = [
                diff
                for diff in _diff_views(left["views"], right["views"])
                if diff.get("kind") != "opaque_length_mismatch"
            ]
            if any(d.get("kind") == "unknown_identifier_differential" for d in diffs):
                findings.append(
                    {
                        "kind": "unknown_identifier_differential",
                        "left": left["id"],
                        "right": right["id"],
                        "explanation": "unknown hash-like identifier differed across equivalent implementations",
                    }
                )
            pair_status = "equivalent" if not diffs else "mismatch"
            if diffs:
                statuses.append("findings")
                findings.append(
                    {
                        "kind": "transcript_mismatch",
                        "left": left["id"],
                        "right": right["id"],
                        "explanation": "normalized observer transcripts differed after implementation-channel exemption",
                        "pointers": [d["pointer"] for d in diffs],
                    }
                )
            pairs.append(
                {
                    "left": left["id"],
                    "right": right["id"],
                    "left_implementation": left["implementation"],
                    "right_implementation": right["implementation"],
                    "eligibility": "compared",
                    "status": pair_status,
                    "diffs": [
                        {
                            "pointer": d["pointer"],
                            "left_boundary": d.get("left_boundary"),
                            "right_boundary": d.get("right_boundary"),
                            "explanation": d["explanation"],
                        }
                        for d in diffs
                    ],
                }
            )

    findings = _dedupe(findings)
    status = _overall(statuses, findings, pairs)
    report = {
        "schema": CROSS_SCHEMA,
        "status": status,
        "policy": copy.deepcopy(policy),
        "unassessed_channels": (
            ["timing distributions", "cross-implementation proof length", "cross-implementation body size"]
            + (["response Date values"] if policy.get("response_clock_headers") else [])
            + (["request-object absolute issuance time"] if policy.get("request_object_clock") else [])
        ),
        "oracle_scope": _oracle_scope(claim),
        "classifications": [
            {
                "session": row["id"],
                "implementation": row["implementation"],
                "statement_digest": row["classification"]["statement_digest"],
                "acceptance": row["classification"]["acceptance"],
                "release": row["classification"]["release"],
                "public_context": row["classification"]["public_context"],
                "hidden_markers": row["classification"]["hidden_markers"],
            }
            for row in rows
        ],
        "pairs": pairs,
        "findings": findings,
        "coverage": {
            "sessions": len(sessions),
            "classified": len(rows),
            "implementations": sorted({row["implementation"] for row in rows}),
            "compared_pairs": sum(1 for p in pairs if p["eligibility"] == "compared"),
        },
        "exceptions": sorted({f["kind"] for f in findings if f.get("kind") in {"truncated_decode", "missing_events", "malformed_event", "invalid_auth", "policy_error", "invalid_accepted", "opaque_invalid"}}),
        "method": _cross_method(),
        "same_backend_method": _method(),
    }
    return _scrub(report, all_markers + fresh_secrets)


def _cross_method() -> str:
    return (
        "Same-claim classification, then observer HTTP equality after named "
        "fresh alpha-rename, declared proof opacity, and explicit exemption of "
        "implementation identity (profile, circuit_id, issuer coordinates, "
        "proof length, Content-Length, body size). Extra siblings, hidden "
        "markers, and unknown identifiers remain comparable. This is not a "
        "cryptographic indistinguishability argument."
    )

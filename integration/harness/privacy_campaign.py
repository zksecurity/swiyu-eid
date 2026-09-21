"""Generic privacy campaign analyzer for synthetic observation traces."""

from __future__ import annotations

import base64
import binascii
import json
import math
import hashlib
import re
from copy import deepcopy
from typing import Any
from urllib.parse import unquote, unquote_plus

SCHEMA_IN = "swiyu.privacy-traces.v1"
SCHEMA_OUT = "swiyu.privacy-campaign.v1"
FAMILIES = frozenset(
    {
        "disclosure",
        "hidden_branch",
        "linkability",
        "failure_fallback",
        "probing",
        "status_access",
        "session_isolation",
        "diagnostics",
        "side_channel",
        "prepared_state",
        "scoped_identifier",
    }
)
RELATIONS = frozenset(
    {
        "secret_scan",
        "equivalent",
        "unlinkable",
        "scoped",
        "same",
        "different",
        "metrics",
    }
)
EVIDENCE = frozenset({"integration", "crypto", "control"})
MAX_DEPTH = 8
MAX_DECODE_BYTES = 1_048_576
MAX_NODES = 4_096
HEX_RE = re.compile(r"\A(?:[0-9a-fA-F]{2})+\Z")
B64_RE = re.compile(r"\A[A-Za-z0-9+/]+={0,2}\Z")
B64URL_RE = re.compile(r"\A[A-Za-z0-9\-_]+={0,2}\Z")

METHOD = (
    "Bounded structural decode (JSON, base64/base64url, hex, URL, JWT segments; "
    f"max {MAX_DECODE_BYTES} decoded bytes, depth {MAX_DEPTH}, {MAX_NODES} nodes) "
    "and JSON-pointer comparison. Decoder-limit truncation is a coverage gap, not a "
    "clean secret scan. Byte equality is not a privacy proof and does "
    "not claim cryptographic unlinkability. Functional expected_outcome is compared "
    "independently of provider outcome. Secret canaries are scanned on views and "
    "artifact metadata (labels, paths, subject/session/scope/ids), including declared "
    "public and opaque paths."
)


class CampaignError(ValueError):
    """Invalid privacy trace bundle."""


def analyze_campaign(bundle: dict[str, Any]) -> dict[str, Any]:
    provider, cases = _validate_bundle(bundle)
    analyzed_cases: list[dict[str, Any]] = []
    integration_findings: list[dict[str, Any]] = []
    control_cases_out: list[dict[str, Any]] = []
    control_findings: list[dict[str, Any]] = []
    coverage_seen: list[dict[str, str]] = []
    gaps: list[dict[str, str]] = []
    statuses: list[str] = []

    for case in cases:
        result = _analyze_case(case)
        slim = {
            "id": case["id"],
            "family": case["family"],
            "relation": case["relation"],
            "observation_count": len(case["records"]),
            "observer": case["observer"],
            "runtime": case["runtime"],
            "evidence_kind": case["evidence_kind"],
            "status": result["status"],
            "findings": result["findings"],
        }
        if result.get("gap_reason"):
            slim["reason"] = result["gap_reason"]
        if case.get("skip_reason"):
            slim["skip_reason"] = case["skip_reason"]
        elif result.get("skip_reason"):
            slim["skip_reason"] = result["skip_reason"]
        if case["evidence_kind"] == "control":
            expected = _expected_control_status(case["id"])
            if expected is not None:
                slim["expected_status"] = expected
            control_cases_out.append(slim)
            control_findings.extend(result["findings"])
            continue
        analyzed_cases.append(slim)
        statuses.append(result["status"])
        if result["status"] == "coverage_gap":
            gaps.append(
                {
                    "case_id": case["id"],
                    "family": case["family"],
                    "relation": case["relation"],
                    "reason": result.get("gap_reason") or "missing observation",
                }
            )
        else:
            coverage_seen.append(
                {
                    "case_id": case["id"],
                    "family": case["family"],
                    "relation": case["relation"],
                    "evidence_kind": case["evidence_kind"],
                }
            )
            integration_findings.extend(result["findings"])

    privacy_status = _campaign_status(statuses, analyzed_cases)
    summary = _summary(privacy_status, integration_findings, gaps)
    report = {
        "schema": SCHEMA_OUT,
        "provider": provider,
        "privacy": {
            "status": privacy_status,
            "summary": summary,
            "findings": integration_findings,
            "cases": analyzed_cases,
            "coverage": {
                "cases": coverage_seen,
                "gaps": gaps,
                "families": sorted({row["family"] for row in coverage_seen}),
                "relations": sorted({row["relation"] for row in coverage_seen}),
            },
            "detector_controls": {
                "cases": control_cases_out,
                "findings": control_findings,
                "status": _control_status(control_cases_out),
            },
            "method": METHOD,
        },
    }
    secrets = [secret for case in cases for secret in case.get("secrets") or []]
    return _scrub(report, secrets)


def _campaign_status(statuses: list[str], analyzed: list[dict[str, Any]]) -> str:
    if not analyzed:
        return "not_run"
    runnable = [s for s in statuses if s != "coverage_gap"]
    if not runnable:
        return "not_run"
    if any(s == "findings" for s in runnable):
        return "findings"
    if any(s == "inconclusive" for s in runnable):
        return "inconclusive"
    return "clean"


def _expected_control_status(case_id: str) -> str | None:
    if case_id.endswith("-faulty"):
        return "findings"
    if case_id.endswith("-inadequate"):
        return "inconclusive"
    if case_id.endswith("-clean"):
        return "clean"
    return None


def _control_status(cases: list[dict[str, Any]]) -> str:
    if not cases:
        return "not_run"
    mismatches = []
    for case in cases:
        expected = _expected_control_status(case["id"])
        if expected is None:
            continue
        if case["status"] != expected:
            mismatches.append(case)
    if mismatches:
        return "findings"
    if all(_expected_control_status(c["id"]) for c in cases):
        return "clean"
    if any(c["status"] == "findings" for c in cases):
        return "findings"
    if any(c["status"] == "inconclusive" for c in cases):
        return "inconclusive"
    return "clean"


def _summary(status: str, findings: list[dict[str, Any]], gaps: list[dict[str, str]]) -> str:
    if status == "not_run":
        return "No integration observations were analyzed; coverage is a gap."
    if status == "findings":
        return f"{len(findings)} privacy finding(s); functional differences retained."
    if status == "inconclusive":
        return "Observations were insufficient for a clean/fail verdict (e.g. missing subject controls)."
    if gaps:
        return "No integration privacy findings; remaining coverage gaps are reported separately."
    return "No integration privacy findings on analyzed observations. Not a cryptographic proof."


def _validate_bundle(bundle: Any) -> tuple[dict[str, str], list[dict[str, Any]]]:
    if not isinstance(bundle, dict):
        raise CampaignError("bundle must be an object")
    if bundle.get("schema") != SCHEMA_IN:
        raise CampaignError("unsupported schema")
    provider = bundle.get("provider")
    if not isinstance(provider, dict) or not isinstance(provider.get("id"), str) or not isinstance(provider.get("title"), str):
        raise CampaignError("provider must be {id,title} strings")
    cases = bundle.get("cases")
    if not isinstance(cases, list):
        raise CampaignError("cases must be an array")
    validated = [_validate_case(case, index) for index, case in enumerate(cases)]
    return {"id": provider["id"], "title": provider["title"]}, validated


def _validate_case(case: Any, index: int) -> dict[str, Any]:
    if not isinstance(case, dict):
        raise CampaignError(f"case {index} must be an object")
    for key in ("id", "family", "relation", "observer", "runtime", "evidence_kind"):
        if not isinstance(case.get(key), str) or not case[key]:
            raise CampaignError(f"case {index} missing {key}")
    if case["family"] not in FAMILIES:
        raise CampaignError(f"unknown family: {case['family']}")
    if case["relation"] not in RELATIONS:
        raise CampaignError(f"unknown relation: {case['relation']}")
    if case["evidence_kind"] not in EVIDENCE:
        raise CampaignError(f"unknown evidence_kind: {case['evidence_kind']}")
    records = case.get("records")
    if not isinstance(records, list):
        raise CampaignError(f"case {case['id']} records must be an array")
    secrets = case.get("secrets", [])
    if secrets is None:
        secrets = []
    if not isinstance(secrets, list):
        raise CampaignError(f"case {case['id']} secrets must be an array")
    opaque = case.get("opaque_paths", []) or []
    compare = case.get("compare_paths", []) or []
    if not isinstance(opaque, list) or not isinstance(compare, list):
        raise CampaignError("path lists must be arrays")
    for pointer in [*opaque, *compare]:
        _parse_pointer(pointer)
    skip = case.get("skip_reason")
    if skip is not None and not isinstance(skip, str):
        raise CampaignError("skip_reason must be a string")
    return {
        "id": case["id"],
        "family": case["family"],
        "relation": case["relation"],
        "observer": case["observer"],
        "runtime": case["runtime"],
        "evidence_kind": case["evidence_kind"],
        "records": [_validate_record(case["id"], rec, i) for i, rec in enumerate(records)],
        "secrets": [_validate_secret(case["id"], secret, i) for i, secret in enumerate(secrets)],
        "opaque_paths": list(opaque),
        "compare_paths": list(compare),
        "skip_reason": skip,
    }


def _validate_secret(case_id: str, secret: Any, index: int) -> dict[str, str]:
    if not isinstance(secret, dict):
        raise CampaignError(f"{case_id} secret {index} must be an object")
    if not isinstance(secret.get("label"), str) or not isinstance(secret.get("value"), str):
        raise CampaignError(f"{case_id} secret {index} needs label and value strings")
    if not secret["value"]:
        raise CampaignError(f"{case_id} secret {index} value is empty")
    return {"label": secret["label"], "value": secret["value"]}


def _validate_record(case_id: str, rec: Any, index: int) -> dict[str, Any]:
    if not isinstance(rec, dict):
        raise CampaignError(f"{case_id} record {index} must be an object")
    for key in ("id", "subject", "session", "scope"):
        if not isinstance(rec.get(key), str) or not rec[key]:
            raise CampaignError(f"{case_id} record {index} missing {key}")
    if "public_context" not in rec or not _is_json_value(rec["public_context"]):
        raise CampaignError(f"{case_id} record {index} public_context invalid")
    if "expected_outcome" not in rec:
        raise CampaignError(f"{case_id} record {index} missing expected_outcome")
    if "outcome" not in rec or rec["outcome"] is None:
        raise CampaignError(f"{case_id} record {index} missing observed outcome")
    view = rec.get("view")
    if view is not None and not isinstance(view, dict):
        raise CampaignError(f"{case_id} record {index} view must be a JSON object")
    allowed = rec.get("allowed_public", {}) or {}
    if not isinstance(allowed, dict):
        raise CampaignError(f"{case_id} record {index} allowed_public must be an object")
    for pointer in allowed:
        _parse_pointer(pointer)
    metrics = rec.get("metrics")
    if metrics is not None:
        if not isinstance(metrics, dict):
            raise CampaignError(f"{case_id} record {index} metrics must be an object")
        for key in ("duration_ms", "size_bytes"):
            if key in metrics:
                value = metrics[key]
                if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                    raise CampaignError(f"{case_id} record {index} metrics.{key} must be finite and nonnegative")
    return {
        "id": rec["id"],
        "subject": rec["subject"],
        "session": rec["session"],
        "scope": rec["scope"],
        "public_context": rec["public_context"],
        "expected_outcome": rec["expected_outcome"],
        "outcome": rec.get("outcome"),
        "view": view,
        "allowed_public": allowed,
        "metrics": metrics,
    }


def _is_json_value(value: Any) -> bool:
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError):
        return False
    return True


def _analyze_case(case: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    if case.get("skip_reason"):
        return {
            "status": "coverage_gap",
            "findings": [],
            "gap_reason": case["skip_reason"],
            "skip_reason": case["skip_reason"],
        }
    if not case["records"]:
        return {
            "status": "coverage_gap",
            "findings": [],
            "gap_reason": "no records",
        }

    empty = False
    decode_limits: list[dict[str, bool]] = []
    findings.extend(_functional_findings(case))
    for rec in case["records"]:
        if rec["view"] is None or rec["view"] == {}:
            empty = True
            findings.append(
                _finding(
                    case,
                    "empty_observation",
                    "/",
                    "Observation is empty; empty views cannot pass.",
                )
            )

    for rec in case["records"]:
        secret_hits, limits = _scan_secrets(case, rec)
        findings.extend(secret_hits)
        decode_limits.append(limits)
        findings.extend(_validate_allowed_public(case, rec))
    truncated = any(item.get("truncated") or item.get("bound_hit") for item in decode_limits)

    relation = case["relation"]
    if relation == "secret_scan":
        pass
    elif relation == "equivalent":
        findings.extend(_relation_equivalent(case))
    elif relation == "same":
        findings.extend(_relation_compare(case, expect_equal=True))
    elif relation == "different":
        findings.extend(_relation_compare(case, expect_equal=False))
    elif relation == "unlinkable":
        extra, inconclusive = _relation_unlinkable(case)
        findings.extend(extra)
        if empty:
            return {"status": "findings", "findings": findings}
        if findings:
            return {"status": "findings", "findings": findings}
        if truncated:
            reason = (
                f"Decoder did not cover the full observation "
                f"(limit {MAX_DECODE_BYTES} bytes / depth {MAX_DEPTH} / {MAX_NODES} nodes); "
                "unlinkable scan is incomplete, not clean."
            )
            return {"status": "coverage_gap", "findings": [], "gap_reason": reason}
        if inconclusive:
            return {
                "status": "inconclusive",
                "findings": [
                    _finding(
                        case,
                        "inadequate_controls",
                        "/",
                        "Suspected identifier reuse lacks subject/session controls; inconclusive, not unlinkability.",
                    )
                ],
            }
        return {"status": "clean", "findings": []}
    elif relation == "scoped":
        findings.extend(_relation_scoped(case))
    elif relation == "metrics":
        extra, gap = _relation_metrics(case)
        if gap:
            return {"status": "coverage_gap", "findings": extra, "gap_reason": gap}
        findings.extend(extra)
    else:
        raise CampaignError(f"unknown relation: {relation}")

    if empty:
        return {"status": "findings", "findings": findings}
    if findings:
        return {"status": "findings", "findings": findings}
    if truncated:
        reason = (
            f"Decoder did not cover the full observation "
            f"(limit {MAX_DECODE_BYTES} bytes / depth {MAX_DEPTH} / {MAX_NODES} nodes); "
            "secret scan is incomplete, not clean."
        )
        return {
            "status": "coverage_gap",
            "findings": [],
            "gap_reason": reason,
        }
    return {"status": "clean", "findings": []}


def _functional_findings(case: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    for rec in case["records"]:
        if rec.get("outcome") is None:
            continue
        if rec["expected_outcome"] != rec["outcome"]:
            findings.append(
                _finding(
                    case,
                    "functional_difference",
                    "/",
                    "expected_outcome differs from observed outcome; retained as a finding.",
                )
            )
    return findings


def _finding(case: dict[str, Any], kind: str, field: str, detail: str) -> dict[str, Any]:
    secrets = case.get("secrets") or []
    return {
        "kind": kind,
        "case_id": _sanitize(case["id"], secrets),
        "observer": _sanitize(case["observer"], secrets),
        "runtime": _sanitize(case["runtime"], secrets),
        "field": _sanitize(field, secrets),
        "detail": _sanitize(detail, secrets),
    }


def _redaction_token(secret: dict[str, str]) -> str:
    label = secret.get("label") or "canary"
    value = secret.get("value") or ""
    if value and value in label:
        return "[redacted]"
    return f"[redacted:{label}]"


def _sanitize(text: str, secrets: list[dict[str, str]]) -> str:
    out = text
    for secret in sorted(secrets, key=lambda item: len(item.get("value") or ""), reverse=True):
        value = secret.get("value") or ""
        if value and value in out:
            out = out.replace(value, _redaction_token(secret))
    return out


def _scrub(value: Any, secrets: list[dict[str, str]]) -> Any:
    if not secrets:
        return value
    if isinstance(value, str):
        return _sanitize(value, secrets)
    if isinstance(value, list):
        return [_scrub(item, secrets) for item in value]
    if isinstance(value, dict):
        return {_sanitize(str(key), secrets) if isinstance(key, str) else key: _scrub(item, secrets) for key, item in value.items()}
    return value


def _scan_secrets(case: dict[str, Any], rec: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, bool]]:
    findings = []
    leaves, limits = _decoded_leaves(rec.get("view") if isinstance(rec.get("view"), dict) else {})
    artifacts = _artifact_text_leaves(case, rec)
    leaves = [*leaves, *artifacts]
    for secret in case["secrets"]:
        value = secret["value"]
        for pointer, text in leaves:
            if value and value in text:
                findings.append(
                    _finding(
                        case,
                        "secret_disclosure",
                        pointer or "/",
                        f"Synthetic secret {secret['label']} observed in decoded view or artifact metadata.",
                    )
                )
                break
    return findings, limits


def _artifact_text_leaves(case: dict[str, Any], rec: dict[str, Any]) -> list[tuple[str, str]]:
    leaves: list[tuple[str, str]] = []
    for pointer, value in (
        ("/id", rec.get("id")),
        ("/subject", rec.get("subject")),
        ("/session", rec.get("session")),
        ("/scope", rec.get("scope")),
        ("/case_id", case.get("id")),
        ("/observer", case.get("observer")),
        ("/runtime", case.get("runtime")),
    ):
        if isinstance(value, str) and value:
            leaves.append((pointer, value))
    for secret in case.get("secrets") or []:
        if isinstance(secret.get("label"), str):
            leaves.append(("/secrets/label", secret["label"]))
    for pointer in case.get("opaque_paths") or []:
        if isinstance(pointer, str):
            leaves.append(("/opaque_paths", pointer))
    for pointer in case.get("compare_paths") or []:
        if isinstance(pointer, str):
            leaves.append(("/compare_paths", pointer))
    for pointer in rec.get("allowed_public") or {}:
        if isinstance(pointer, str):
            leaves.append(("/allowed_public", pointer))
    return leaves


def _validate_allowed_public(case: dict[str, Any], rec: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    view = rec.get("view")
    if not isinstance(view, dict):
        return findings
    for pointer, expected in rec["allowed_public"].items():
        try:
            actual = _get_pointer(view, pointer)
        except (KeyError, TypeError, IndexError, CampaignError):
            findings.append(
                _finding(
                    case,
                    "allowed_public_mismatch",
                    pointer,
                    "allowed_public path missing; value was not ignored.",
                )
            )
            continue
        if actual != expected:
            findings.append(
                _finding(
                    case,
                    "allowed_public_mismatch",
                    pointer,
                    "allowed_public value did not match; path was not ignored.",
                )
            )
    return findings


def _stripped_view(rec: dict[str, Any], extra_paths: list[str]) -> Any:
    view = deepcopy(rec["view"]) if isinstance(rec.get("view"), dict) else {}
    skip = []
    for pointer, expected in rec["allowed_public"].items():
        try:
            if _get_pointer(view, pointer) == expected:
                skip.append(pointer)
        except (KeyError, TypeError, IndexError, CampaignError):
            continue
    for pointer in [*skip, *extra_paths]:
        try:
            _delete_pointer(view, pointer)
        except (KeyError, TypeError, IndexError, CampaignError):
            continue
    return view


def _relation_equivalent(case: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    records = case["records"]
    if len(records) < 2:
        findings.append(
            _finding(case, "insufficient_observations", "/", "equivalent requires at least two observations.")
        )
        return findings
    baseline = records[0]
    for rec in records[1:]:
        if rec["expected_outcome"] != baseline["expected_outcome"]:
            findings.append(
                _finding(
                    case,
                    "functional_difference",
                    "/",
                    "expected_outcome differs across equivalent records; retained as a finding.",
                )
            )
        if rec["public_context"] != baseline["public_context"]:
            findings.append(
                _finding(
                    case,
                    "context_mismatch",
                    "/",
                    "public_context differs; records are not comparable as equivalent.",
                )
            )
        left = _stripped_view(baseline, case["opaque_paths"])
        right = _stripped_view(rec, case["opaque_paths"])
        if left != right:
            findings.append(
                _finding(
                    case,
                    "unexpected_public_difference",
                    "/",
                    "Views differ after removing validated allowed_public and opaque_paths.",
                )
            )
    return findings


def _relation_compare(case: dict[str, Any], *, expect_equal: bool) -> list[dict[str, Any]]:
    findings = []
    paths = case["compare_paths"]
    if not paths:
        findings.append(_finding(case, "missing_compare_paths", "/", "compare_paths required."))
        return findings
    records = case["records"]
    if len(records) < 2:
        findings.append(_finding(case, "insufficient_observations", "/", "comparison requires at least two observations."))
        return findings
    values = []
    for rec in records:
        if not isinstance(rec.get("view"), dict):
            findings.append(_finding(case, "empty_observation", "/", "Missing view for comparison."))
            continue
        slot = []
        for pointer in paths:
            try:
                slot.append(_get_pointer(rec["view"], pointer))
            except (KeyError, TypeError, IndexError, CampaignError):
                findings.append(_finding(case, "missing_compare_path", pointer, "compare_path missing from view."))
                slot.append(None)
        values.append(slot)
    if any(item is None for row in values for item in row):
        return findings
    for i, left in enumerate(values):
        for right in values[i + 1 :]:
            equal = left == right
            if expect_equal and not equal:
                findings.append(_finding(case, "values_not_same", "/", "compare_paths were not equal."))
                return findings
            if not expect_equal and equal:
                findings.append(_finding(case, "values_not_different", "/", "compare_paths were equal but must differ."))
                return findings
    return findings


def _relation_unlinkable(case: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
    findings: list[dict[str, Any]] = []
    records = [rec for rec in case["records"] if isinstance(rec.get("view"), dict)]
    subjects = {rec["subject"] for rec in records}
    sessions = {(rec["subject"], rec["session"]) for rec in records}
    if len(records) < 2:
        return findings, True
    by_subject: dict[str, list[set[str]]] = {}
    for rec in records:
        leaf_rows, _limits = _decoded_leaves(_stripped_view(rec, case["opaque_paths"]))
        leaves = {
            text
            for _, text in leaf_rows
            if text and not _looks_boolean_or_tiny(text)
        }
        by_subject.setdefault(rec["subject"], []).append(leaves)

    repeating: dict[str, set[str]] = {}
    for subject, bags in by_subject.items():
        if len(bags) < 2:
            continue
        shared = set.intersection(*bags) if bags else set()
        repeating[subject] = shared

    all_repeating = set().union(*repeating.values()) if repeating else set()
    constants = set(all_repeating)
    for subject, bags in by_subject.items():
        union = set().union(*bags) if bags else set()
        constants &= union

    linkable = False
    for subject, shared in repeating.items():
        exclusive = shared - constants
        if exclusive:
            linkable = True
            findings.append(
                _finding(
                    case,
                    "linkable_identifier",
                    "/",
                    "Credential-specific value repeated across fresh sessions after ignoring public/opaque paths.",
                )
            )

    inadequate = len(subjects) < 2 or len(sessions) < 2 or any(len(bags) < 2 for bags in by_subject.values())
    if linkable:
        return findings, False
    if inadequate:
        leftover_repeat = any(shared - constants for shared in repeating.values())
        return findings, leftover_repeat or inadequate and bool(repeating)
    return findings, False


def _looks_boolean_or_tiny(text: str) -> bool:
    return text in {"true", "false", "null"} or len(text) <= 1


def _relation_scoped(case: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    paths = case["compare_paths"]
    if not paths:
        findings.append(_finding(case, "missing_compare_paths", "/", "scoped relation requires compare_paths from scenario policy."))
        return findings
    groups: dict[tuple[str, str], list[Any]] = {}
    for rec in case["records"]:
        if not isinstance(rec.get("view"), dict):
            findings.append(_finding(case, "empty_observation", "/", "Missing view for scoped comparison."))
            continue
        slot = []
        for pointer in paths:
            try:
                slot.append(_get_pointer(rec["view"], pointer))
            except (KeyError, TypeError, IndexError, CampaignError):
                findings.append(_finding(case, "missing_compare_path", pointer, "compare_path missing."))
                slot = None
                break
        if slot is None:
            continue
        key = (rec["subject"], rec["scope"])
        groups.setdefault(key, []).append(slot)

    for key, values in groups.items():
        if any(item != values[0] for item in values[1:]):
            findings.append(
                _finding(
                    case,
                    "scope_unstable",
                    "/",
                    "compare_paths were not stable for the same subject and policy scope.",
                )
            )

    by_subject: dict[str, dict[str, Any]] = {}
    for (subject, scope), values in groups.items():
        by_subject.setdefault(subject, {})[scope] = values[0]
    for subject, scopes in by_subject.items():
        uniq = list(scopes.values())
        if len(uniq) >= 2 and any(item == uniq[0] for item in uniq[1:]):
            findings.append(
                _finding(
                    case,
                    "scope_collision",
                    "/",
                    "compare_paths were not distinct across policy scopes for the same subject.",
                )
            )
    if len(groups) < 2:
        findings.append(
            _finding(
                case,
                "insufficient_scope_controls",
                "/",
                "scoped comparison needs multiple subject/scope observations from scenario policy.",
            )
        )
    return findings


def _relation_metrics(case: dict[str, Any]) -> tuple[list[dict[str, Any]], str | None]:
    findings: list[dict[str, Any]] = []
    records = case["records"]
    by_subject: dict[str, list[dict[str, Any]]] = {}
    order = []
    for rec in records:
        metrics = rec.get("metrics") or {}
        by_subject.setdefault(rec["subject"], []).append(metrics)
        order.append(rec["subject"])
    if any(len(samples) < 8 for samples in by_subject.values()) or len(by_subject) < 2:
        return (
            [
                _finding(
                    case,
                    "insufficient_metrics",
                    "/",
                    "metrics relation needs >=8 samples per subject class.",
                )
            ],
            "insufficient metrics samples",
        )
    if _is_grouped_order(order):
        findings.append(
            _finding(
                case,
                "metrics_order_not_randomized",
                "/",
                "Input order is grouped by subject; exploratory metrics require randomized order.",
            )
        )
    for key in ("duration_ms", "size_bytes"):
        series = {
            subject: [m[key] for m in samples if isinstance(m.get(key), (int, float))]
            for subject, samples in by_subject.items()
        }
        if any(len(vals) < 8 for vals in series.values()):
            continue
        subjects = list(series)
        for i, left in enumerate(subjects):
            for right in subjects[i + 1 :]:
                if _separated(series[left], series[right]):
                    findings.append(
                        _finding(
                            case,
                            "exploratory_distinguishability",
                            f"/metrics/{key}",
                            "Exploratory class separation in metrics; not a cryptographic side-channel proof.",
                        )
                    )
    return findings, None


def _is_grouped_order(order: list[str]) -> bool:
    if len(order) < 4:
        return True
    runs = 1
    for prev, cur in zip(order, order[1:]):
        if cur != prev:
            runs += 1
    return runs <= len(set(order))


def _separated(a: list[float], b: list[float]) -> bool:
    return max(a) < min(b) or max(b) < min(a)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _parse_pointer(pointer: Any) -> list[str]:
    if not isinstance(pointer, str):
        raise CampaignError("JSON pointer must be a string")
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        raise CampaignError(f"invalid JSON pointer: {pointer}")
    tokens = []
    for raw in pointer[1:].split("/"):
        tokens.append(raw.replace("~1", "/").replace("~0", "~"))
    return tokens


def _escape_token(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _get_pointer(doc: Any, pointer: str) -> Any:
    cur = doc
    for token in _parse_pointer(pointer):
        if isinstance(cur, list):
            idx = int(token)
            cur = cur[idx]
        elif isinstance(cur, dict):
            if token not in cur:
                raise KeyError(token)
            cur = cur[token]
        else:
            raise TypeError("cannot traverse")
    return cur


def _delete_pointer(doc: Any, pointer: str) -> None:
    tokens = _parse_pointer(pointer)
    if not tokens:
        if isinstance(doc, dict):
            doc.clear()
        return
    cur = doc
    for token in tokens[:-1]:
        if isinstance(cur, list):
            cur = cur[int(token)]
        else:
            cur = cur[token]
    last = tokens[-1]
    if isinstance(cur, list):
        idx = int(last)
        cur.pop(idx)
    elif isinstance(cur, dict) and last in cur:
        del cur[last]


def _decoded_leaves(value: Any) -> tuple[list[tuple[str, str]], dict[str, bool]]:
    out: list[tuple[str, str]] = []
    limits = {"truncated": False, "bound_hit": False}
    _walk(value, "", 0, 0, out, set(), limits)
    return out, limits


def _walk(
    value: Any,
    pointer: str,
    depth: int,
    nodes: int,
    out: list[tuple[str, str]],
    seen: set[str],
    limits: dict[str, bool],
) -> int:
    if nodes >= MAX_NODES or depth > MAX_DEPTH:
        limits["bound_hit"] = True
        return nodes
    nodes += 1
    if isinstance(value, dict):
        for key, child in value.items():
            child_ptr = f"{pointer}/{_escape_token(str(key))}"
            nodes = _walk(child, child_ptr, depth + 1, nodes, out, seen, limits)
        return nodes
    if isinstance(value, list):
        for idx, child in enumerate(value):
            child_ptr = f"{pointer}/{idx}"
            nodes = _walk(child, child_ptr, depth + 1, nodes, out, seen, limits)
        return nodes
    if isinstance(value, str):
        out.append((pointer or "/", value))
        encoded_len = len(value.encode("utf-8", "replace"))
        if encoded_len > MAX_DECODE_BYTES:
            limits["truncated"] = True
            prefix = value.encode("utf-8", "replace")[:MAX_DECODE_BYTES].decode("utf-8", "ignore")
            if prefix != value:
                out.append((pointer or "/", prefix))
            return nodes
        fingerprint = f"{depth}:{hashlib.sha256(value.encode('utf-8', 'replace')).hexdigest()}"
        if fingerprint in seen:
            return nodes
        seen.add(fingerprint)
        for decoded in _decode_string(value):
            nodes = _walk(decoded, pointer, depth + 1, nodes, out, seen, limits)
        return nodes
    if value is None or isinstance(value, (int, float, bool)):
        out.append((pointer or "/", json.dumps(value)))
    return nodes


def _decode_string(text: str) -> list[Any]:
    decoded: list[Any] = []
    if text.startswith("%") or "%" in text:
        for fn in (unquote, unquote_plus):
            try:
                candidate = fn(text)
            except Exception:
                continue
            if candidate != text:
                decoded.append(candidate)
    json_candidate = _try_json(text)
    if json_candidate is not None:
        decoded.append(json_candidate)
    if "." in text and text.count(".") >= 2 and " " not in text:
        for segment in text.split("."):
            if segment:
                raw = _b64url_decode(segment)
                if raw is not None:
                    as_text = _bytes_to_text(raw)
                    if as_text is not None:
                        decoded.append(as_text)
                        parsed = _try_json(as_text)
                        if parsed is not None:
                            decoded.append(parsed)
    raw = _b64url_decode(text) if B64URL_RE.fullmatch(text) and len(text) >= 8 else None
    if raw is not None:
        as_text = _bytes_to_text(raw)
        if as_text is not None:
            decoded.append(as_text)
    if B64_RE.fullmatch(text) and len(text) >= 8:
        padded = text + "=" * ((4 - len(text) % 4) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            raw = None
        if raw:
            as_text = _bytes_to_text(raw)
            if as_text is not None:
                decoded.append(as_text)
    if HEX_RE.fullmatch(text) and len(text) >= 8:
        try:
            raw = bytes.fromhex(text)
        except ValueError:
            raw = None
        if raw:
            as_text = _bytes_to_text(raw)
            if as_text is not None:
                decoded.append(as_text)
    return decoded


def _try_json(text: str) -> Any | None:
    stripped = text.strip()
    if len(stripped) < 2 or stripped[0] not in "{[\"":
        return None
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return None


def _b64url_decode(text: str) -> bytes | None:
    padded = text + "=" * ((4 - len(text) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return None


def _bytes_to_text(raw: bytes) -> str | None:
    if not raw or len(raw) > MAX_DECODE_BYTES:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if any(ord(ch) < 9 for ch in text):
        return None
    return text

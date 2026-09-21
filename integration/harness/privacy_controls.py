"""Deliberately clean and faulty detector controls for privacy relations."""

from __future__ import annotations

from typing import Any

SECRET = "SYNTHETIC-CTRL-SECRET-aa11"


def control_cases() -> list[dict[str, Any]]:
    return [
        _secret_clean(),
        _secret_faulty(),
        _equivalent_clean(),
        _equivalent_faulty(),
        _same_clean(),
        _same_faulty(),
        _different_clean(),
        _different_faulty(),
        _unlinkable_clean(),
        _unlinkable_faulty(),
        _unlinkable_inadequate(),
        _scoped_clean(),
        _scoped_faulty(),
        _metrics_clean(),
        _metrics_faulty(),
    ]


def _base(case_id: str, family: str, relation: str, records: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    case = {
        "id": case_id,
        "family": family,
        "relation": relation,
        "observer": "control",
        "runtime": "fixture",
        "evidence_kind": "control",
        "records": records,
        "secrets": extra.get("secrets", []),
        "opaque_paths": extra.get("opaque_paths", []),
        "compare_paths": extra.get("compare_paths", []),
    }
    return case


def _rec(rid: str, subject: str, session: str, scope: str, view: dict[str, Any], **extra: Any) -> dict[str, Any]:
    rec = {
        "id": rid,
        "subject": subject,
        "session": session,
        "scope": scope,
        "public_context": extra.get("public_context", {"aud": "ctrl"}),
        "expected_outcome": extra.get("expected_outcome", "ok"),
        "outcome": extra.get("outcome", "ok"),
        "view": view,
        "allowed_public": extra.get("allowed_public", {}),
    }
    if "metrics" in extra:
        rec["metrics"] = extra["metrics"]
    return rec


def _secret_clean() -> dict[str, Any]:
    return _base(
        "ctrl-secret-clean",
        "disclosure",
        "secret_scan",
        [_rec("r1", "a", "s1", "x", {"token": "no-canary-here"})],
        secrets=[{"label": "canary", "value": SECRET}],
    )


def _secret_faulty() -> dict[str, Any]:
    return _base(
        "ctrl-secret-faulty",
        "disclosure",
        "secret_scan",
        [_rec("r1", "a", "s1", "x", {"blob": SECRET})],
        secrets=[{"label": "canary", "value": SECRET}],
    )


def _equivalent_clean() -> dict[str, Any]:
    view_a = {"ok": True, "proof": "aaa", "aud": "ctrl"}
    view_b = {"ok": True, "proof": "bbb", "aud": "ctrl"}
    allowed = {"/aud": "ctrl"}
    return _base(
        "ctrl-equivalent-clean",
        "hidden_branch",
        "equivalent",
        [
            _rec("r1", "a", "s1", "x", view_a, allowed_public=allowed),
            _rec("r2", "a", "s2", "x", view_b, allowed_public=allowed),
        ],
        opaque_paths=["/proof"],
    )


def _equivalent_faulty() -> dict[str, Any]:
    return _base(
        "ctrl-equivalent-faulty",
        "hidden_branch",
        "equivalent",
        [
            _rec("r1", "a", "s1", "x", {"ok": True, "branch": "A"}),
            _rec("r2", "a", "s2", "x", {"ok": True, "branch": "B"}),
        ],
    )


def _same_clean() -> dict[str, Any]:
    return _base(
        "ctrl-same-clean",
        "prepared_state",
        "same",
        [
            _rec("r1", "a", "s1", "x", {"id": "stable"}),
            _rec("r2", "a", "s2", "x", {"id": "stable"}),
        ],
        compare_paths=["/id"],
    )


def _same_faulty() -> dict[str, Any]:
    return _base(
        "ctrl-same-faulty",
        "prepared_state",
        "same",
        [
            _rec("r1", "a", "s1", "x", {"id": "stable"}),
            _rec("r2", "a", "s2", "x", {"id": "other"}),
        ],
        compare_paths=["/id"],
    )


def _different_clean() -> dict[str, Any]:
    return _base(
        "ctrl-different-clean",
        "session_isolation",
        "different",
        [
            _rec("r1", "a", "s1", "x", {"nonce": "n1"}),
            _rec("r2", "a", "s2", "x", {"nonce": "n2"}),
        ],
        compare_paths=["/nonce"],
    )


def _different_faulty() -> dict[str, Any]:
    return _base(
        "ctrl-different-faulty",
        "session_isolation",
        "different",
        [
            _rec("r1", "a", "s1", "x", {"nonce": "n1"}),
            _rec("r2", "a", "s2", "x", {"nonce": "n1"}),
        ],
        compare_paths=["/nonce"],
    )


def _unlinkable_clean() -> dict[str, Any]:
    return _base(
        "ctrl-unlinkable-clean",
        "linkability",
        "unlinkable",
        [
            _rec("r1", "a", "s1", "x", {"pub": "P", "tok": "t-a1"}),
            _rec("r2", "a", "s2", "x", {"pub": "P", "tok": "t-a2"}),
            _rec("r3", "b", "s1", "x", {"pub": "P", "tok": "t-b1"}),
            _rec("r4", "b", "s2", "x", {"pub": "P", "tok": "t-b2"}),
        ],
        opaque_paths=[],
    )


def _unlinkable_faulty() -> dict[str, Any]:
    return _base(
        "ctrl-unlinkable-faulty",
        "linkability",
        "unlinkable",
        [
            _rec("r1", "a", "s1", "x", {"pub": "P", "tok": "repeat-a"}),
            _rec("r2", "a", "s2", "x", {"pub": "P", "tok": "repeat-a"}),
            _rec("r3", "b", "s1", "x", {"pub": "P", "tok": "repeat-b"}),
            _rec("r4", "b", "s2", "x", {"pub": "P", "tok": "repeat-b"}),
        ],
    )


def _unlinkable_inadequate() -> dict[str, Any]:
    return _base(
        "ctrl-unlinkable-inadequate",
        "linkability",
        "unlinkable",
        [
            _rec("r1", "a", "s1", "x", {"tok": "repeat-a"}),
            _rec("r2", "a", "s2", "x", {"tok": "repeat-a"}),
        ],
    )


def _scoped_clean() -> dict[str, Any]:
    return _base(
        "ctrl-scoped-clean",
        "scoped_identifier",
        "scoped",
        [
            _rec("r1", "a", "s1", "alpha", {"sid": "A-alpha"}),
            _rec("r2", "a", "s2", "alpha", {"sid": "A-alpha"}),
            _rec("r3", "a", "s3", "beta", {"sid": "A-beta"}),
        ],
        compare_paths=["/sid"],
    )


def _scoped_faulty() -> dict[str, Any]:
    return _base(
        "ctrl-scoped-faulty",
        "scoped_identifier",
        "scoped",
        [
            _rec("r1", "a", "s1", "alpha", {"sid": "same"}),
            _rec("r2", "a", "s2", "alpha", {"sid": "same"}),
            _rec("r3", "a", "s3", "beta", {"sid": "same"}),
        ],
        compare_paths=["/sid"],
    )


def _metrics_samples(subject: str, base: int, jitter: int) -> list[dict[str, Any]]:
    recs = []
    for i in range(8):
        recs.append(
            _rec(
                f"{subject}-{i}",
                subject,
                f"s{i}",
                "x",
                {"n": i},
                metrics={"duration_ms": base + (i % 2) * jitter, "size_bytes": 100 + i},
            )
        )
    return recs


def _metrics_clean() -> dict[str, Any]:
    a = _metrics_samples("a", 10, 1)
    b = _metrics_samples("b", 11, 1)
    interleaved = []
    for i in range(8):
        interleaved.append(a[i])
        interleaved.append(b[i])
    return _base("ctrl-metrics-clean", "side_channel", "metrics", interleaved)


def _metrics_faulty() -> dict[str, Any]:
    a = _metrics_samples("a", 10, 0)
    b = _metrics_samples("b", 500, 0)
    interleaved = []
    for i in range(8):
        interleaved.append(a[i])
        interleaved.append(b[i])
    return _base("ctrl-metrics-faulty", "side_channel", "metrics", interleaved)

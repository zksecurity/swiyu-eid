"""Claim campaign runner — ProviderClient lifecycle + privacy findings."""

from __future__ import annotations

import base64
import binascii
import hashlib
import html
import json
import os
import sys
import time
import uuid
from contextlib import contextmanager
from itertools import combinations
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SEMANTICS = ROOT.parent / "semantics"
PROVIDERS_ROOT = ROOT.parent / "providers"
REFERENCE_MANIFEST = PROVIDERS_ROOT / "semantic-reference" / "manifest.json"
REFERENCE_SUPPORT = PROVIDERS_ROOT / "semantic-reference" / "support.json"
ALLOWED_OUTPUT_FILES = frozenset({"report.json", "report.html", "result.json"})

if str(SEMANTICS) not in sys.path:
    sys.path.insert(0, str(SEMANTICS))

from semantics.assertions import AUTH_OPERATION, expected_transcript  # noqa: E402
from semantics.credentials import CredentialError, authenticate  # noqa: E402
from semantics.canonical import canonical_json_bytes  # noqa: E402
from semantics.claims import load_claim  # noqa: E402
from semantics.leakage import analyze_pair, analyze_presentation_leakage  # noqa: E402
from semantics.planner import plan_campaign_cases  # noqa: E402
from semantics.support import (  # noqa: E402
    implementation_digest,
    load_support,
    verify_claim_supported,
)

from provider_client import ProviderClient, ProviderError  # noqa: E402


def _safe_output_dir(output: str) -> Path:
    out = Path(output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    for name in ALLOWED_OUTPUT_FILES:
        entry = out / name
        if entry.is_symlink():
            raise ValueError(f"unsafe symlink in output: {entry.name}")
    return out


def _atomic_write(path: Path, content: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)


def _functional_overall(cases: list[dict[str, Any]]) -> str:
    functional = [case for case in cases if case["outcome"] not in {"not_run", "unsupported"}]
    if not functional:
        return "not_run"
    outcomes = {case["outcome"] for case in functional}
    if outcomes <= {"passed"}:
        return "passed"
    if "provider_error" in outcomes:
        return "provider_error"
    return "failed"


_PREDICATE_PHRASES = {
    "date.on-or-before@1": "on or before",
    "date.on-or-after@1": "on or after",
    "value.equals@1": "equals",
    "value.in-set@1": "in set",
}


def _render_operand(node: Any) -> str:
    if isinstance(node, dict):
        if "attribute" in node:
            return f"attribute {node['attribute']}"
        if "given" in node:
            return f"given {node['given']}"
        if "const" in node:
            return f"const {node['const']}"
        if "credential" in node:
            return f"credential {node['credential']}"
        return " ".join(_render_operand(v) for v in node.values())
    if isinstance(node, list):
        return ", ".join(_render_operand(item) for item in node)
    return str(node)


def _render_condition(node: Any) -> str:
    if not isinstance(node, dict):
        return str(node)
    if "all" in node:
        parts = [_render_condition(child) for child in node.get("all") or []]
        return "(" + " AND ".join(parts) + ")"
    if "any" in node:
        parts = [_render_condition(child) for child in node.get("any") or []]
        return "(" + " OR ".join(parts) + ")"
    predicate = node.get("predicate")
    if isinstance(predicate, str):
        phrase = _PREDICATE_PHRASES.get(
            predicate,
            predicate.replace("@1", "").replace(".", " ").replace("-", " ").strip(),
        )
        args = node.get("args") if isinstance(node.get("args"), dict) else {}
        operands = [_render_operand(value) for value in args.values()]
        if len(operands) >= 2:
            return f"{operands[0]} {phrase} {operands[1]}"
        if operands:
            return f"{phrase} {operands[0]}"
        return phrase
    return json.dumps(node, sort_keys=True)


def _summarize_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    order: list[tuple[str, str]] = []
    for item in findings:
        marker = (str(item.get("kind", "")), str(item.get("field", "")))
        if marker not in grouped:
            grouped[marker] = {
                "kind": item.get("kind"),
                "field": item.get("field"),
                "count": 0,
                "cases": [],
                "detail": item.get("detail"),
            }
            order.append(marker)
        grouped[marker]["count"] += 1
        case_id = item.get("case")
        if case_id and case_id not in grouped[marker]["cases"]:
            grouped[marker]["cases"].append(case_id)
    return [grouped[marker] for marker in order]


def _coverage(cases: list[dict[str, Any]]) -> dict[str, int]:
    executed = sum(1 for case in cases if case.get("outcome") not in {"not_run", "unsupported"})
    omitted = sum(1 for case in cases if case.get("outcome") == "not_run")
    return {"executed": executed, "omitted": omitted, "total": len(cases)}


def _auth_issuer_given_name(claim: Any) -> str | None:
    for entry in claim.document.get("require", []):
        if entry.get("assert") != AUTH_OPERATION:
            continue
        issuer_operand = entry.get("args", {}).get("issuer", {})
        if isinstance(issuer_operand, dict) and "given" in issuer_operand:
            return issuer_operand["given"]
    return None


def _attribute_definitions(claim: Any) -> dict[str, str]:
    definitions: dict[str, str] = {}
    for alias, spec in claim.document.get("attributes", {}).items():
        path = spec.get("path", [])
        if isinstance(path, list) and len(path) == 1 and isinstance(path[0], str):
            definitions[alias] = path[0]
    return definitions


def _decode_presentation(token: str) -> bytes:
    if not isinstance(token, str):
        raise ProviderError("malformed", "invalid presentation encoding")
    if token and not all(
        char in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for char in token
    ):
        raise ProviderError("malformed", "invalid presentation encoding")
    padded = token + "=" * (-len(token) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ProviderError("malformed", str(exc)) from exc


def _harness_permitted_projection(claim: Any, plan_case: Any) -> dict[str, Any] | None:
    projection: dict[str, Any] = {
        "acceptance": bool(plan_case.expected_verdict),
        "profile": "swiyu.semantic-reference.v0",
        "statement_digest": claim.statement_digest,
    }
    release = claim.document.get("release", {})
    if "claim.context@1" in release.get("protocol_derived", []):
        digest = expected_transcript(claim, plan_case.given).hex()
        projection["protocol_derived_digest"] = digest
        projection["presentation_context"] = digest

    issuer_name = _auth_issuer_given_name(claim)
    if issuer_name is None:
        return None
    issuer = plan_case.given.get(issuer_name)
    if not isinstance(issuer, dict):
        return None
    credential_id = claim.document["credential"]["id"]
    try:
        authenticated = authenticate(
            plan_case.fixture["credential"],
            issuer,
            _attribute_definitions(claim),
        )
    except CredentialError:
        return None
    projection[f"{credential_id}.issuer"] = authenticated.issuer_id
    projection[f"{credential_id}.key_id"] = authenticated.key_id
    projection[f"{credential_id}.credential_type"] = authenticated.credential_type
    return projection


def _privacy_status(findings: list[dict[str, Any]], unknown_codec: int, pair_statuses: list[str]) -> str:
    if findings:
        return "findings"
    if unknown_codec or any(status == "not_run" for status in pair_statuses):
        return "not_run"
    if any(status == "findings" for status in pair_statuses):
        return "findings"
    if any(status == "inconclusive" for status in pair_statuses):
        return "inconclusive"
    return "clean"


def _render_campaign_html(report: dict[str, Any]) -> str:
    rows = []
    for case in report.get("cases", []):
        cls = case.get("outcome", "unknown")
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(case.get('id', '')))}</td>"
            f"<td>{html.escape(str(case.get('recipe', '')))}</td>"
            f"<td>{html.escape(str(case.get('expected_verdict', '')))}</td>"
            f"<td>{html.escape(str(case.get('observed_verified', '')))}</td>"
            f"<td class='{html.escape(cls)}'>{html.escape(cls)}</td>"
            f"<td>{html.escape(str(case.get('stage', '')))}</td>"
            "</tr>"
        )
    privacy = report.get("privacy", {})
    privacy_rows = []
    for finding in privacy.get("findings", []):
        cases = finding.get("cases") or []
        refs = f" (cases: {html.escape(', '.join(str(c) for c in cases))})" if cases else ""
        count = finding.get("count", 1)
        privacy_rows.append(
            "<li>"
            f"{html.escape(str(finding.get('kind', '')))} / "
            f"{html.escape(str(finding.get('field', '')))} × {html.escape(str(count))}"
            f"{refs}"
            "</li>"
        )
    pair_rows = []
    for pair in privacy.get("pairs", []):
        pair_rows.append(
            "<li>"
            f"{html.escape(str(pair.get('left_id', '')))} ↔ "
            f"{html.escape(str(pair.get('right_id', '')))}: "
            f"eligibility={html.escape(str(pair.get('eligibility', '')))}, "
            f"status={html.escape(str(pair.get('status', '')))}, "
            f"raw_lengths={html.escape(str(pair.get('raw_lengths', '')))}, "
            f"field_counts={html.escape(str(pair.get('field_counts', '')))}"
            "</li>"
        )
    claim = report.get("claim", {})
    timings = report.get("stage_timings", {})
    timing_items = "".join(
        f"<li>{html.escape(str(name))}: {html.escape(str(value))} milliseconds</li>"
        for name, value in timings.items()
    )
    if not timing_items:
        timing_items = "<li>no stage timings recorded (milliseconds)</li>"
    identities = "".join(
        f"<li>{html.escape(label)}: {html.escape(str(report.get(key, '')))}</li>"
        for label, key in (
            ("statement", "statement_identity"),
            ("implementation", "implementation_identity"),
            ("campaign", "campaign_identity"),
        )
    )
    coverage = report.get("coverage") or privacy.get("coverage") or _coverage(report.get("cases", []))
    condition = html.escape(_render_condition(claim.get("where")))
    raw_where = html.escape(json.dumps(claim.get("where"), indent=2))
    functional = html.escape(str(report.get("overall", "")))
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Claim campaign report</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;max-width:70rem;}}
table{{border-collapse:collapse;width:100%;}}
th,td{{border:1px solid #ccc;padding:.4rem;text-align:left;}}
.passed{{background:#e8f5e9;}}.failed{{background:#ffebee;}}
.provider_error{{background:#fff3e0;}}
.disclaimer{{color:#666;font-size:.9rem;margin:1rem 0;}}
.condition{{font-size:1.05rem;line-height:1.5;}}
details{{margin:1rem 0;}}
</style></head><body>
<h1>Claim campaign report</h1>
<p class="disclaimer">Desktop test-only harness. Functional overall reflects verifier outcomes only; privacy findings are reported separately and do not imply confidentiality or ZK support.</p>
<p><strong>Functional result</strong>: {functional}</p>
<p><strong>Coverage</strong> (executed/omitted): {coverage.get("executed", 0)}/{coverage.get("omitted", 0)}</p>
<h2>Claim</h2>
<p>Mandatory guards: {html.escape(", ".join(claim.get("require", [])))}</p>
<p class="condition">{condition}</p>
<details><summary>Full condition definition</summary>
<pre>{raw_where}</pre>
</details>
<p>Given inputs: {html.escape(", ".join(claim.get("given_inputs", [])))}</p>
<h2>Stage timings</h2>
<ul>{timing_items}</ul>
<h2>Cases</h2>
<table><thead><tr><th>ID</th><th>Recipe</th><th>Expected</th><th>Observed</th><th>Outcome</th><th>Stage</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<h2>Privacy</h2>
<p>Status: {html.escape(str(privacy.get('status', '')))}</p>
<ul>{''.join(privacy_rows)}</ul>
<h3>Pairs</h3>
<ul>{''.join(pair_rows) if pair_rows else "<li>none</li>"}</ul>
<details><summary>Identities</summary>
<ul>{identities}</ul>
</details>
</body></html>"""


def _campaign_identity(claim: Any, planned: list[Any], *, seed: int, max_cases: int) -> str:
    hasher = hashlib.sha256()
    hasher.update(claim.statement_digest.encode("ascii"))
    for source in (
        Path(__file__),
        SEMANTICS / "semantics" / "planner.py",
        SEMANTICS / "semantics" / "leakage.py",
        SEMANTICS / "semantics" / "fixtures.py",
        SEMANTICS / "semantics" / "support.py",
        ROOT / "zkbench.py",
    ):
        hasher.update(source.read_bytes())
    hasher.update(str(seed).encode())
    hasher.update(str(max_cases).encode())
    hasher.update(sys.version.encode())
    hasher.update(sys.version_info[:3].__repr__().encode())
    for case in planned:
        hasher.update(case.id.encode())
        hasher.update(case.recipe.encode())
        hasher.update(case.expectation_basis.encode())
        hasher.update(b"1" if case.expected_verdict else b"0")
        if case.expectation_basis != "not_run":
            hasher.update(hashlib.sha256(canonical_json_bytes(case.fixture)).digest())
            hasher.update(hashlib.sha256(canonical_json_bytes(case.given)).digest())
    return hasher.hexdigest()


@contextmanager
def _launching_interpreter_on_path():
    bindir = str(Path(sys.executable).parent)
    previous = os.environ.get("PATH", "")
    os.environ["PATH"] = bindir + os.pathsep + previous
    try:
        yield
    finally:
        os.environ["PATH"] = previous


def _harness_stage(verified: Any, *, refused: bool = False) -> str:
    if refused:
        return "refusal"
    if verified is True:
        return "accepted"
    return "verifier_reject"


def run_claims_demo(
    *,
    claim_path: str,
    output: str,
    inject_accept_all: bool = False,
    inject_leak: bool = False,
    max_cases: int = 64,
    manifest_path: str | None = None,
    support_path: str | None = None,
) -> tuple[int, dict[str, Any]]:
    out_dir = _safe_output_dir(output)
    claim = load_claim(claim_path)
    manifest = Path(manifest_path) if manifest_path else REFERENCE_MANIFEST
    support_file = Path(support_path) if support_path else REFERENCE_SUPPORT
    support = load_support(support_file)
    verify_claim_supported(
        support,
        claim_id=claim.document["id"],
        statement_digest=claim.statement_digest,
        claim=claim,
    )

    inject_mode = None
    if inject_accept_all:
        inject_mode = "accept-all"
    elif inject_leak:
        inject_mode = "inject-leak"

    planned = plan_campaign_cases(claim, seed=1, max_cases=max_cases)
    if not planned:
        raise RuntimeError("no constructible campaign cases")

    cases_out: list[dict[str, Any]] = []
    privacy_findings: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    unknown_codec = 0
    unavailable_projection = 0
    release = claim.document.get("release", {})
    timings = {name: 0.0 for name in ("initialize", "prepare", "present", "verify", "cleanup")}
    statement_identity = claim.statement_digest
    impl_identity = implementation_digest(support, manifest)
    campaign_id = _campaign_identity(claim, planned, seed=1, max_cases=max_cases)

    e2e_start = time.perf_counter()
    with _launching_interpreter_on_path():
        with ProviderClient(str(manifest), timeout=15.0) as client:
            t0 = time.perf_counter()
            client.call("initialize", {})
            timings["initialize"] += time.perf_counter() - t0
            for plan_case in planned:
                if plan_case.expectation_basis == "not_run":
                    cases_out.append(
                        {
                            "id": plan_case.id,
                            "recipe": plan_case.recipe,
                            "expectation_basis": plan_case.expectation_basis,
                            "expected_verdict": plan_case.expected_verdict,
                            "observed_verified": None,
                            "stage": "not_run",
                            "outcome": "not_run",
                            "detail": plan_case.reference_outcome.get("reason", "not_run"),
                            "elapsed_ms": 0,
                        }
                    )
                    continue
                observed = None
                stage = "verifier_reject"
                outcome = "failed"
                detail = ""
                try:
                    t0 = time.perf_counter()
                    prep = client.call(
                        "prepare",
                        {
                            "profile": "swiyu.semantic-reference.v0",
                            "statement_digest": claim.statement_digest,
                            "fixture": plan_case.fixture,
                            "given": plan_case.given,
                            "release": release,
                            "inject_mode": inject_mode,
                        },
                    )
                    timings["prepare"] += time.perf_counter() - t0
                    t0 = time.perf_counter()
                    pres = client.call(
                        "present",
                        {
                            "profile": "swiyu.semantic-reference.v0",
                            "handle": prep["handle"],
                        },
                    )
                    timings["present"] += time.perf_counter() - t0
                    raw = _decode_presentation(pres["presentation"])
                    derived = expected_transcript(claim, plan_case.given).hex()
                    projection = _harness_permitted_projection(claim, plan_case)
                    if projection is None:
                        unavailable_projection += 1
                    leak = analyze_presentation_leakage(
                        raw_bytes=raw,
                        release=release,
                        expected_derived_digest=derived,
                        expected_given=plan_case.given,
                        permitted_projection=projection,
                    )
                    codec_unknown = leak.get("status") == "not_run"
                    if codec_unknown:
                        unknown_codec += 1
                    for finding in leak.get("findings") or []:
                        tagged = dict(finding)
                        tagged["case"] = plan_case.id
                        privacy_findings.append(tagged)
                    t0 = time.perf_counter()
                    ver = client.call(
                        "verify",
                        {
                            "profile": "swiyu.semantic-reference.v0",
                            "presentation": pres["presentation"],
                            "claim_path": str(Path(claim_path).resolve()),
                            "given": plan_case.given,
                            "inject_mode": inject_mode,
                        },
                    )
                    timings["verify"] += time.perf_counter() - t0
                    observed = ver.get("verified")
                    stage = _harness_stage(observed)
                    expected_functional = plan_case.expected_verdict
                    if observed is expected_functional:
                        outcome = "passed"
                    else:
                        outcome = "failed"
                    detail = "functional reference evaluation"
                    if not codec_unknown:
                        observations.append(
                            {
                                "id": plan_case.id,
                                "raw_bytes": raw,
                                "given": plan_case.given,
                                "outcome": observed,
                                "permitted_projection": projection,
                                "release": release,
                                "stage": stage,
                                "statement_identity": statement_identity,
                            }
                        )
                except ProviderError as exc:
                    if getattr(exc, "status", None) == "unsupported" or "unsupported" in str(exc):
                        stage = "refusal"
                        outcome = "unsupported"
                    else:
                        stage = "provider_error"
                        outcome = "provider_error"
                    detail = str(exc)
                cases_out.append(
                    {
                        "id": plan_case.id,
                        "recipe": plan_case.recipe,
                        "expectation_basis": plan_case.expectation_basis,
                        "expected_verdict": plan_case.expected_verdict,
                        "observed_verified": observed,
                        "stage": stage,
                        "outcome": outcome,
                        "detail": detail,
                    }
                )
            t0 = time.perf_counter()
            client.call("cleanup", {})
            timings["cleanup"] += time.perf_counter() - t0
    timings["e2e"] = time.perf_counter() - e2e_start

    pair_records: list[dict[str, Any]] = []
    pair_statuses: list[str] = []
    ineligible_count = 0
    for left, right in combinations(observations, 2):
        compared = analyze_pair(left=left, right=right)
        compared["left_id"] = left["id"]
        compared["right_id"] = right["id"]
        compared.pop("raw_bytes", None)
        if compared.get("eligibility") == "eligible":
            pair_records.append(compared)
            pair_statuses.append(str(compared.get("status")))
            for finding in compared.get("findings") or []:
                tagged = dict(finding)
                tagged["case"] = f"{left['id']}+{right['id']}"
                privacy_findings.append(tagged)
        else:
            ineligible_count += 1

    summarized = _summarize_findings(privacy_findings)
    coverage = _coverage(cases_out)
    coverage["unknown_codec"] = unknown_codec
    coverage["unavailable_projection"] = unavailable_projection
    privacy_status = _privacy_status(summarized, unknown_codec, pair_statuses)
    overall = _functional_overall(cases_out)
    report = {
        "run_id": str(uuid.uuid4()),
        "overall": overall,
        "overall_note": "functional verifier outcomes only; privacy reported separately",
        "statement_identity": statement_identity,
        "implementation_identity": impl_identity,
        "campaign_identity": campaign_id,
        "stage_timings": {key: round(value * 1000, 2) for key, value in timings.items()},
        "claim": {
            "id": claim.document["id"],
            "statement_digest": claim.statement_digest,
            "where": claim.document.get("where"),
            "require": [entry["id"] for entry in claim.document.get("require", [])],
            "given_inputs": sorted(claim.document.get("given", {}).keys()),
        },
        "cases": cases_out,
        "coverage": coverage,
        "privacy": {
            "status": privacy_status,
            "findings": summarized,
            "pairs": pair_records,
            "ineligible_count": ineligible_count,
            "coverage": coverage,
            "timing_stats": {"status": "not_run", "reason": "timing stats not implemented"},
        },
        "metrics": {
            "label": "desktop/test-only — not a production security or ZK benchmark",
            "case_count": len(cases_out),
            "topology": "localhost/test-only",
        },
    }
    _atomic_write(out_dir / "report.json", json.dumps(report, indent=2))
    _atomic_write(out_dir / "report.html", _render_campaign_html(report))
    exit_code = 0
    if inject_accept_all:
        exit_code = 1
    elif overall != "passed":
        exit_code = 1
    return exit_code, report

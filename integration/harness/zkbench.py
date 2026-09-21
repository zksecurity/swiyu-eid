#!/usr/bin/env python3
"""Local integration harness runner CLI (T20 subset)."""
import argparse
import json
import os
import subprocess
import sys
import time
import uuid

from manifest import ManifestError, load_manifest
from provider_client import ProviderClient, ProviderError
from report import render_html_report, render_provider_report

try:
    from claim_campaign import run_claims_demo
except ImportError:  # pragma: no cover
    run_claims_demo = None

ROOT = os.path.dirname(os.path.abspath(__file__))
PROVIDERS_ROOT = os.path.abspath(os.path.join(ROOT, "..", "providers"))
DEFAULT_STUB = os.path.join(PROVIDERS_ROOT, "test-stub", "manifest.json")

ADULT = json.dumps({"birthdate": "2000-06-15", "holder": "alice"})
UNDERAGE = json.dumps({"birthdate": "2015-03-01", "holder": "bob"})


def cmd_check(manifest_path: str) -> int:
    try:
        m = load_manifest(manifest_path)
        print(f"ok: {m['id']} ({m['kind']}) profiles={m['profiles']}")
        return 0
    except ManifestError as exc:
        print(f"manifest error: {exc}", file=sys.stderr)
        return 1


def cmd_call(manifest_path: str, operation: str, input_path: str) -> int:
    with open(input_path, encoding="utf-8") as f:
        payload = json.load(f)
    try:
        with ProviderClient(manifest_path) as client:
            result = client.call(operation, payload)
        print(json.dumps({"status": "ok", "result": result}, indent=2))
        return 0
    except (ManifestError, ProviderError) as exc:
        print(json.dumps({"status": "error", "message": str(exc)}), file=sys.stderr)
        return 1


def _run_flow(client: ProviderClient, cred: str, nonce: str, audience: str, cutoff: str):
    timings: dict[str, float] = {}
    t0 = time.perf_counter()
    client.call("initialize", {})
    timings["initialize_ms"] = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    prep = client.call("prepare", {
        "profile": "swiyu-test-age18-v0",
        "credential": {"format": "dc+sd-jwt", "data": cred},
        "context": {},
    })
    timings["prepare_ms"] = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    pres = client.call("present", {
        "profile": "swiyu-test-age18-v0",
        "handle": prep["handle"],
        "request_context": {"nonce": nonce, "audience": audience},
        "inputs": {},
    })
    timings["present_ms"] = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    ver = client.call("verify", {
        "profile": "swiyu-test-age18-v0",
        "presentation": pres["presentation"],
        "request_context": {"nonce": nonce, "audience": audience},
        "inputs": {"cutoff_date": cutoff},
    })
    timings["verify_ms"] = (time.perf_counter() - t0) * 1000
    if not isinstance(ver.get("verified"), bool):
        raise ProviderError("malformed", "verified must be boolean")

    t0 = time.perf_counter()
    client.call("cleanup", {})
    timings["cleanup_ms"] = (time.perf_counter() - t0) * 1000

    elapsed = (
        timings["initialize_ms"]
        + timings["prepare_ms"]
        + timings["present_ms"]
        + timings["verify_ms"]
        + timings["cleanup_ms"]
    )
    return ver, elapsed, timings


def _write_inject_crash_provider(tmpdir: str) -> str:
    d = os.path.join(tmpdir, "inject-crash-prov")
    os.makedirs(d, exist_ok=True)
    manifest = {
        "schema": "swiyu.provider-manifest.v1",
        "id": "inject-crash-prov",
        "title": "Inject Crash",
        "kind": "test-only",
        "profiles": ["p"],
        "command": [sys.executable, "-c", "import sys; sys.exit(1)"],
    }
    with open(os.path.join(d, "manifest.json"), "w") as f:
        json.dump(manifest, f)
    return os.path.join(d, "manifest.json")


def _overall_result(cases: list[dict]) -> str:
    outcomes = {c["outcome"] for c in cases}
    if outcomes and outcomes <= {"not_run"}:
        return "not_run"
    if outcomes <= {"passed"}:
        return "passed"
    if "provider_error" in outcomes:
        return "provider_error"
    return "failed"


_BENCHMARK_STAGES = (
    "provider_startup", "initialize", "prepare", "witness", "prove",
    "present", "verify", "cleanup",
)


def _measurement(status: str = "not_run", elapsed_ms: float | None = None) -> dict:
    return {
        "status": status,
        "elapsed_ms": round(elapsed_ms, 3) if elapsed_ms is not None else None,
    }



def _deepcopy_json(value):
    return json.loads(json.dumps(value))


def _resolve_manifest_local_path(manifest: dict, rel_path: str) -> str:
    if not isinstance(rel_path, str) or not rel_path:
        raise ProviderError("fixture", "provider_run_fixture must be a non-empty path")
    manifest_dir = os.path.abspath(manifest["_manifest_dir"])
    target = os.path.abspath(os.path.join(manifest_dir, rel_path))
    if target != manifest_dir and not target.startswith(manifest_dir + os.sep):
        raise ProviderError("fixture", "provider_run_fixture escapes provider directory")
    if not os.path.isfile(target):
        raise ProviderError("fixture", f"provider_run_fixture not found: {rel_path}")
    return target


def _load_provider_run_fixture(manifest: dict) -> dict | None:
    source = manifest.get("source")
    if not isinstance(source, dict):
        return None
    fixture_rel = source.get("provider_run_fixture")
    if not fixture_rel:
        return None
    fixture_path = _resolve_manifest_local_path(manifest, fixture_rel)
    if fixture_path.endswith(".json"):
        with open(fixture_path, encoding="utf-8") as stream:
            fixture = json.load(stream)
    elif fixture_path.endswith((".mjs", ".js")):
        completed = subprocess.run(
            ["node", fixture_path],
            cwd=manifest["_manifest_dir"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        fixture = json.loads(completed.stdout)
    else:
        raise ProviderError("fixture", "provider_run_fixture must be .json, .js, or .mjs")
    if not isinstance(fixture, dict):
        raise ProviderError("fixture", "provider_run_fixture must produce a JSON object")
    if fixture.get("schema") != "swiyu.provider-run-fixture.v1":
        raise ProviderError("fixture", "unsupported provider_run_fixture schema")
    return fixture


def _operation_status_ready(operation: str, advertised: list, readiness: dict) -> bool:
    entry = readiness.get(operation)
    if isinstance(entry, dict):
        return entry.get("status") in {"implemented", "ready"}
    return operation in advertised


def _fixture_payload(fixture: dict, key: str) -> dict:
    payload = fixture.get(key)
    if not isinstance(payload, dict):
        raise ProviderError("fixture", f"provider fixture missing object payload: {key}")
    return _deepcopy_json(payload)


def _record_presentation_artifacts(report: dict, presented: dict) -> None:
    presentation = presented["presentation"]
    sizes = report["artifacts"]["sizes_bytes"]
    sizes["presentation"] = len(presentation.encode("utf-8"))
    artifact_sizes = presented.get("artifact_sizes")
    if not isinstance(artifact_sizes, dict):
        return
    for name in ("witness", "proof"):
        value = artifact_sizes.get(name)
        if isinstance(value, int) and value > 0:
            sizes[name] = value


def _run_provider_fixture_flow(
    client: ProviderClient,
    fixture: dict,
    profile: str,
    timed,
    stages: dict,
    report: dict,
) -> None:
    if fixture.get("profile") != profile:
        raise ProviderError("fixture", "provider fixture profile does not match manifest profile")
    prepared = timed("prepare", lambda: client.call("prepare", _fixture_payload(fixture, "prepare")))
    present_payload = _fixture_payload(fixture, "present")
    present_payload["handle"] = prepared["handle"]
    presented = timed("present", lambda: client.call("present", present_payload, timeout=180.0))
    presentation = presented["presentation"]
    _record_presentation_artifacts(report, presented)
    if stages["witness"]["status"] == "not_run":
        stages["witness"] = _measurement("covered_by_present")
    if stages["prove"]["status"] == "not_run":
        stages["prove"] = _measurement("covered_by_present")
    verify_payload = _fixture_payload(fixture, "verify")
    verify_payload["presentation"] = presentation
    verified = timed("verify", lambda: client.call("verify", verify_payload, timeout=180.0))
    valid_passed = verified.get("verified") is True
    report["cases"].append({
        "name": fixture.get("case_name", "fixture_lifecycle"),
        "outcome": "passed" if valid_passed else "failed",
        "detail": "provider completed the declared profile fixture" if valid_passed else "provider rejected the declared profile fixture",
    })
    negative = fixture.get("negative_verify")
    if isinstance(negative, dict):
        negative_payload = _deepcopy_json(negative.get("payload"))
        if not isinstance(negative_payload, dict):
            raise ProviderError("fixture", "negative_verify.payload must be an object")
        negative_payload["presentation"] = presentation
        rejected = client.call("verify", negative_payload, timeout=180.0)
        expected = negative.get("expected_verified", False)
        passed = rejected.get("verified") is expected
        report["cases"].append({
            "name": str(negative.get("name", "negative_verify")),
            "outcome": "passed" if passed else "failed",
            "detail": "negative fixture produced the expected verifier result" if passed else "negative fixture did not produce the expected verifier result",
            "expected": f"verified={expected}",
            "observed": f"verified={rejected.get('verified')}",
        })



def _manifest_circuits(manifest: dict) -> set[str]:
    circuits: set[str] = set()
    for item in manifest.get("circuits", []):
        if isinstance(item, str):
            circuits.add(item)
    source = manifest.get("source")
    if isinstance(source, dict):
        for key in ("circuit", "circuit_id", "native_circuit"):
            value = source.get(key)
            if isinstance(value, str) and value:
                circuits.add(value)
    return circuits


def _validate_support_for_report(
    support_path: str | None,
    profiles: list[str],
    circuits: set[str],
) -> dict:
    if not support_path:
        return {"status": "not_provided", "claims": []}
    semantics_root = os.path.abspath(os.path.join(ROOT, "..", "semantics"))
    if semantics_root not in sys.path:
        sys.path.insert(0, semantics_root)
    try:
        from semantics.claims import load_claim
        from semantics.support import SupportError, load_support, verify_claim_supported
    except ImportError as exc:  # pragma: no cover - depends on caller environment
        return {"status": "failed", "error": f"semantics package unavailable: {exc}", "claims": []}
    try:
        support = load_support(support_path)
    except SupportError as exc:
        return {"status": "failed", "error": str(exc), "claims": []}
    claims_dir = os.path.abspath(os.path.join(semantics_root, "claims"))
    loaded_claims = []
    load_errors = []
    for name in sorted(os.listdir(claims_dir)) if os.path.isdir(claims_dir) else []:
        if not name.endswith(".json"):
            continue
        claim_path = os.path.join(claims_dir, name)
        try:
            loaded_claims.append(load_claim(claim_path))
        except Exception as exc:
            load_errors.append({"id": name, "status": "failed", "detail": f"claim load failed: {exc}", "path": claim_path})
    results = list(load_errors)
    overall = "failed" if load_errors else "passed"
    for entry in support.get("supported_claims", []):
        claim_id = entry.get("id")
        digest = entry.get("statement_digest")
        matching = [
            claim for claim in loaded_claims
            if not isinstance(claim, dict) and claim.document.get("id") == claim_id
        ]
        if not matching:
            results.append({"id": claim_id, "status": "failed", "detail": "claim file not found"})
            overall = "failed"
            continue
        claim = matching[0]
        if claim.statement_digest != digest:
            results.append({
                "id": claim_id,
                "status": "failed",
                "detail": "support statement_digest does not match loaded claim",
                "support_digest": digest,
                "claim_digest": claim.statement_digest,
            })
            overall = "failed"
            continue
        try:
            verify_claim_supported(
                support,
                claim_id=claim_id,
                statement_digest=claim.statement_digest,
                claim=claim,
                implementation_profile=entry.get("implementation_profile"),
                circuit=entry.get("circuit"),
            )
        except SupportError as exc:
            results.append({"id": claim_id, "status": "failed", "detail": str(exc)})
            overall = "failed"
            continue
        profile_status = "not_declared"
        if entry.get("implementation_profile"):
            profile_status = "matched" if entry.get("implementation_profile") in profiles else "profile_not_in_manifest"
            if profile_status != "matched":
                overall = "failed"
        circuit_status = "not_declared"
        if entry.get("circuit"):
            circuit_status = "matched" if entry.get("circuit") in circuits else "circuit_not_in_manifest"
            if circuit_status != "matched":
                overall = "failed"
        results.append({
            "id": claim_id,
            "statement_digest": claim.statement_digest,
            "implementation_profile": entry.get("implementation_profile"),
            "circuit": entry.get("circuit"),
            "status": "passed" if profile_status == "matched" and circuit_status in {"matched", "not_declared"} else "failed",
            "profile_status": profile_status,
            "circuit_status": circuit_status,
        })
    return {"status": overall, "claims": results}


def _readiness_value(operation: str, advertised: list, readiness: dict) -> str:
    entry = readiness.get(operation)
    if isinstance(entry, dict):
        status = str(entry.get("status", "unknown"))
        reason = entry.get("reason")
        return f"{status}: {reason}" if reason else status
    return "ready" if operation in advertised else "not_advertised"


def _apply_support_overall(report: dict) -> None:
    status = report.get("support", {}).get("status")
    if status == "failed":
        report["cases"].append({
            "name": "semantic_support",
            "outcome": "failed",
            "detail": "semantic support admission failed",
        })
        report["overall"] = "failed"


def cmd_provider_run(
    manifest_path: str,
    output: str,
    support: str | None = None,
    privacy_report: str | None = None,
) -> int:
    """Run a provider smoke flow and always emit reviewable report artifacts."""
    os.makedirs(output, exist_ok=True)
    absolute_manifest = os.path.abspath(manifest_path)
    stages = {stage: _measurement() for stage in _BENCHMARK_STAGES}
    report = {
        "schema": "swiyu.provider-report.v1",
        "run_id": str(uuid.uuid4()),
        "overall": "provider_error",
        "provider": {
            "id": "unknown", "title": "Unknown provider", "kind": "unknown",
            "profiles": [], "manifest_path": absolute_manifest,
            "support_path": os.path.abspath(support) if support else None,
        },
        "support": {"status": "pending" if support else "not_provided", "claims": []},
        "operation_readiness": {
            op: "unknown" for op in ("initialize", "prepare", "present", "verify", "cleanup")
        },
        "benchmark": {
            "schema": "swiyu.benchmark.v1",
            "environment": "local",
            "note": "Wall-clock integration measurements; heavy cryptographic stages remain not_run until supplied by a provider run.",
            "stages": stages,
        },
        "artifacts": {"sizes_bytes": {"witness": None, "proof": None, "presentation": None}},
        "cases": [],
        "leakage": {
            "schema": "swiyu.differential-leakage.v1", "status": "not_run",
            "summary": "No differential claim campaign was supplied.", "findings": [], "pairs": [],
        },
    }
    if privacy_report:
        privacy_path = os.path.abspath(privacy_report)
        try:
            with open(privacy_path, encoding="utf-8") as f:
                source_report = json.load(f)
            privacy = source_report.get("privacy", {})
            status = privacy.get("status")
            if status not in {"clean", "findings", "inconclusive", "not_run"}:
                raise ValueError(f"unknown privacy status: {status}")
            leakage = {
                "schema": "swiyu.differential-leakage.v1",
                "status": status,
                "summary": privacy.get("summary") or "Imported from a claim campaign privacy summary.",
                "findings": privacy.get("findings", []),
                "pairs": privacy.get("pairs", []),
                "coverage": privacy.get("coverage", {}),
                "source_path": privacy_path,
            }
            if source_report.get("schema") == "swiyu.privacy-campaign.v1":
                if source_report.get("provider", {}).get("id") != load_manifest(absolute_manifest).get("id"):
                    raise ValueError("privacy campaign belongs to a different provider")
            for optional_key in ("detector_controls", "matrix", "observations", "method", "cases"):
                if optional_key in privacy:
                    leakage[optional_key] = privacy[optional_key]
            report["leakage"] = leakage
        except (OSError, ValueError, TypeError, json.JSONDecodeError, ManifestError) as exc:
            report["leakage"] = {
                "schema": "swiyu.differential-leakage.v1",
                "status": "inconclusive",
                "summary": f"Could not import privacy report: {exc}",
                "findings": [], "pairs": [], "source_path": privacy_path,
            }

    def timed(stage: str, fn):
        started = time.perf_counter()
        try:
            value = fn()
        except Exception:
            stages[stage] = _measurement("failed", (time.perf_counter() - started) * 1000)
            raise
        stages[stage] = _measurement("completed", (time.perf_counter() - started) * 1000)
        return value

    try:
        manifest = load_manifest(absolute_manifest)
        report["provider"].update({
            key: manifest[key] for key in ("id", "title", "kind", "profiles")
        })
        report["support"] = _validate_support_for_report(
            support,
            manifest["profiles"],
            _manifest_circuits(manifest),
        )
        profile = manifest["profiles"][0]
        started = time.perf_counter()
        with ProviderClient(
            absolute_manifest,
            timeout=180.0,
            max_output_bytes=4 * 1024 * 1024,
            max_input_bytes=4 * 1024 * 1024,
        ) as client:
            stages["provider_startup"] = _measurement(
                "completed", (time.perf_counter() - started) * 1000
            )
            initialized = timed("initialize", lambda: client.call("initialize", {}))
            advertised = initialized.get("operations", [])
            advertised_profiles = initialized.get("profiles", [])
            provider_readiness = initialized.get("operationReadiness", {})
            report["artifacts"]["readiness"] = initialized.get("artifacts")
            for operation in report["operation_readiness"]:
                report["operation_readiness"][operation] = _readiness_value(
                    operation,
                    advertised,
                    provider_readiness if isinstance(provider_readiness, dict) else {},
                )
            if profile not in advertised_profiles:
                raise ProviderError("profile_mismatch", "manifest profile not advertised by initialize")
            fixture = _load_provider_run_fixture(manifest)
            if profile == "swiyu-test-age18-v0":
                prepared = timed("prepare", lambda: client.call("prepare", {
                    "profile": profile,
                    "credential": {"format": "dc+sd-jwt", "data": ADULT},
                    "context": {},
                }))
                presented = timed("present", lambda: client.call("present", {
                    "profile": profile, "handle": prepared["handle"],
                    "request_context": {"nonce": "provider-run", "audience": "zkbench"},
                    "inputs": {},
                }))
                presentation = presented["presentation"]
                _record_presentation_artifacts(report, presented)
                verified = timed("verify", lambda: client.call("verify", {
                    "profile": profile, "presentation": presentation,
                    "request_context": {"nonce": "provider-run", "audience": "zkbench"},
                    "inputs": {"cutoff_date": "2024-01-01"},
                }))
                outcome = "passed" if verified.get("verified") is True else "failed"
                report["cases"].append({
                    "name": "valid_presentation", "outcome": outcome,
                    "detail": "provider accepted a challenge-bound adult presentation" if outcome == "passed" else "provider did not verify the smoke presentation",
                })
            elif fixture and all(
                _operation_status_ready(operation, advertised, provider_readiness if isinstance(provider_readiness, dict) else {})
                for operation in ("prepare", "present", "verify")
            ):
                report["benchmark"]["note"] = (
                    "Wall-clock integration measurements from the declared provider fixture. "
                    "Witness/prove are marked covered_by_present when the provider exposes them as part of present."
                )
                _run_provider_fixture_flow(client, fixture, profile, timed, stages, report)
            else:
                detail = "no generic fixture is defined for this provider profile"
                if fixture:
                    detail = "provider fixture exists, but prepare/present/verify are not all ready"
                report["cases"].append({
                    "name": "lifecycle_smoke", "outcome": "not_run",
                    "detail": detail,
                })
            timed("cleanup", lambda: client.call("cleanup", {}))
        report["overall"] = _overall_result(report["cases"])
        _apply_support_overall(report)
    except (ManifestError, ProviderError, KeyError, TypeError) as exc:
        report["cases"].append({
            "name": "provider_conformance", "outcome": "provider_error", "detail": str(exc),
        })
        report["overall"] = "provider_error"

    with open(os.path.join(output, "provider-report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    with open(os.path.join(output, "provider-report.html"), "w", encoding="utf-8") as f:
        f.write(render_provider_report(report))
    print(f"provider report written to {output} (overall={report['overall']})")
    return 0 if report["overall"] in {"passed", "not_run"} else 1


def cmd_demo(output: str, inject_crash: bool = False) -> int:
    os.makedirs(output, exist_ok=True)
    run_id = str(uuid.uuid4())
    cases: list[dict] = []
    metrics: dict = {
        "run_id": run_id,
        "label": "desktop/test-only — illustrative wall-clock timings, not a crypto or OpenAC benchmark",
    }

    def record(name, outcome, detail, elapsed_ms=None, expected=None, observed=None):
        entry = {
            "name": name,
            "outcome": outcome,
            "detail": detail,
            "elapsed_ms": round(elapsed_ms, 2) if elapsed_ms is not None else None,
        }
        if expected is not None:
            entry["expected"] = expected
        if observed is not None:
            entry["observed"] = observed
        cases.append(entry)

    try:
        t_start = time.perf_counter()
        with ProviderClient(DEFAULT_STUB) as client:
            startup_ms = (time.perf_counter() - t_start) * 1000
            ver, ms, stage = _run_flow(
                client, ADULT, "demo-n1", "demo.verifier", "2024-01-01"
            )
            stage["provider_startup_ms"] = startup_ms
            metrics["valid_adult_timings"] = stage
            record(
                "valid_adult",
                "passed" if ver["verified"] is True else "failed",
                "expected acceptance",
                ms,
                expected="verified=true",
                observed=f"verified={ver['verified']}",
            )
    except ProviderError as exc:
        record("valid_adult", "provider_error", str(exc))

    try:
        t_start = time.perf_counter()
        with ProviderClient(DEFAULT_STUB) as client:
            startup_ms = (time.perf_counter() - t_start) * 1000
            ver, ms, stage = _run_flow(
                client, UNDERAGE, "demo-n2", "demo.verifier", "2024-01-01"
            )
            stage["provider_startup_ms"] = startup_ms
            metrics["underage_timings"] = stage
            record(
                "underage",
                "passed" if ver["verified"] is False else "failed",
                "expected rejection (predicate false)",
                ms,
                expected="verified=false",
                observed=f"verified={ver['verified']}",
            )
    except ProviderError as exc:
        record("underage", "provider_error", str(exc))

    try:
        with ProviderClient(DEFAULT_STUB) as client:
            client.call("initialize", {})
            prep = client.call("prepare", {
                "profile": "swiyu-test-age18-v0",
                "credential": {"format": "dc+sd-jwt", "data": ADULT},
                "context": {},
            })
            t0 = time.perf_counter()
            pres = client.call("present", {
                "profile": "swiyu-test-age18-v0",
                "handle": prep["handle"],
                "request_context": {"nonce": "bound-n", "audience": "v"},
                "inputs": {},
            })
            ver = client.call("verify", {
                "profile": "swiyu-test-age18-v0",
                "presentation": pres["presentation"],
                "request_context": {"nonce": "wrong-n", "audience": "v"},
                "inputs": {"cutoff_date": "2024-01-01"},
            })
            client.call("cleanup", {})
            ms = (time.perf_counter() - t0) * 1000
            record(
                "wrong_nonce",
                "passed" if ver["verified"] is False else "failed",
                "expected rejection (binding)",
                ms,
                expected="verified=false",
                observed=f"verified={ver['verified']}",
            )
    except ProviderError as exc:
        record("wrong_nonce", "provider_error", str(exc))

    try:
        with ProviderClient(DEFAULT_STUB) as client:
            client.call("initialize", {})
            prep = client.call("prepare", {
                "profile": "swiyu-test-age18-v0",
                "credential": {"format": "dc+sd-jwt", "data": ADULT},
                "context": {},
            })
            t0 = time.perf_counter()
            pres = client.call("present", {
                "profile": "swiyu-test-age18-v0",
                "handle": prep["handle"],
                "request_context": {"nonce": "aud-n", "audience": "expected-aud"},
                "inputs": {},
            })
            ver = client.call("verify", {
                "profile": "swiyu-test-age18-v0",
                "presentation": pres["presentation"],
                "request_context": {"nonce": "aud-n", "audience": "wrong-aud"},
                "inputs": {"cutoff_date": "2024-01-01"},
            })
            client.call("cleanup", {})
            ms = (time.perf_counter() - t0) * 1000
            record(
                "wrong_audience",
                "passed" if ver["verified"] is False else "failed",
                "expected rejection (audience binding)",
                ms,
                expected="verified=false",
                observed=f"verified={ver['verified']}",
            )
    except ProviderError as exc:
        record("wrong_audience", "provider_error", str(exc))

    if inject_crash:
        try:
            with ProviderClient(_write_inject_crash_provider(output), timeout=2.0) as client:
                client.call("initialize", {})
            record("inject_crash", "failed", "expected provider_error but succeeded")
        except ProviderError as exc:
            record(
                "inject_crash",
                "provider_error",
                str(exc),
                expected="provider_error",
                observed=exc.code,
            )

    overall = _overall_result(cases)
    result = {"run_id": run_id, "overall": overall, "cases": cases, "metrics": metrics}
    with open(os.path.join(output, "result.json"), "w") as f:
        json.dump(result, f, indent=2)
    html = render_html_report("Swiyu integration harness demo", cases, metrics)
    with open(os.path.join(output, "report.html"), "w") as f:
        f.write(html)
    print(f"demo written to {output} (overall={overall})")
    return 0 if overall == "passed" else 1


def cmd_claims_demo(
    claim: str,
    output: str,
    inject_accept_all: bool = False,
    inject_leak: bool = False,
    manifest: str | None = None,
    support: str | None = None,
    max_cases: int | None = None,
) -> int:
    if run_claims_demo is None:
        print("claim campaign module unavailable", file=sys.stderr)
        return 2
    kwargs = {
        "claim_path": claim,
        "output": output,
        "inject_accept_all": inject_accept_all,
        "inject_leak": inject_leak,
    }
    if manifest:
        kwargs["manifest_path"] = manifest
    if support:
        kwargs["support_path"] = support
    if max_cases is not None:
        kwargs["max_cases"] = max_cases
    try:
        code, report = run_claims_demo(**kwargs)
    except (ValueError, RuntimeError) as exc:
        print(f"claims-demo error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        if exc.__class__.__name__ == "SupportError":
            print(f"claims-demo error: {exc}", file=sys.stderr)
            return 1
        raise
    print(
        f"claims-demo written to {output} "
        f"(overall={report['overall']}, privacy={report['privacy']['status']})"
    )
    return code


def main() -> int:
    parser = argparse.ArgumentParser(description="Swiyu integration harness local runner")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_check = sub.add_parser("check")
    p_check.add_argument("manifest")
    p_demo = sub.add_parser("demo")
    p_demo.add_argument("--output", required=True)
    p_demo.add_argument(
        "--inject-crash",
        action="store_true",
        help="add failed-provider inject_crash case (demo then exits 1)",
    )
    p_call = sub.add_parser("call")
    p_call.add_argument("manifest")
    p_call.add_argument("operation")
    p_call.add_argument("--input", required=True)
    p_claims = sub.add_parser("claims-demo")
    p_claims.add_argument("--claim", required=True)
    p_claims.add_argument("--output", required=True)
    p_claims.add_argument("--manifest")
    p_claims.add_argument("--support")
    p_claims.add_argument("--max-cases", type=int)
    p_claims.add_argument("--inject-accept-all", action="store_true")
    p_claims.add_argument("--inject-leak", action="store_true")
    p_provider = sub.add_parser("provider-run")
    p_provider.add_argument("manifest")
    p_provider.add_argument("--output", required=True)
    p_provider.add_argument("--support")
    p_provider.add_argument("--privacy-report")
    p_provider.add_argument("--flow", choices=["oid4vp"], help="Run semantic transcript tests and stage benchmarks for the selected flow")
    p_provider.add_argument("--claim")
    p_provider.add_argument("--verifier-base")
    p_provider.add_argument("--fixture-document")
    p_provider.add_argument("--inject", default="", help="Optional detector validation: hidden_field,hash_header")
    p_provider.add_argument("--retain-private", action="store_true")
    p_shared = sub.add_parser(
        "shared-claim-run",
        help="Compare complete OID4VP transcripts of two ZK backends for the shared age-25 claim",
    )
    p_shared.add_argument("--claim", required=True)
    p_shared.add_argument("--output", required=True)
    p_shared.add_argument("--fixture-only", action="store_true")
    p_shared.add_argument("--inject", default="", help="Optional detector validation: hidden_field,hash_header")
    p_shared.add_argument("--verifier-base")
    p_shared.add_argument("--retain-private", action="store_true")
    p_privacy = sub.add_parser("privacy-run", help="Run shared integration privacy scenarios")
    privacy_source = p_privacy.add_mutually_exclusive_group(required=True)
    privacy_source.add_argument("--manifest")
    privacy_source.add_argument("--adapter", help="Local .mjs/.js/.py collector producing privacy traces")
    privacy_source.add_argument("--traces", help="Existing privacy trace JSON file")
    p_privacy.add_argument("--output", required=True)
    p_privacy.add_argument("--controls", action="store_true")
    p_privacy.add_argument("--presentations", type=int, default=0,
                           help="Manifest mode only: execute up to eight provider presentations")
    args = parser.parse_args()
    if args.cmd == "check":
        return cmd_check(args.manifest)
    if args.cmd == "demo":
        return cmd_demo(args.output, inject_crash=args.inject_crash)
    if args.cmd == "call":
        return cmd_call(args.manifest, args.operation, args.input)
    if args.cmd == "claims-demo":
        return cmd_claims_demo(
            args.claim,
            args.output,
            inject_accept_all=args.inject_accept_all,
            inject_leak=args.inject_leak,
            manifest=args.manifest,
            support=args.support,
            max_cases=args.max_cases,
        )
    if args.cmd == "provider-run":
        if args.flow:
            if not args.claim:
                parser.error("--flow requires --claim")
            if args.privacy_report:
                parser.error("--flow captures its own transcript; --privacy-report is not an input")
            try:
                from transcript_runner import run_transcript_campaign
                options = dict(support_path=args.support, retain_private=args.retain_private,
                               injections=[x.strip() for x in args.inject.split(",") if x.strip()])
                if args.verifier_base:
                    code, result = run_transcript_campaign(args.manifest, args.claim, args.output,
                        verifier_base=args.verifier_base, fixture_document_path=args.fixture_document, **options)
                else:
                    from transcript_local import run_local_campaign
                    code, result = run_local_campaign(args.manifest, args.claim, args.output, **options)
            except (ValueError, OSError, RuntimeError, ProviderError, ManifestError):
                print("Transcript campaign could not complete. Check the local runtime logs; no clean result was inferred.", file=sys.stderr)
                return 2
            print(f"Transcript report: {args.output}/report.html")
            return code
        return cmd_provider_run(
            args.manifest, args.output, support=args.support,
            privacy_report=args.privacy_report,
        )
    if args.cmd == "shared-claim-run":
        try:
            from transcript_shared import run_shared_transcript_campaign
            from semantics.support import SupportError
        except ImportError:
            print("Shared-claim transcript campaign could not complete. No clean result was inferred.", file=sys.stderr)
            return 2
        try:
            code, result = run_shared_transcript_campaign(
                args.claim,
                args.output,
                fixture_only=args.fixture_only,
                retain_private=args.retain_private,
                injections=[x.strip() for x in args.inject.split(",") if x.strip()] or None,
                verifier_base=args.verifier_base,
            )
        except (ValueError, OSError, RuntimeError, ManifestError, SupportError, ProviderError):
            print("Shared-claim transcript campaign could not complete. No clean result was inferred.", file=sys.stderr)
            return 2
        print(f"Shared-claim transcript report: {args.output}/report.html")
        return code
    if args.cmd == "privacy-run":
        from privacy_runner import execute_collector, run_privacy
        if args.presentations and not args.manifest:
            parser.error("--presentations requires --manifest")
        try:
            if args.traces and not args.traces.endswith(".json"):
                raise ValueError("trace input must be JSON")
            code, result = run_privacy(output=args.output, manifest=args.manifest,
                adapter=args.adapter, traces=execute_collector(args.traces) if args.traces else None,
                controls=args.controls, presentations=args.presentations)
        except (ValueError, OSError, ProviderError, ManifestError):
            print("Privacy campaign could not run: source invalid or unavailable. Raw provider diagnostics withheld.", file=sys.stderr)
            return 2
        print(f"Privacy report: {args.output}/privacy-report.html ({result['privacy']['status']})")
        return code
    return 2


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Same-claim OID4VP transcript campaign across EPFL d10 and OpenAC age-25."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
INTEGRATION = ROOT.parent
SEMANTICS = INTEGRATION / "semantics"
RUNTIME = INTEGRATION / "runtime"
OPENAC = INTEGRATION / "providers" / "openac"
EPFL = INTEGRATION / "providers" / "epfl"
TWO_MIB = 2 * 1024 * 1024
EPFL_TOOLCHAIN = Path("/tmp/swiyu-epfl-20260915/owned/scratch/toolchain/bin")

for path in (str(ROOT), str(SEMANTICS), str(RUNTIME), str(INTEGRATION), str(OPENAC)):
    if path not in sys.path:
        sys.path.insert(0, path)

from age25_transcript_wallet import Age25TranscriptWallet  # noqa: E402
from manifest import ManifestError, load_manifest  # noqa: E402
from provider_client import ProviderClient, ProviderError  # noqa: E402
from semantics.claims import load_claim  # noqa: E402
from semantics.support import SupportError, load_support, verify_claim_supported  # noqa: E402
from transcript.fixture_verifier import FixtureVerifier  # noqa: E402
from transcript_cross import analyze_cross_implementation  # noqa: E402
from transcript_equivalence import analyze_transcripts, classify_fixture  # noqa: E402
from transcript_local import export_runtime_logs, start_owned_java_runtime  # noqa: E402
from transcript_policy import build_cross_flow_policy, build_flow_policy  # noqa: E402
from transcript_report import render_transcript_report  # noqa: E402
from transcript_runner import (  # noqa: E402
    ENGINE_NOTE,
    _atomic_write,
    _create_body,
    _injection_material,
    _load_transcript_fixture,
    _run_one_session,
    _safe_output_dir,
    _sanitize_session,
)

SHARED_CLAIM_ID = "swiyu.shared.age25-holder-challenge.v0"


def default_backends() -> list[dict[str, Any]]:
    providers = INTEGRATION / "providers"
    return [
        {
            "id": "epfl",
            "implementation": "epfl-d10-swiyu-jwt-age25-v0",
            "circuit": "d10_swiyu_jwt",
            "manifest": providers / "epfl" / "manifest.json",
            "sidecar": providers / "epfl" / "transcript-sidecar.py",
            "proofs": "native-ultrahonk",
        },
        {
            "id": "openac",
            "implementation": "openac-age25-jwt-v0",
            "circuit": "swiyu_age25_jwt",
            "manifest": providers / "openac" / "manifest.json",
            "fixture": providers / "openac" / "transcript-fixture-age25.py",
            "sidecar": providers / "openac" / "transcript-sidecar-age25.py",
            "proofs": "openac-age25-synthetic-envelope",
        },
    ]


def prepare_epfl_native_env() -> None:
    toolchain = Path(os.environ.get("SWIYU_EPFL_TOOLCHAIN") or EPFL_TOOLCHAIN)
    os.environ.setdefault("SWIYU_EPFL_TOOLCHAIN", str(toolchain))
    os.environ.setdefault("SWIYU_EPFL_CIRCUIT_ROOT", str(EPFL / "circuit"))
    os.environ.setdefault("SWIYU_EPFL_WORK_ROOT", "/tmp/swiyu-epfl-native-shared")
    os.environ.setdefault("RAYON_NUM_THREADS", "2")
    os.environ.setdefault("HARDWARE_CONCURRENCY", "2")
    os.environ.setdefault("OMP_NUM_THREADS", "2")
    os.environ.setdefault("BB_NUM_CPUS", "2")
    current = os.environ.get("PATH", "")
    prefix = str(toolchain)
    if current.split(":")[0] != prefix:
        os.environ["PATH"] = f"{prefix}:{current}" if current else prefix


def _open_backend_wallet(item: dict[str, Any]):
    if item["id"] == "openac":
        return Age25TranscriptWallet()
    return ProviderClient(
        item["manifest"]["_manifest_path"],
        timeout=420,
        max_output_bytes=TWO_MIB,
        max_input_bytes=TWO_MIB,
    )


def _run_backend_sessions(
    *,
    item: dict[str, Any],
    base: str,
    claim_path: str,
    fixture_only: bool,
    inject_mode: str | None,
    provider,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    create_body = _create_body(item["document"], item["variants"])
    policy = build_flow_policy(item["document"])
    campaigns: list[dict[str, Any]] = []
    clean_sessions: list[dict[str, Any]] = []
    injected_sessions: list[dict[str, Any]] = []
    group = []
    for variant in item["variants"]:
        session = _run_one_session(
            base=base,
            variant=variant,
            document=item["document"],
            create_body=create_body,
            extra_fields=None,
            extra_headers=None,
            provider=provider,
            fixture_only=fixture_only,
            require_dcql=not fixture_only,
            campaign=f"clean-{item['id']}",
            claim_path=claim_path,
        )
        session["implementation"] = item["implementation"]
        session["proof_kind"] = "fixture-opaque" if fixture_only else item["proofs"]
        group.append(session)
    clean_sessions.extend(group)
    campaigns.append(
        {
            "name": f"{item['implementation']} clean A/B",
            "kind": "baseline",
            "implementation": item["implementation"],
            "report": analyze_transcripts(claim_path, group, policy),
        }
    )
    if inject_mode:
        injected = []
        for variant in item["variants"]:
            fields, headers = _injection_material(variant["credential"]["data"], inject_mode)
            session = _run_one_session(
                base=base,
                variant=variant,
                document=item["document"],
                create_body=create_body,
                extra_fields=fields,
                extra_headers=headers,
                provider=provider,
                fixture_only=fixture_only,
                require_dcql=not fixture_only,
                campaign=f"injected-{item['id']}",
                claim_path=claim_path,
            )
            session["implementation"] = item["implementation"]
            session["proof_kind"] = "fixture-opaque" if fixture_only else item["proofs"]
            injected.append(session)
        injected_sessions.extend(injected)
        campaigns.append(
            {
                "name": f"{item['implementation']} injected transport A/B",
                "kind": "injected regression",
                "implementation": item["implementation"],
                "report": analyze_transcripts(claim_path, injected, policy),
            }
        )
    return campaigns, clean_sessions, injected_sessions


def _load_backends(claim, backends: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    specs = backends or default_backends()
    loaded: list[dict[str, Any]] = []
    for spec in specs:
        manifest = load_manifest(str(spec["manifest"]))
        support = load_support(Path(manifest["_manifest_dir"]) / "support.json")
        verify_claim_supported(
            support,
            claim_id=claim.document["id"],
            statement_digest=claim.statement_digest,
            claim=claim,
            implementation_profile=spec["implementation"],
            circuit=spec["circuit"],
        )
        document = _load_transcript_fixture(manifest, str(spec["fixture"]) if spec.get("fixture") else None)
        variants = document["variants"]
        if len(variants) < 2:
            raise ManifestError(f"{spec['id']} transcript fixture must provide at least two variants")
        for variant in variants:
            classification = classify_fixture(
                os.environ["SWIYU_TRANSCRIPT_CLAIM"],
                variant["credential"]["data"],
                variant["given"],
            )
            if classification.get("acceptance") is not True:
                raise ManifestError(f"{spec['id']} variant {variant.get('id')} failed independent classification")
        loaded.append({**spec, "manifest": manifest, "document": document, "variants": variants})
    query_ids = {item["document"].get("mapping", {}).get("query_id") for item in loaded}
    if len(query_ids) != 1:
        raise ManifestError("shared-claim factories must use the same DCQL query id")
    return loaded


def run_shared_transcript_campaign(
    claim_path: str,
    output: str,
    *,
    fixture_only: bool = False,
    retain_private: bool = False,
    injections: list[str] | None = None,
    verifier_base: str | None = None,
    backends: list[dict[str, Any]] | None = None,
) -> tuple[int, dict[str, Any]]:
    out_dir = _safe_output_dir(output)
    resolved_claim = str(Path(claim_path).resolve())
    os.environ["SWIYU_TRANSCRIPT_CLAIM"] = resolved_claim
    claim = load_claim(claim_path)
    if claim.document.get("id") != SHARED_CLAIM_ID:
        raise ManifestError(f"shared-claim campaign requires {SHARED_CLAIM_ID}")

    loaded = _load_backends(claim, backends)
    inject_mode = None
    injection_modes = list(injections or [])
    if "hidden_field" in injection_modes and "hash_header" in injection_modes:
        inject_mode = "both"
    elif "hidden_field" in injection_modes:
        inject_mode = "hidden_field"
    elif "hash_header" in injection_modes:
        inject_mode = "hash_header"

    own_java = not fixture_only and not (verifier_base or os.environ.get("SWIYU_TRANSCRIPT_VERIFIER_BASE"))
    if own_java:
        prepare_epfl_native_env()

    mock = None
    shared_base = verifier_base or os.environ.get("SWIYU_TRANSCRIPT_VERIFIER_BASE")
    if fixture_only:
        mock = FixtureVerifier()
        shared_base = mock.start()

    clean_sessions: list[dict[str, Any]] = []
    injected_sessions: list[dict[str, Any]] = []
    campaigns: list[dict[str, Any]] = []
    backend_runtime: list[dict[str, Any]] = []
    try:
        for item in loaded:
            if own_java:
                backend_campaigns, backend_clean, backend_injected = _run_owned_backend(
                    item=item,
                    claim_path=resolved_claim,
                    inject_mode=inject_mode,
                    out_dir=out_dir,
                )
                backend_runtime.append(
                    {
                        "id": item["id"],
                        "http": "java-oid4vp-harness",
                        "proofs": item["proofs"],
                    }
                )
            elif fixture_only:
                backend_campaigns, backend_clean, backend_injected = _run_backend_sessions(
                    item=item,
                    base=shared_base,
                    claim_path=resolved_claim,
                    fixture_only=True,
                    inject_mode=inject_mode,
                    provider=None,
                )
                backend_runtime.append(
                    {
                        "id": item["id"],
                        "http": "fixture-mock",
                        "proofs": "fixture-opaque",
                    }
                )
            else:
                with _open_backend_wallet(item) as provider:
                    provider.call("initialize", {})
                    backend_campaigns, backend_clean, backend_injected = _run_backend_sessions(
                        item=item,
                        base=shared_base,
                        claim_path=resolved_claim,
                        fixture_only=False,
                        inject_mode=inject_mode,
                        provider=provider,
                    )
                backend_runtime.append(
                    {
                        "id": item["id"],
                        "http": "verifier-base",
                        "proofs": item["proofs"],
                    }
                )
            campaigns.extend(backend_campaigns)
            clean_sessions.extend(backend_clean)
            injected_sessions.extend(backend_injected)
    finally:
        if mock is not None:
            mock.stop()

    cross_policy = build_cross_flow_policy([item["document"] for item in loaded])
    campaigns.append(
        {
            "name": "Cross-implementation clean",
            "kind": "cross-implementation",
            "report": analyze_cross_implementation(claim_path, clean_sessions, cross_policy),
        }
    )
    if injected_sessions:
        campaigns.append(
            {
                "name": "Cross-implementation injected",
                "kind": "cross-implementation injected",
                "report": analyze_cross_implementation(claim_path, injected_sessions, cross_policy),
            }
        )

    proof_note = (
        "Fixture-only mock HTTP verifier and opaque proof envelope. Never used as cryptographic evidence. "
        if fixture_only
        else (
            "Each backend used the Java OID4VP harness (signed request objects, direct_post, "
            "management result) and its matching sidecar. EPFL proofs are native nargo/bb UltraHonk. "
            "OpenAC age-25 proofs are session-bound synthetic envelopes with the real OpenAC wire "
            "shape; Spartan keys for swiyu_age25_jwt are not packaged. Loopback host/port is "
            "test-infrastructure identity, not a product finding. "
            if own_java
            else "Single --verifier-base URL for both backends. Presentation clients are attached; "
            "the sidecar behind that URL must accept both envelope types. "
        )
    )
    qualification = (
        "Same pinned claim through two Swiyu OID4VP integrations (EPFL d10 and "
        "OpenAC age-25). Selected application HTTP: management create, request "
        "object, direct_post, management result. "
        + proof_note
        + ENGINE_NOTE
    )
    all_sessions = clean_sessions + injected_sessions
    public_sessions = [_sanitize_session(session, index) for index, session in enumerate(all_sessions)]
    mode = "fixture-only" if fixture_only else ("live-java" if own_java else "live")
    bundle = {
        "schema": "swiyu.transcript-campaign-bundle.v1",
        "provider": "epfl+openac",
        "claim": claim.document.get("id"),
        "mode": mode,
        "evidence_usable": False,
        "case_study": (
            "Two ZK implementations of swiyu.shared.age25-holder-challenge.v0 "
            "run the same selected Swiyu OID4VP flow. Hidden birth dates differ; "
            "declared public meaning does not. Implementation identity may differ."
        ),
        "novelty": (
            "Differential leakage over complete selected OID4VP transcripts "
            "across two circuits that share one pinned claim, not only A/B "
            "credentials on a single backend."
        ),
        "qualification": qualification,
        "runtime_evidence": {
            "http": "fixture-mock" if fixture_only else ("java-oid4vp-harness" if own_java else "verifier-base"),
            "proofs": {
                item["id"]: ("fixture-opaque" if fixture_only else item["proofs"]) for item in loaded
            },
            "backends": backend_runtime,
            "engine": "transcript_cross.analyze_cross_implementation",
        },
        "campaigns": campaigns,
        "sessions": all_sessions,
        "policy": cross_policy,
        "limitations": {
            "http_scope": "complete selected application HTTP exchanges",
            "excluded": [
                "packet/TLS",
                "Android/emulator",
                "native OpenAC age-25 proving (keys not packaged)",
                "production filters/database when using memory repositories",
            ],
            "engine_note": ENGINE_NOTE,
        },
    }
    exported = dict(bundle)
    exported["sessions"] = public_sessions
    _atomic_write(out_dir / "report.json", json.dumps(exported, indent=2) + "\n")
    _atomic_write(out_dir / "report.html", render_transcript_report(exported))

    if retain_private:
        private_dir = out_dir / "private"
        private_dir.mkdir(parents=True, exist_ok=True)
        _atomic_write(
            private_dir / "sessions.json",
            json.dumps({"sessions": all_sessions}, indent=2) + "\n",
            mode=0o600,
        )

    def _statuses(kind: str) -> list[str]:
        return [c["report"].get("status") for c in campaigns if c["kind"] == kind]

    if any(report.get("status") == "error" for report in (c["report"] for c in campaigns)):
        return 2, bundle
    if not _statuses("baseline") or any(status != "clean" for status in _statuses("baseline")):
        return 1, bundle
    if _statuses("cross-implementation") != ["clean"]:
        return 1, bundle
    if inject_mode and (
        not _statuses("injected regression")
        or any(status != "findings" for status in _statuses("injected regression"))
    ):
        return 1, bundle
    if inject_mode and _statuses("cross-implementation injected") != ["findings"]:
        return 1, bundle
    if not all(session["accepted"] for session in all_sessions):
        return 1, bundle
    return 0, bundle


def _sidecar_argv(item: dict[str, Any]) -> list[str]:
    return [sys.executable, str(item["sidecar"])]


def _run_owned_backend(
    *,
    item: dict[str, Any],
    claim_path: str,
    inject_mode: str | None,
    out_dir: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    backend_out = out_dir / item["id"]
    backend_out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".runtime-{item['id']}-", dir=out_dir) as temporary:
        scratch = Path(temporary)
        os.chmod(scratch, 0o700)
        ready_timeout = 420 if item["id"] == "epfl" else 360
        runtime = start_owned_java_runtime(
            _sidecar_argv(item),
            item["document"],
            scratch,
            ready_timeout=ready_timeout,
        )
        try:
            with _open_backend_wallet(item) as provider:
                provider.call("initialize", {})
                return _run_backend_sessions(
                    item=item,
                    base=runtime.verifier_url,
                    claim_path=claim_path,
                    fixture_only=False,
                    inject_mode=inject_mode,
                    provider=provider,
                )
        finally:
            runtime.close()
            export_runtime_logs(backend_out, runtime.logs)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the shared-claim OID4VP transcript campaign")
    parser.add_argument("--claim", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--fixture-only", action="store_true")
    parser.add_argument("--retain-private", action="store_true")
    parser.add_argument("--inject", default="", help="comma modes: hidden_field,hash_header")
    parser.add_argument("--verifier-base")
    args = parser.parse_args(argv)
    injections = [part.strip() for part in args.inject.split(",") if part.strip()]
    try:
        code, bundle = run_shared_transcript_campaign(
            args.claim,
            args.output,
            fixture_only=args.fixture_only,
            retain_private=args.retain_private,
            injections=injections or None,
            verifier_base=args.verifier_base,
        )
    except (SupportError, ManifestError, RuntimeError, ProviderError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps({"status": "ok", "mode": bundle["mode"], "evidence_usable": bundle["evidence_usable"]}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())

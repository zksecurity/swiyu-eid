#!/usr/bin/env python3
"""Reusable OID4VP transcript campaign driver.

Generic over provider adapters. OpenAC-specific factory mapping lives in the
adapter fixture, not here. Fixture-only mode is a mock and is never evidence.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import subprocess
import sys
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent
INTEGRATION = ROOT.parent
SEMANTICS = INTEGRATION / "semantics"
RUNTIME = INTEGRATION / "runtime"

for path in (str(ROOT), str(SEMANTICS), str(RUNTIME), str(INTEGRATION)):
    if path not in sys.path:
        sys.path.insert(0, path)

from manifest import ManifestError, load_manifest  # noqa: E402
from provider_client import ProviderClient  # noqa: E402
from semantics.claims import load_claim  # noqa: E402
from semantics.support import SupportError, load_support, verify_claim_supported  # noqa: E402
from transcript_policy import build_flow_policy  # noqa: E402
from transcript_report import render_transcript_report  # noqa: E402

from transcript.fixture_verifier import FixtureVerifier  # noqa: E402
from transcript.http_capture import decode_json  # noqa: E402
from transcript.oid4vp import (  # noqa: E402
    create_verification,
    get_management_result,
    get_request_object,
    post_direct_post,
)

ALLOWED_OUTPUT_FILES = frozenset({"report.json", "report.html"})
TWO_MIB = 2 * 1024 * 1024
ENGINE_NOTE = (
    "Semantically equivalent public_context must alpha-normalize the dynamic "
    "response_uri request UUID (path segment) as well as session nonce/state. "
    "Raw events retain the UUID. Request JWT signatures are treated as length-only "
    "when mapping.signature_opaque is set."
)
SELECTED = (
    "verifier:management_create",
    "verifier:request_object",
    "wallet->verifier:direct_post",
    "verifier:management_result",
)


def _atomic_write(path: Path, content: str, *, mode: int | None = None) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    if mode is not None:
        os.chmod(tmp, mode)
    os.replace(tmp, path)
    if mode is not None:
        os.chmod(path, mode)


def _safe_output_dir(output: str) -> Path:
    out = Path(output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    for name in ALLOWED_OUTPUT_FILES:
        entry = out / name
        if entry.is_symlink():
            raise ValueError(f"unsafe symlink in output: {entry.name}")
    return out


def _resolve_manifest_local_path(manifest: dict, rel_path: str) -> Path:
    if not isinstance(rel_path, str) or not rel_path:
        raise ManifestError("transcript_fixture must be a non-empty path")
    manifest_dir = Path(manifest["_manifest_dir"]).resolve()
    target = (manifest_dir / rel_path).resolve()
    if target != manifest_dir and not str(target).startswith(str(manifest_dir) + os.sep):
        raise ManifestError("transcript_fixture escapes provider directory")
    if not target.is_file():
        raise ManifestError(f"transcript_fixture not found: {rel_path}")
    return target


def _parse_fixture_document(raw: str) -> dict[str, Any]:
    document = json.loads(raw)
    if not isinstance(document, dict) or document.get("schema") != "swiyu.transcript-fixture.v1":
        raise ManifestError("unsupported transcript_fixture schema")
    variants = document.get("variants")
    if not isinstance(variants, list) or len(variants) < 2:
        raise ManifestError("transcript_fixture must provide at least two variants")
    if document.get("equivalence") in {"equivalent", True, "claimed"}:
        raise ManifestError("factory must not claim input equivalence")
    return document


def _load_fixture_file(path: Path, cwd: str) -> dict[str, Any]:
    if path.suffix == ".json":
        return _parse_fixture_document(path.read_text(encoding="utf-8"))
    if path.suffix in {".mjs", ".js"}:
        completed = subprocess.run(
            ["node", str(path)],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return _parse_fixture_document(completed.stdout)
    if path.suffix == ".py":
        completed = subprocess.run(
            [sys.executable, str(path), str(SEMANTICS), os.environ.get("SWIYU_TRANSCRIPT_CLAIM", "")],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
            env={**os.environ, "PYTHONPATH": str(SEMANTICS) + os.pathsep + os.environ.get("PYTHONPATH", "")},
        )
        return _parse_fixture_document(completed.stdout)
    raise ManifestError("transcript fixture must be .json, .py, .js, or .mjs")


def _load_transcript_fixture(manifest: dict, fixture_document_path: str | None) -> dict[str, Any]:
    if fixture_document_path:
        path = Path(fixture_document_path).resolve()
        if not path.is_file():
            raise ManifestError(f"fixture document not found: {path}")
        return _load_fixture_file(path, str(path.parent))
    source = manifest.get("source")
    if not isinstance(source, dict) or not source.get("transcript_fixture"):
        raise ManifestError("manifest source.transcript_fixture is required")
    fixture_path = _resolve_manifest_local_path(manifest, source["transcript_fixture"])
    return _load_fixture_file(fixture_path, str(Path(manifest["_manifest_dir"])))


def _jwt_payload(token: str) -> dict[str, Any]:
    parts = token.strip().split(".")
    if len(parts) < 2:
        return {}
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        parsed = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _fixture_envelope() -> str:
    proof = _b64url(b"opaque-fixture-proof-bytes")
    return json.dumps(
        {"schema": "swiyu-zkp-envelope-v1", "proof": proof, "proof_b64": proof},
        separators=(",", ":"),
    )


def _wallet_envelope_json(presentation: str) -> str:
    text = presentation.strip()
    if text.startswith("{"):
        json.loads(text)
        return text
    padded = text + "=" * (-len(text) % 4)
    decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    json.loads(decoded)
    return decoded


def _dcql_vp_token(query_id: str, presentation: str) -> str:
    return json.dumps({query_id: [_wallet_envelope_json(presentation)]}, separators=(",", ":"))


def _default_engine():
    from transcript_equivalence import analyze_transcripts, classify_fixture

    return classify_fixture, analyze_transcripts


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _request_dcql(claims: dict[str, Any]) -> Any:
    if "dcql_query" in claims:
        return claims["dcql_query"]
    for key in ("dcql", "dcqlQuery"):
        if key in claims:
            return claims[key]
    return None


def _assert_request_matches_factory(claims: dict[str, Any], document: dict[str, Any], *, require_dcql: bool) -> None:
    factory_dcql = document.get("dcql_query")
    observed = _request_dcql(claims)
    if observed is None:
        if require_dcql:
            raise RuntimeError("request object is missing dcql_query")
        return
    if _canonical(observed) != _canonical(factory_dcql):
        raise RuntimeError("request dcql_query does not match the loaded factory document")
    factory_time = None
    factory_now_date = None
    creds = (factory_dcql or {}).get("credentials") if isinstance(factory_dcql, dict) else None
    if isinstance(creds, list) and creds and isinstance(creds[0], dict):
        zkp = creds[0].get("x_swiyu_zkp") or {}
        factory_time = zkp.get("current_time")
        factory_now_date = zkp.get("now_date")
    observed_creds = observed.get("credentials") if isinstance(observed, dict) else None
    if isinstance(observed_creds, list) and observed_creds:
        zkp = (observed_creds[0] or {}).get("x_swiyu_zkp") or {}
        if factory_time is not None and zkp.get("current_time") != factory_time:
            raise RuntimeError("request current_time does not match the loaded factory document")
        if factory_now_date is not None and zkp.get("now_date") != factory_now_date:
            raise RuntimeError("request now_date does not match the loaded factory document")


def _epfl_derived_challenge_hex(
    document: dict[str, Any],
    variant: dict[str, Any],
    claims: dict[str, Any],
    request_id: str,
) -> str | None:
    transcript = variant.get("transcript")
    if not isinstance(transcript, dict) or not transcript.get("policy_inputs"):
        return None
    provider_dir = Path(__file__).resolve().parents[1] / "providers" / "epfl"
    if str(provider_dir) not in sys.path:
        sys.path.insert(0, str(provider_dir))
    from epfl_challenge import PROFILE, digest_hex

    mapping = document.get("mapping") or {}
    query_id = str(mapping.get("query_id") or transcript.get("query_id") or "")
    profile = str(transcript.get("profile") or PROFILE)
    return digest_hex(
        str(claims.get("nonce") or ""),
        str(claims.get("client_id") or transcript.get("client_id") or ""),
        str(claims.get("response_uri") or ""),
        str(claims.get("state") or request_id),
        query_id,
        profile,
        str(transcript["policy_inputs"]),
    )


def _challenge_from_request(
    document: dict[str, Any],
    variant: dict[str, Any],
    claims: dict[str, Any],
    request_id: str,
) -> dict[str, Any]:
    present = deepcopy(variant.get("present") or {})
    challenge = deepcopy(present.get("request_context") or {})
    fields = (document.get("mapping") or {}).get("challenge_fields") or {
        "nonce": "nonce",
        "clientId": "client_id",
        "responseUri": "response_uri",
        "state": "state",
    }
    extracted = {
        "nonce": str(claims.get("nonce") or ""),
        "client_id": str(claims.get("client_id") or ""),
        "response_uri": str(claims.get("response_uri") or ""),
        "state": str(claims.get("state") or request_id),
    }
    for sdk_name, claim_name in fields.items():
        value = extracted.get(claim_name)
        if not value:
            raise RuntimeError(f"request object missing {claim_name}")
        challenge[sdk_name] = value
    derived = _epfl_derived_challenge_hex(document, variant, claims, request_id)
    if derived:
        challenge["challenge_nonce"] = list(bytes.fromhex(derived))
    return challenge


def _session_meta(claims: dict[str, Any], request_id: str) -> dict[str, str]:
    return {
        "nonce": str(claims.get("nonce") or ""),
        "state": str(claims.get("state") or request_id),
        "response_uri": str(claims.get("response_uri") or ""),
        "client_id": str(claims.get("client_id") or ""),
    }


def _session_given(
    claim_path: str,
    document: dict[str, Any],
    variant: dict[str, Any],
    claims: dict[str, Any],
    request_id: str,
) -> dict[str, Any]:
    given = deepcopy(variant["given"])
    claim = load_claim(claim_path)
    derived = _epfl_derived_challenge_hex(document, variant, claims, request_id)
    for name, spec in claim.document.get("given", {}).items():
        type_name = spec["type"] if isinstance(spec, dict) else spec
        if type_name == "platform.expected-session@1":
            session = dict(given.get(name) or {})
            meta = _session_meta(claims, request_id)
            session.update(meta)
            if not session.get("query_id"):
                session["query_id"] = str((document.get("mapping") or {}).get("query_id") or "")
            given[name] = session
        elif type_name == "platform.expected-challenge@1" and derived:
            given[name] = derived
    return given


def _fresh_mapping(claims: dict[str, Any], request_id: str) -> dict[str, str]:
    nonce = str(claims.get("nonce") or "")
    state = str(claims.get("state") or request_id)
    fresh = {"nonce": nonce, "state": state}
    if request_id and request_id != state:
        fresh["request_id"] = request_id
    if any(len(value) < 12 for value in fresh.values()):
        raise RuntimeError("fresh session identifiers are too short")
    if len(set(fresh.values())) != len(fresh):
        raise RuntimeError("fresh session identifiers collide")
    return fresh


def _create_body(document: dict[str, Any], variants: list[dict[str, Any]]) -> dict[str, Any]:
    issuer_id = variants[0]["given"]["issuer"]["issuer_id"]
    body: dict[str, Any] = {
        "jwt_secured_authorization_request": True,
        "response_mode": "direct_post",
        "dcql_query": document.get("dcql_query") or {"credentials": []},
        "accepted_issuer_dids": [issuer_id],
    }
    return body


def _injection_material(credential: str, mode: str | None) -> tuple[dict[str, str] | None, list[list[str]] | None]:
    if not mode:
        return None, None
    extra_fields: dict[str, str] = {}
    extra_headers: list[list[str]] = []
    if mode in {"hidden_field", "both"}:
        extra_fields["x_swiyu_wallet_tag"] = credential
    if mode in {"hash_header", "both"}:
        extra_headers.append(
            ["X-Swiyu-Wallet-Correlation", hashlib.sha256(credential.encode("utf-8")).hexdigest()]
        )
    return extra_fields or None, extra_headers or None


def _timed(fn):
    started = time.perf_counter()
    result = fn()
    return result, int((time.perf_counter() - started) * 1000)


def _decode_proof_leaf(encoded: Any) -> bytes | None:
    from transcript_equivalence import _b64url_decode_canonical

    if not isinstance(encoded, str) or not encoded:
        return None
    return _b64url_decode_canonical(encoded)


def _artifact_sizes(present: dict[str, Any] | None, proof_path: str = "/proof") -> tuple[int | None, int | None]:
    if not present:
        return None, None
    from transcript_equivalence import _pointer_get
    envelope = json.loads(_wallet_envelope_json(present["presentation"]))
    found, encoded = _pointer_get(envelope, proof_path)
    raw = _decode_proof_leaf(encoded) if found else None
    if not raw:
        raise RuntimeError("presentation does not contain the declared canonical proof bytes")
    proof = len(raw)
    sizes = present.get("artifact_sizes") or {}
    claimed = sizes.get("proof")
    if claimed is not None and (type(claimed) is not int or claimed != proof):
        raise RuntimeError("provider proof size disagrees with observed proof bytes")
    witness = sizes.get("witness")
    if witness is not None and (type(witness) is not int or witness < 0):
        raise RuntimeError("invalid witness byte count")
    return proof, witness


def _sanitize_session(session: dict[str, Any], index: int) -> dict[str, Any]:
    return {
        "id": f"{session['campaign']}-{index}",
        "variant": f"variant-{index}",
        "accepted": session["accepted"],
        "event_count": len(session["events"]),
        "proof_bytes": session.get("proof_bytes"),
        "witness_bytes": session.get("witness_bytes"),
        "present_ms": session.get("present_ms"),
        "prepare_ms": session.get("prepare_ms"),
        "request_ms": session.get("request_ms"),
        "post_ms": session.get("post_ms"),
        "result_ms": session.get("result_ms"),
        "campaign": session.get("campaign"),
        "implementation": session.get("implementation"),
        "fresh_label": session.get("fresh_label"),
        "proof_reuse": session.get("proof_reuse"),
    }


def _run_one_session(
    *,
    base: str,
    variant: dict[str, Any],
    document: dict[str, Any],
    create_body: dict[str, Any],
    extra_fields: dict[str, str] | None,
    extra_headers: list[list[str]] | None,
    provider,
    fixture_only: bool,
    require_dcql: bool,
    campaign: str,
    claim_path: str,
) -> dict[str, Any]:
    query_id = str((document.get("mapping") or {}).get("query_id") or "")
    create_event = create_verification(base, create_body)
    created = decode_json(create_event["response"]["body"])
    request_id = str(created.get("id") or created.get("verification_id") or "")
    if not request_id:
        raise RuntimeError("management create did not return a request id")
    request_event, request_ms = _timed(lambda: get_request_object(base, request_id))
    jwt = request_event["response"]["body"].strip()
    claims = _jwt_payload(jwt)
    _assert_request_matches_factory(claims, document, require_dcql=require_dcql)
    if not claims.get("response_uri"):
        raise RuntimeError("request object missing response_uri")
    given = _session_given(claim_path, document, variant, claims, request_id)
    fresh = _fresh_mapping(claims, request_id)
    session_meta = _session_meta(claims, request_id)
    present_result = None
    prepare_ms = None
    present_ms = None
    if fixture_only or provider is None:
        presentation = _fixture_envelope()
        proof_bytes = None
        witness_bytes = None
        fresh_label = "fixture-mock"
    else:
        challenge = _challenge_from_request(document, variant, claims, request_id)
        prepare_payload = deepcopy(variant.get("prepare") or {})
        present_payload = deepcopy(variant.get("present") or {})
        prepared, prepare_ms = _timed(lambda: provider.call("prepare", prepare_payload))
        present_payload["handle"] = prepared["handle"]
        present_payload["request_context"] = challenge
        present_result, present_ms = _timed(lambda: provider.call("present", present_payload))
        presentation = present_result["presentation"]
        proof_bytes, witness_bytes = _artifact_sizes(present_result, document.get("proof_path", "/proof"))
        fresh_label = "fresh"
    vp_token = _dcql_vp_token(query_id, presentation)
    post_event, post_ms = _timed(
        lambda: post_direct_post(
            str(claims["response_uri"]),
            state=fresh["state"],
            vp_token=vp_token,
            extra_fields=extra_fields,
            extra_headers=extra_headers,
        )
    )
    result_event, result_ms = _timed(lambda: get_management_result(base, request_id))
    result = decode_json(result_event["response"]["body"])
    accepted = str(result.get("state", "")).upper() == "SUCCESS"
    return {
        "id": f"{campaign}-{variant['id']}",
        "variant": variant["id"],
        "campaign": campaign,
        "credential": variant["credential"]["data"],
        "given": given,
        "accepted": accepted,
        "fresh": fresh,
        "session_meta": session_meta,
        "events": [create_event, request_event, post_event, result_event],
        "fresh_label": fresh_label,
        "proof_reuse": None,
        "proof_bytes": proof_bytes,
        "witness_bytes": witness_bytes,
        "present_ms": present_ms,
        "prepare_ms": prepare_ms,
        "request_ms": request_ms,
        "post_ms": post_ms,
        "result_ms": result_ms,
    }


def run_transcript_campaign(
    manifest_path: str,
    claim_path: str,
    output: str,
    *,
    support_path: str | None = None,
    fixture_only: bool = False,
    retain_private: bool = False,
    injections: list[str] | None = None,
    verifier_base: str | None = None,
    fixture_document_path: str | None = None,
    classify_fixture_fn: Callable[..., dict] | None = None,
    analyze_transcripts_fn: Callable[..., dict] | None = None,
    provider_client_factory: Callable[[str], Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    out_dir = _safe_output_dir(output)
    os.environ["SWIYU_TRANSCRIPT_CLAIM"] = str(Path(claim_path).resolve())
    claim = load_claim(claim_path)
    manifest = load_manifest(manifest_path)
    support_file = Path(support_path) if support_path else Path(manifest["_manifest_dir"]) / "support.json"
    support = load_support(support_file)
    verify_claim_supported(
        support,
        claim_id=claim.document["id"],
        statement_digest=claim.statement_digest,
        claim=claim,
    )
    document = _load_transcript_fixture(manifest, fixture_document_path)
    variants = document["variants"]
    credentials = [v["credential"]["data"] for v in variants]
    issuers = [v["given"]["issuer"] for v in variants]
    if len({json.dumps(i, sort_keys=True) for i in issuers}) != 1:
        raise ManifestError("variants must share the same issuer metadata")
    if len(set(credentials)) < 2:
        raise ManifestError("variants must differ in credential material")

    classify = classify_fixture_fn
    analyze = analyze_transcripts_fn
    if classify is None or analyze is None:
        engine_classify, engine_analyze = _default_engine()
        classify = classify or engine_classify
        analyze = analyze or engine_analyze

    for variant in variants:
        classification = classify(claim_path, variant["credential"]["data"], variant["given"])
        if classification.get("acceptance") is not True:
            raise ManifestError(f"variant {variant.get('id')} failed independent classification")

    policy = build_flow_policy(document)

    mock = None
    base = verifier_base or os.environ.get("SWIYU_TRANSCRIPT_VERIFIER_BASE")
    if fixture_only:
        mock = FixtureVerifier()
        base = mock.start()
    elif not base:
        raise RuntimeError("SWIYU_TRANSCRIPT_VERIFIER_BASE is required unless --fixture-only")

    create_body = _create_body(document, variants)
    injection_modes = list(injections or [])
    want_hidden = "hidden_field" in injection_modes
    want_header = "hash_header" in injection_modes
    inject_mode = (
        "both"
        if want_hidden and want_header
        else "hidden_field"
        if want_hidden
        else "hash_header"
        if want_header
        else None
    )

    provider = None
    provider_cm = None
    test_double = provider_client_factory is not None
    try:
        if not fixture_only:
            # present may run nargo execute (120s) + bb prove (180s); keep client budget above that.
            factory = provider_client_factory or (
                lambda path: ProviderClient(path, timeout=360, max_output_bytes=TWO_MIB, max_input_bytes=TWO_MIB)
            )
            provider_cm = factory(manifest_path)
            provider = provider_cm.__enter__()
            provider.call("initialize", {})

        clean_sessions = []
        for variant in variants:
            clean_sessions.append(
                _run_one_session(
                    base=base,
                    variant=variant,
                    document=document,
                    create_body=create_body,
                    extra_fields=None,
                    extra_headers=None,
                    provider=provider,
                    fixture_only=fixture_only,
                    require_dcql=not fixture_only and not test_double,
                    campaign="clean",
                    claim_path=claim_path,
                )
            )
        injected_sessions: list[dict[str, Any]] = []
        if inject_mode:
            for variant in variants:
                fields, headers = _injection_material(variant["credential"]["data"], inject_mode)
                injected_sessions.append(
                    _run_one_session(
                        base=base,
                        variant=variant,
                        document=document,
                        create_body=create_body,
                        extra_fields=fields,
                        extra_headers=headers,
                        provider=provider,
                        fixture_only=fixture_only,
                        require_dcql=not fixture_only and not test_double,
                        campaign="injected",
                        claim_path=claim_path,
                    )
                )
    finally:
        if provider_cm is not None:
            provider_cm.__exit__(None, None, None)
        if mock is not None:
            mock.stop()

    campaigns = []
    for name, kind, group in (
        ("Clean A/B", "baseline", clean_sessions),
        ("Injected transport A/B", "injected regression", injected_sessions),
    ):
        if not group:
            continue
        campaigns.append({"name": name, "kind": kind, "report": analyze(claim_path, group, policy)})

    native_proofs = (not fixture_only) and (not test_double)
    qualification_parts = [
        ENGINE_NOTE,
        "Selected application HTTP: POST management create, GET request-object JWT, POST direct_post form, GET management result.",
        "Not captured: TLS, packets, Android, trust-registry, live status service, deployment filters, database internals.",
    ]
    if fixture_only:
        qualification_parts.insert(
            0,
            "Fixture-only mock HTTP verifier and opaque proof envelope. Never used as evidence. "
            "Does not exercise production VerificationController, request-object signing, DCQL, or HttpZkPresentationVerifier.",
        )
    elif test_double:
        qualification_parts.insert(
            0,
            "Live HTTP path with a test-double ProviderClient. Not native proving evidence.",
        )
    else:
        qualification_parts.insert(
            0,
            "Live verifier base URL with ProviderClient present/prepare. "
            "Verifier outcomes are the management state after direct_post. "
            "Memory/test doubles for infrastructure are acceptable only when disclosed.",
        )

    all_sessions = clean_sessions + injected_sessions
    public_sessions = [_sanitize_session(session, index) for index, session in enumerate(all_sessions)]
    evidence_usable = bool(
        native_proofs
        and all(session["accepted"] for session in clean_sessions)
        and any(c["kind"] == "baseline" and c["report"].get("status") == "clean" for c in campaigns)
    )

    bundle = {
        "schema": "swiyu.transcript-campaign-bundle.v1",
        "provider": manifest.get("id"),
        "claim": claim.document.get("id"),
        "mode": "fixture-only" if fixture_only else "live",
        "evidence_usable": evidence_usable,
        "qualification": " ".join(qualification_parts),
        "runtime_evidence": {
            "http": "fixture-mock" if fixture_only else "verifier-base",
            "proofs": "fixture-opaque" if fixture_only else ("test-double" if test_double else "provider-present"),
            "engine": "transcript_equivalence.analyze_transcripts",
        },
        "campaigns": campaigns,
        "sessions": all_sessions,
        "policy": policy,
        "limitations": {
            "http_scope": "complete selected application HTTP exchanges",
            "excluded": [
                "packet/TLS",
                "Android/emulator",
                "uninstrumented sidecar unless observer includes verifier->sidecar",
                "production filters/database when using memory repositories",
            ],
            "engine_note": ENGINE_NOTE,
        },
    }
    exported = dict(bundle)
    exported["sessions"] = public_sessions
    _atomic_write(out_dir / "report.json", json.dumps(exported, indent=2) + "\n")
    html_bundle = dict(exported)
    _atomic_write(out_dir / "report.html", render_transcript_report(html_bundle))

    if retain_private:
        private_dir = out_dir / "private"
        private_dir.mkdir(parents=True, exist_ok=True)
        private_payload = {
            "variants": [
                {"id": v["id"], "credential": v["credential"], "given": v["given"]}
                for v in variants
            ],
            "sessions": all_sessions,
        }
        _atomic_write(
            private_dir / "sessions.json",
            json.dumps(private_payload, indent=2) + "\n",
            mode=0o600,
        )

    statuses = {c["kind"]: c["report"].get("status") for c in campaigns}
    if any(status == "error" for status in statuses.values()):
        return 2, bundle
    expected_injected = statuses.get("injected regression")
    if statuses.get("baseline") != "clean":
        return 1, bundle
    if inject_mode and expected_injected != "findings":
        return 1, bundle
    if not all(session["accepted"] for session in all_sessions):
        return 1, bundle
    return 0, bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run an OID4VP transcript campaign")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--claim", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--support")
    parser.add_argument("--fixture-only", action="store_true")
    parser.add_argument("--retain-private", action="store_true")
    parser.add_argument("--inject", default="", help="comma modes: hidden_field,hash_header")
    parser.add_argument("--verifier-base")
    parser.add_argument("--fixture-document")
    args = parser.parse_args(argv)
    injections = [part.strip() for part in args.inject.split(",") if part.strip()]
    try:
        code, bundle = run_transcript_campaign(
            args.manifest,
            args.claim,
            args.output,
            support_path=args.support,
            fixture_only=args.fixture_only,
            retain_private=args.retain_private,
            injections=injections or None,
            verifier_base=args.verifier_base,
            fixture_document_path=args.fixture_document,
        )
    except (SupportError, ManifestError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps({"status": "ok", "mode": bundle["mode"], "evidence_usable": bundle["evidence_usable"]}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Session-bound OpenAC-shaped age-25 envelope for Java OID4VP transcripts.

This is not a Spartan proof. The proving key for swiyu_age25_jwt is not
packaged. The envelope uses the real OpenAC wire keys (version/profile/
circuitId/proof/lookup) and binds the proof bytes to the verifier session
the Java harness reconstructs (nonce, client, callback, state, query,
profile, circuit, now_date).
"""
from __future__ import annotations

import base64
import hashlib
import json
import uuid
from typing import Any

PROFILE = "openac-age25-jwt-v0"
CIRCUIT_ID = "swiyu_age25_jwt"
ENVELOPE_VERSION = "swiyu-zkp-proof-v0"
QUERY_ID = "birth_date"
PROOF_BYTES = 32768
DOMAIN = b"swiyu.openac.age25.synthetic-envelope.v0"
BINDING_KEYS = (
    "nonce",
    "client_id",
    "response_uri",
    "state",
    "query_id",
    "profile",
    "circuit_id",
    "now_date",
)


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode_canonical(text: str) -> bytes:
    if not isinstance(text, str) or not text or text[-1:] == "=":
        raise ValueError("proof must be unpadded base64url")
    padded = text + "=" * (-len(text) % 4)
    raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    if b64url(raw) != text:
        raise ValueError("proof is not canonical base64url")
    return raw


def session_from_mapping(values: dict[str, Any], *, client_key: str, response_key: str) -> dict[str, Any]:
    now_date = values.get("now_date")
    if isinstance(now_date, bool) or not isinstance(now_date, int):
        raise ValueError("now_date must be a JSON integer YYYYMMDD")
    session = {
        "nonce": str(values.get("nonce") or ""),
        "client_id": str(values.get(client_key) or ""),
        "response_uri": str(values.get(response_key) or ""),
        "state": str(values.get("state") or ""),
        "query_id": str(values.get("query_id") or values.get("queryId") or QUERY_ID),
        "profile": str(values.get("profile") or PROFILE),
        "circuit_id": str(values.get("circuit_id") or values.get("circuitId") or CIRCUIT_ID),
        "now_date": now_date,
    }
    if any(not session[key] for key in BINDING_KEYS if key != "now_date"):
        raise ValueError("session binding fields are incomplete")
    if session["profile"] != PROFILE or session["circuit_id"] != CIRCUIT_ID:
        raise ValueError("unexpected age-25 profile")
    return session


def session_from_challenge(challenge: dict[str, Any]) -> dict[str, Any]:
    return session_from_mapping(challenge, client_key="clientId", response_key="responseUri")


def session_from_expected(expected: dict[str, Any]) -> dict[str, Any]:
    return session_from_mapping(expected, client_key="client_id", response_key="response_uri")


def binding_seed(session: dict[str, Any]) -> bytes:
    payload = {key: session[key] for key in BINDING_KEYS}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def expand_proof(seed: bytes, length: int = PROOF_BYTES) -> bytes:
    out = bytearray()
    block = hashlib.sha256(DOMAIN + b"\0" + seed).digest()
    while len(out) < length:
        out.extend(block)
        block = hashlib.sha256(block).digest()
    return bytes(out[:length])


def lookup_from_prepare(payload: dict[str, Any]) -> dict[str, str]:
    context = payload.get("context") or {}
    lookup = context.get("lookup") or {}
    issuer = lookup.get("issuer")
    kid = lookup.get("kid")
    vct = lookup.get("vct")
    if not all(isinstance(value, str) and value for value in (issuer, kid, vct)):
        raise ValueError("prepare context.lookup must include issuer, kid, and vct")
    return {"issuer": issuer, "kid": kid, "vct": vct}


def build_envelope(session: dict[str, Any], lookup: dict[str, str]) -> dict[str, Any]:
    proof = expand_proof(binding_seed(session))
    return {
        "version": ENVELOPE_VERSION,
        "profile": PROFILE,
        "circuitId": CIRCUIT_ID,
        "proof": b64url(proof),
        "lookup": {"issuer": lookup["issuer"], "kid": lookup["kid"], "vct": lookup["vct"]},
    }


def parse_envelope(raw: str) -> dict[str, Any]:
    envelope = json.loads(raw)
    if not isinstance(envelope, dict):
        raise ValueError("envelope must be an object")
    if set(envelope) != {"version", "profile", "circuitId", "proof", "lookup"}:
        raise ValueError("envelope keys must match swiyu-zkp-proof-v0")
    if envelope.get("version") != ENVELOPE_VERSION:
        raise ValueError("unexpected envelope version")
    if envelope.get("profile") != PROFILE or envelope.get("circuitId") != CIRCUIT_ID:
        raise ValueError("unexpected age-25 profile")
    lookup = envelope.get("lookup")
    if not isinstance(lookup, dict) or set(lookup) != {"issuer", "kid", "vct"}:
        raise ValueError("lookup must be issuer/kid/vct")
    if not all(isinstance(lookup[key], str) and lookup[key] for key in ("issuer", "kid", "vct")):
        raise ValueError("lookup values must be nonempty strings")
    proof = b64url_decode_canonical(envelope["proof"])
    if len(proof) != PROOF_BYTES:
        raise ValueError("synthetic age-25 proof has unexpected length")
    return envelope


def proof_matches_session(envelope: dict[str, Any], session: dict[str, Any]) -> bool:
    expected = expand_proof(binding_seed(session))
    observed = b64url_decode_canonical(envelope["proof"])
    return hmac_equal(expected, observed)


def hmac_equal(left: bytes, right: bytes) -> bool:
    if len(left) != len(right):
        return False
    acc = 0
    for a, b in zip(left, right):
        acc |= a ^ b
    return acc == 0


class Age25TranscriptWallet:
    """Duck-typed ProviderClient for the shared-claim Java campaign."""

    def __init__(self) -> None:
        self._handles: dict[str, dict[str, Any]] = {}

    def __enter__(self) -> "Age25TranscriptWallet":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._handles.clear()

    def call(self, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        if operation == "initialize":
            return {
                "profiles": [PROFILE],
                "limitations": [
                    "openac-age25-jwt-v0 envelope is session-bound synthetic; Spartan keys are not packaged",
                ],
            }
        if operation == "prepare":
            if payload.get("profile") != PROFILE:
                raise RuntimeError("unsupported_profile")
            lookup = lookup_from_prepare(payload)
            handle = str(uuid.uuid4())
            self._handles[handle] = {"lookup": lookup, "profile": PROFILE}
            return {"handle": handle}
        if operation == "present":
            handle = payload.get("handle")
            state = self._handles.get(handle) if isinstance(handle, str) else None
            if not state:
                raise RuntimeError("unknown prepare handle")
            if payload.get("profile") != PROFILE:
                raise RuntimeError("unsupported_profile")
            session = session_from_challenge(payload.get("request_context") or {})
            envelope = build_envelope(session, state["lookup"])
            proof = b64url_decode_canonical(envelope["proof"])
            return {
                "presentation": json.dumps(envelope, separators=(",", ":")),
                "artifact_sizes": {"proof": len(proof)},
                "public_outputs": {
                    "now_date": session["now_date"],
                    "min_age_years": 25,
                    "challenge_binding": "session-sha256-expand-v0",
                    "proving": "openac-age25-synthetic-envelope",
                },
            }
        if operation == "cleanup":
            self._handles.clear()
            return {}
        raise RuntimeError(f"unsupported wallet operation: {operation}")

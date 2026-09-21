#!/usr/bin/env python3
"""EPFL transcript campaign factory for synthetic dc+sd-jwt variants."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from epfl_challenge import CIRCUIT_ID, PROFILE, digest_hex, policy_inputs_json
from fixtures import ISSUER_ID, KEY_ID, NOW_DATE, VARIANT_A, VARIANT_B, fixture_bundle

QUERY_ID = "birth_date"
CLIENT_ID = "did:example:epfl-verifier"
RESPONSE_URI = "https://example.test/oid4vp/api/request-object/00000000-0000-4000-8000-000000000001/response-data"
STATE = "epfl-transcript-state-v1"
NONCE = "epfl-transcript-nonce-v1"


def _session_challenge_hex(issuer_pub_x: list[int], issuer_pub_y: list[int]) -> str:
    policy_inputs = policy_inputs_json(
        CIRCUIT_ID,
        "".join(f"{b:02x}" for b in issuer_pub_x),
        "".join(f"{b:02x}" for b in issuer_pub_y),
        NOW_DATE,
    )
    return digest_hex(NONCE, CLIENT_ID, RESPONSE_URI, STATE, QUERY_ID, PROFILE, policy_inputs)


def _variant(variant_id: str, witness) -> dict:
    challenge_hex = _session_challenge_hex(witness.issuer_pub_x, witness.issuer_pub_y)
    bundle = fixture_bundle(variant_id, challenge_hex)
    given = bundle["given"]
    request_context = {
        "issuer_pub_x": witness.issuer_pub_x,
        "issuer_pub_y": witness.issuer_pub_y,
        "now_date": NOW_DATE,
        "challenge_nonce": list(bytes.fromhex(challenge_hex)),
    }
    policy_inputs = policy_inputs_json(
        CIRCUIT_ID,
        "".join(f"{b:02x}" for b in witness.issuer_pub_x),
        "".join(f"{b:02x}" for b in witness.issuer_pub_y),
        NOW_DATE,
    )
    return {
        "id": variant_id,
        "credential": {"format": "dc+sd-jwt", "data": bundle["credential"]},
        "given": given,
        "prepare": {
            "profile": PROFILE,
            "credential": {"format": "epfl-variant", "variant": variant_id},
            "context": {},
        },
        "present": {
            "profile": PROFILE,
            "request_context": request_context,
            "inputs": {},
        },
        "verify": {
            "profile": PROFILE,
            "request_context": request_context,
            "inputs": {},
        },
        "transcript": {
            "nonce": NONCE,
            "client_id": CLIENT_ID,
            "response_uri": RESPONSE_URI,
            "state": STATE,
            "query_id": QUERY_ID,
            "profile": PROFILE,
            "circuit_id": CIRCUIT_ID,
            "policy_inputs": policy_inputs,
            "challenge_nonce_hex": challenge_hex,
        },
        "compact_sd_jwt_sha256": hashlib.sha256(bundle["credential"].encode("ascii")).hexdigest(),
    }


def build_document() -> dict:
    issuer_x = "".join(f"{b:02x}" for b in VARIANT_A.issuer_pub_x)
    issuer_y = "".join(f"{b:02x}" for b in VARIANT_A.issuer_pub_y)
    return {
        "schema": "swiyu.transcript-fixture.v1",
        "equivalence": "not_claimed",
        "mapping": {
            "format": "dc+sd-jwt",
            "profile": PROFILE,
            "query_id": QUERY_ID,
            "challenge_from": "transcript.challenge_nonce_hex",
            "givens": {
                "issuer": "issuer",
                "now_date": "now_date",
                "challenge_nonce": "challenge_nonce",
            },
            "challenge_fields": {
                "nonce": "nonce",
                "clientId": "client_id",
                "responseUri": "response_uri",
                "state": "state",
            },
            "signature_opaque": True,
        },
        "dcql_query": {
            "credentials": [{
                "id": QUERY_ID,
                "format": "dc+sd-jwt",
                "meta": {"vct_values": ["https://example.ch/vct/epfl-d10-test"]},
                "require_cryptographic_holder_binding": True,
                "claims": [{"id": "birth_date", "path": ["birth_date"]}],
                "x_swiyu_zkp": {
                    "profile": PROFILE,
                    "circuit_id": CIRCUIT_ID,
                    "now_date": NOW_DATE,
                    "issuer_pub_x": issuer_x,
                    "issuer_pub_y": issuer_y,
                },
            }]
        },
        "proof_path": "/proof_b64",
        "variants": [
            _variant(VARIANT_A.variant_id, VARIANT_A),
            _variant(VARIANT_B.variant_id, VARIANT_B),
        ],
    }


def main() -> None:
    sys.stdout.write(json.dumps(build_document(), separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()

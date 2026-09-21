#!/usr/bin/env python3
"""OpenAC age-25 transcript factory for the shared holder/challenge claim.

Reuses the EPFL synthetic dc+sd-jwt adults so both backends present the same
hidden birth dates and the same public given. Does not claim equivalence.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

EPFL = Path(__file__).resolve().parent.parent / "epfl"
if str(EPFL) not in sys.path:
    sys.path.insert(0, str(EPFL))

from fixtures import ISSUER_ID, KEY_ID, NOW_DATE, VARIANT_A, VARIANT_B, VCT, fixture_bundle  # noqa: E402

PROFILE = "openac-age25-jwt-v0"
CIRCUIT_ID = "swiyu_age25_jwt"
QUERY_ID = "birth_date"
CHALLENGE = "71904c78267613800be90ce2b62f3ef571de0a94eb2f41d2053d8aa58f528f90"


def _variant(variant_id: str) -> dict:
    bundle = fixture_bundle(variant_id, CHALLENGE)
    given = bundle["given"]
    return {
        "id": f"openac-{variant_id}",
        "credential": {"format": "dc+sd-jwt", "data": bundle["credential"]},
        "given": given,
        "prepare": {
            "profile": PROFILE,
            "credential": {
                "format": "dc+sd-jwt",
                "data": bundle["credential"],
                "variant": variant_id,
            },
            "context": {
                "lookup": {
                    "issuer": ISSUER_ID,
                    "kid": KEY_ID,
                    "vct": VCT,
                }
            },
        },
        "present": {
            "profile": PROFILE,
            "request_context": {
                "now_date": NOW_DATE,
                "challenge_nonce": CHALLENGE,
            },
            "inputs": {},
        },
        "verify": {
            "profile": PROFILE,
            "request_context": {
                "now_date": NOW_DATE,
                "challenge_nonce": CHALLENGE,
            },
            "inputs": {},
        },
        "compact_sd_jwt_sha256": hashlib.sha256(bundle["credential"].encode("ascii")).hexdigest(),
    }


def build_document() -> dict:
    return {
        "schema": "swiyu.transcript-fixture.v1",
        "equivalence": "not_claimed",
        "mapping": {
            "format": "dc+sd-jwt",
            "profile": PROFILE,
            "query_id": QUERY_ID,
            "challenge_from": "present.request_context",
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
                },
            }]
        },
        "proof_path": "/proof",
        "variants": [
            _variant(VARIANT_A.variant_id),
            _variant(VARIANT_B.variant_id),
        ],
        "issuer_id": ISSUER_ID,
    }


def main() -> None:
    sys.stdout.write(json.dumps(build_document(), separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()

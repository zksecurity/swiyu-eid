#!/usr/bin/env python3
"""Cross-language EPFL OID4VP challenge digest (swiyu-show-v1)."""
from __future__ import annotations

import hashlib
import json
import struct
from typing import Any

DOMAIN = b"swiyu-show-v1\x00"
PROFILE = "epfl-d10-swiyu-jwt-age25-v0"
CIRCUIT_ID = "d10_swiyu_jwt"


def policy_inputs_json(circuit_id: str, issuer_pub_x: str, issuer_pub_y: str, now_date: int) -> str:
    payload = {
        "circuit_id": circuit_id,
        "issuer_pub_x": issuer_pub_x,
        "issuer_pub_y": issuer_pub_y,
        "now_date": now_date,
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def _length_prefix(value: str) -> bytes:
    encoded = value.encode("utf-8")
    if not 1 <= len(encoded) <= 4096:
        raise ValueError("field UTF-8 length must be in 1..4096")
    return struct.pack(">I", len(encoded)) + encoded


def digest_hex(
    nonce: str,
    client_id: str,
    response_uri: str,
    state: str,
    query_id: str,
    profile: str,
    policy_inputs: str,
) -> str:
    if profile != PROFILE:
        raise ValueError(f"unsupported profile: {profile}")
    parts = [DOMAIN]
    for field in (nonce, client_id, response_uri, state, query_id, profile, policy_inputs):
        parts.append(_length_prefix(field))
    return hashlib.sha256(b"".join(parts)).hexdigest()


def digest_from_expected(expected: dict[str, Any]) -> str:
    policy_inputs = policy_inputs_json(
        expected["circuit_id"],
        _hex_from_coords(expected["issuer_pub_x"]),
        _hex_from_coords(expected["issuer_pub_y"]),
        int(expected["now_date"]),
    )
    return digest_hex(
        expected["nonce"],
        expected["client_id"],
        expected["response_uri"],
        expected["state"],
        expected["query_id"],
        expected["profile"],
        policy_inputs,
    )


def _hex_from_coords(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "".join(f"{int(item):02x}" for item in value)
    raise TypeError("issuer coordinate must be hex or u8 list")


def coords_to_u8_list(value: Any) -> list[int]:
    if isinstance(value, list):
        out = [int(item) for item in value]
        if len(out) != 32:
            raise ValueError("coordinate must be 32 bytes")
        return out
    if isinstance(value, str):
        raw = bytes.fromhex(value)
        if len(raw) != 32:
            raise ValueError("coordinate must be 32 bytes")
        return list(raw)
    raise TypeError("coordinate must be hex or u8 list")

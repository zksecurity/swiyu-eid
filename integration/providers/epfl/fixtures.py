#!/usr/bin/env python3
"""Deterministic EPFL d10 synthetic SD-JWT + Prover.toml witness bundles."""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature

NOW_DATE = 20240101
MIN_AGE_YEARS = "25"  # circuit-fixed literal; matches claim where const
ISSUER_ID = "did:example:epfl-test-issuer"
# Matches d10_swiyu_jwt ENCODED_HEADER constant (typ JWT, not dc+sd-jwt wire header).
CIRCUIT_ENCODED_HEADER = bytes([
    101, 121, 74, 48, 101, 88, 65, 105, 79, 105, 74, 75, 86, 49, 81, 105, 76, 67, 74, 104, 98, 71,
    99, 105, 79, 105, 74, 70, 85, 122, 73, 49, 78, 105, 74, 57,
])
KEY_ID = "epfl-test-key-1"
VCT = "https://example.ch/vct/epfl-d10-test"
STATUS_URI = "https://example.ch/status/epfl-test"
STATUS_INDEX = 0

# Deterministic test keys (never production).
ISSUER_PRIVATE = int("cafebabe" * 8, 16)
HOLDER_PRIVATE = int("deadbeef" * 8, 16)


N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
HALF_N = N // 2


def _fix_malleability(signature: bytes) -> bytes:
    s_int = int.from_bytes(signature[32:], "big")
    if s_int > HALF_N:
        return signature[:32] + (N - s_int).to_bytes(32, "big")
    return signature


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _jwk_from_private(key_int: int, kid: str | None = None) -> dict[str, str]:
    private = ec.derive_private_key(key_int, ec.SECP256R1())
    numbers = private.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(numbers.x.to_bytes(32, "big")),
        "y": _b64url(numbers.y.to_bytes(32, "big")),
    }
    if kid:
        jwk["kid"] = kid
    return jwk


def _pub_xy_bytes(jwk: dict[str, str]) -> tuple[list[int], list[int]]:
    x = list(base64.urlsafe_b64decode(jwk["x"] + "=="))
    y = list(base64.urlsafe_b64decode(jwk["y"] + "=="))
    return x[-32:], y[-32:]


def _sign_es256(signing_input: str, key_int: int) -> str:
    return _b64url(_sign_es256_bytes(signing_input.encode("ascii"), key_int))


def _sign_es256_bytes(signing_input: bytes, key_int: int) -> bytes:
    private = ec.derive_private_key(key_int, ec.SECP256R1())
    der = private.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = _der_to_rs(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _der_to_rs(der: bytes) -> tuple[int, int]:
    if der[0] != 0x30:
        raise ValueError("bad der")
    idx = 2
    if der[idx] != 0x02:
        raise ValueError("bad der")
    rlen = der[idx + 1]
    r = int.from_bytes(der[idx + 2 : idx + 2 + rlen], "big")
    idx = idx + 2 + rlen
    if der[idx] != 0x02:
        raise ValueError("bad der")
    slen = der[idx + 1]
    s = int.from_bytes(der[idx + 2 : idx + 2 + slen], "big")
    return r, s


def _disclosure(salt: str, name: str, value: str) -> str:
    raw = json.dumps([salt, name, value], separators=(",", ":"))
    return _b64url(raw.encode("utf-8"))


def _digest(encoded: str) -> str:
    return _b64url(hashlib.sha256(encoded.encode("ascii")).digest())


def sign_holder_challenge(challenge: bytes, holder_key_int: int = HOLDER_PRIVATE) -> str:
    private = ec.derive_private_key(holder_key_int, ec.SECP256R1())
    der = private.sign(challenge, ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = _der_to_rs(der)
    return _b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def sign_device_raw(challenge: list[int], holder_key_int: int = HOLDER_PRIVATE) -> list[int]:
    sig_b64 = sign_holder_challenge(bytes(challenge), holder_key_int)
    raw = _fix_malleability(base64.urlsafe_b64decode(sig_b64 + "=="))
    return list(raw)


@dataclass(frozen=True)
class EpflVariant:
    variant_id: str
    birth_date: str
    compact_sd_jwt: str
    issuer_pub_x: list[int]
    issuer_pub_y: list[int]
    payload_storage: list[int]
    payload_len: int
    dob_salt: list[int]
    dob_value: list[int]
    dob_salt_len: int
    dob_value_len: int
    dob_sd_offset: int
    x_offset: int
    y_offset: int
    jwt_signature: list[int]
    holder_jwk: dict[str, str]


def _build_variant(variant_id: str, birth_date: str, salt: str) -> EpflVariant:
    issuer_jwk = _jwk_from_private(ISSUER_PRIVATE, KEY_ID)
    holder_jwk = _jwk_from_private(HOLDER_PRIVATE)
    issuer_x, issuer_y = _pub_xy_bytes(issuer_jwk)
    dob_disc = _disclosure(salt, "birth_date", birth_date)
    dob_digest = _digest(dob_disc)
    payload_obj = {
        "iss": ISSUER_ID,
        "vct": VCT,
        "nbf": 1700000000,
        "exp": 2000000000,
        "iat": 1700000000,
        "cnf": {"jwk": holder_jwk},
        "status": {"status_list": {"uri": STATUS_URI, "idx": STATUS_INDEX}},
        "_sd_alg": "sha-256",
        "_sd": [dob_digest],
    }
    payload_json = json.dumps(payload_obj, separators=(",", ":"))
    payload_b64 = _b64url(payload_json.encode())
    sdjwt_header = _b64url(
        json.dumps({"alg": "ES256", "typ": "dc+sd-jwt", "kid": KEY_ID}, separators=(",", ":")).encode()
    )
    sdjwt_signing_input = f"{sdjwt_header}.{payload_b64}"
    sdjwt_sig = _sign_es256(sdjwt_signing_input, ISSUER_PRIVATE)
    compact = f"{sdjwt_signing_input}.{sdjwt_sig}~{dob_disc}~"
    circuit_signing_input = CIRCUIT_ENCODED_HEADER + b"." + payload_b64.encode("ascii")
    circuit_sig = _fix_malleability(_sign_es256_bytes(circuit_signing_input, ISSUER_PRIVATE))
    payload_storage = [ord(c) for c in payload_json]
    payload_storage.extend([0] * (2048 - len(payload_storage)))
    dob_salt_bytes = [ord(c) for c in salt]
    dob_salt_storage = dob_salt_bytes + [0] * (32 - len(dob_salt_bytes))
    dob_value_bytes = [ord(c) for c in birth_date]
    dob_value_storage = dob_value_bytes + [0] * (16 - len(dob_value_bytes))
    dob_sd_offset = payload_json.index(dob_digest)
    x_marker = f'"x":"{holder_jwk["x"]}"'
    y_marker = f'"y":"{holder_jwk["y"]}"'
    x_offset = payload_json.index(x_marker)
    y_offset = payload_json.index(y_marker)
    jwt_sig_bytes = list(circuit_sig)
    return EpflVariant(
        variant_id=variant_id,
        birth_date=birth_date,
        compact_sd_jwt=compact,
        issuer_pub_x=issuer_x,
        issuer_pub_y=issuer_y,
        payload_storage=payload_storage[:2048],
        payload_len=len(payload_json),
        dob_salt=dob_salt_storage,
        dob_value=dob_value_storage,
        dob_salt_len=len(dob_salt_bytes),
        dob_value_len=len(dob_value_bytes),
        dob_sd_offset=dob_sd_offset,
        x_offset=x_offset,
        y_offset=y_offset,
        jwt_signature=jwt_sig_bytes,
        holder_jwk=holder_jwk,
    )


VARIANT_A = _build_variant("epfl-adult-a", "1988-06-19", "S0KVAeqMhfEh7khZxn0fRww")
VARIANT_B = _build_variant("epfl-adult-b", "1985-03-12", "T1LWBeqNigFi8liAyo1gSxx")
VARIANTS = {v.variant_id: v for v in (VARIANT_A, VARIANT_B)}


def canonical_given(challenge_hex: str) -> dict[str, Any]:
    issuer_jwk = _jwk_from_private(ISSUER_PRIVATE, KEY_ID)
    return {
        "issuer": {
            "public_key": issuer_jwk,
            "issuer_id": ISSUER_ID,
            "key_id": KEY_ID,
            "allowed_vcts": [VCT],
        },
        "now_date": NOW_DATE,
        "challenge_nonce": challenge_hex,
    }


def fixture_bundle(variant_id: str, challenge_hex: str) -> dict[str, Any]:
    variant = VARIANTS[variant_id]
    given = canonical_given(challenge_hex)
    challenge_bytes = bytes.fromhex(challenge_hex)
    holder_sig = sign_holder_challenge(challenge_bytes)
    return {
        "variant_id": variant_id,
        "credential": variant.compact_sd_jwt,
        "given": given,
        "fixture": {
            "credential": variant.compact_sd_jwt,
            "holder_signature": holder_sig,
            "presentation_context": challenge_hex,
        },
        "witness": variant,
    }


def write_prover_toml(variant: EpflVariant, challenge: list[int], path) -> None:
    device_sig = sign_device_raw(challenge)
    lines = [
        f"jwt_signature = {json.dumps(variant.jwt_signature)}",
        f"issuer_pub_x = {json.dumps(variant.issuer_pub_x)}",
        f"issuer_pub_y = {json.dumps(variant.issuer_pub_y)}",
        f"dob_sd_offset = {variant.dob_sd_offset}",
        f"x_offset = {variant.x_offset}",
        f"y_offset = {variant.y_offset}",
        f"now_date = {NOW_DATE}",
        f"challenge_nonce = {json.dumps(challenge)}",
        f"device_signature = {json.dumps(device_sig)}",
        f"payload.len = {variant.payload_len}",
        f"payload.storage = {json.dumps(variant.payload_storage)}",
        f"dob_salt.len = {variant.dob_salt_len}",
        f"dob_salt.storage = {json.dumps(variant.dob_salt)}",
        f"dob_value.len = {variant.dob_value_len}",
        f"dob_value.storage = {json.dumps(variant.dob_value)}",
        "",
    ]
    path.write_text("\n".join(lines))


def fresh_challenge_hex(seed: bytes) -> str:
    return hashlib.sha256(seed).hexdigest()


_CHALLENGE_RE = re.compile(r"^[0-9a-f]{64}$")

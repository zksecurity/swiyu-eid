"""Local SD-JWT ES256 fixture builder for credentials RED tests."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_int32(value: int) -> str:
    return _b64url(value.to_bytes(32, "big"))


def _public_jwk(key: ec.EllipticCurvePrivateKey, *, kid: str | None = None) -> dict[str, str]:
    numbers = key.public_key().public_numbers()
    jwk: dict[str, str] = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url_int32(numbers.x),
        "y": _b64url_int32(numbers.y),
    }
    if kid is not None:
        jwk["kid"] = kid
    return jwk


def _disclosure(salt: str, claim_name: str, claim_value: Any) -> tuple[str, str]:
    encoded = _b64url(
        json.dumps([salt, claim_name, claim_value], separators=(",", ":")).encode("utf-8")
    )
    digest = _b64url(hashlib.sha256(encoded.encode("ascii")).digest())
    return encoded, digest


def _sign_es256(private_key: ec.EllipticCurvePrivateKey, signing_input: str) -> str:
    der_signature = private_key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    return _b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


@dataclass(frozen=True)
class SdJwtFixture:
    compact: str
    issuer_record: dict[str, Any]
    attribute_definitions: dict[str, str]
    attributes: dict[str, Any]


class SdJwtFixtureBuilder:
    """Build signed SD-JWT credentials for public-interface tests."""

    def __init__(self, *, seed: int = 1) -> None:
        self._seed = seed
        self._issuer_key = ec.generate_private_key(ec.SECP256R1())
        self._holder_key = ec.generate_private_key(ec.SECP256R1())
        self._issuer_id = f"synthetic-issuer-{seed}"
        self._key_id = f"synthetic-key-{seed}"
        self._vct = "swiyu.synthetic-eid@0"

    def build(
        self,
        attributes: dict[str, Any] | None = None,
        *,
        include_unreachable: str | None = None,
        iat: int | None = None,
        duplicate_sd: bool = False,
        nested_value: bool = False,
        bool_nbf: bool = False,
        extra_payload: dict[str, Any] | None = None,
    ) -> SdJwtFixture:
        attrs = {
            "birthdate": "2000-01-01",
            "nationality": "CH",
            "residence": "CH",
        }
        if attributes:
            attrs.update(attributes)

        disclosures: list[str] = []
        sd_hashes: list[str] = []
        for index, (name, value) in enumerate(attrs.items()):
            claim_value: Any = {"nested": value} if nested_value and name == "birthdate" else value
            encoded, digest = _disclosure(f"salt-{self._seed}-{index}", name, claim_value)
            disclosures.append(encoded)
            sd_hashes.append(digest)

        if include_unreachable is not None:
            encoded, _digest = _disclosure(
                f"unreachable-{self._seed}",
                include_unreachable,
                "UNREACHABLE",
            )
            disclosures.append(encoded)

        header = {
            "alg": "ES256",
            "typ": "dc+sd-jwt",
            "kid": self._key_id,
        }
        payload = {
            "iss": self._issuer_id,
            "vct": self._vct,
            "nbf": True if bool_nbf else 1_700_000_000,
            "exp": 1_900_000_000,
            "cnf": {"jwk": _public_jwk(self._holder_key)},
            "status": {
                "status_list": {
                    "uri": "https://status.example/synthetic-list",
                    "idx": 2,
                }
            },
            "_sd_alg": "sha-256",
            "_sd": list(sd_hashes) + ([sd_hashes[0]] if duplicate_sd and sd_hashes else []),
        }
        if iat is not None:
            payload["iat"] = iat
        if extra_payload:
            payload.update(extra_payload)

        encoded_header = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        encoded_payload = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{encoded_header}.{encoded_payload}"
        signature = _sign_es256(self._issuer_key, signing_input)
        issuer_jwt = f"{signing_input}.{signature}"
        compact = issuer_jwt + "~" + "~".join(disclosures) + "~"

        issuer_record = {
            "public_key": _public_jwk(self._issuer_key, kid=self._key_id),
            "issuer_id": self._issuer_id,
            "key_id": self._key_id,
            "allowed_vcts": [self._vct],
        }
        attribute_definitions = {alias: alias for alias in attrs}
        return SdJwtFixture(
            compact=compact,
            issuer_record=issuer_record,
            attribute_definitions=attribute_definitions,
            attributes=attrs,
        )

    def tamper_disclosure_value(self, compact: str, claim_name: str, new_value: Any) -> str:
        parts = compact.split("~")
        issuer_jwt = parts[0]
        disclosures = parts[1:-1] if parts[-1] == "" else parts[1:]
        tampered: list[str] = []
        for disclosure in disclosures:
            raw = json.loads(base64.urlsafe_b64decode(disclosure + "==").decode("utf-8"))
            if raw[1] == claim_name:
                raw[2] = new_value
                tampered.append(
                    _b64url(json.dumps(raw, separators=(",", ":")).encode("utf-8"))
                )
            else:
                tampered.append(disclosure)
        return issuer_jwt + "~" + "~".join(tampered) + "~"

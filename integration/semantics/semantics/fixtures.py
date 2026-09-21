"""Synthetic fixture factory for claim evaluation campaigns."""

from __future__ import annotations

import base64
import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from semantics.assertions import expected_transcript
from semantics.claims import Claim, ClaimError, validate_claim
from semantics.claim_types import parse_type_name

SECP256R1_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
KEY_DOMAIN = b"swiyu-fixture-key-v1"

DEFAULT_NOW = "1800000000"
DEFAULT_DATE = "2008-01-01"
DEFAULT_ATTR_DATE = "2000-01-01"
DEFAULT_CODE2 = "CH"
DEFAULT_UTF8 = "synthetic"
DEFAULT_NBF = 1_700_000_000
DEFAULT_EXP = 1_900_000_000
DEFAULT_STATUS_INDEX = 2
DEFAULT_LIST_LENGTH = 8
DEFAULT_STATUS_URI = "https://status.example/synthetic-list"
DEFAULT_SESSION = {
    "nonce": "nonce-1",
    "client_id": "client-1",
    "response_uri": "https://verifier.example/response",
    "state": "state-1",
    "query_id": "query-1",
}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_int32(value: int) -> str:
    return _b64url(value.to_bytes(32, "big"))


def derive_fixture_private_key(seed: int, role: str) -> ec.EllipticCurvePrivateKey:
    """Domain-separated deterministic P-256 private key for synthetic fixtures."""
    material = hashlib.sha256(
        KEY_DOMAIN + b"\0" + str(int(seed)).encode("ascii") + b"\0" + role.encode("utf-8")
    ).digest()
    scalar = int.from_bytes(material, "big") % (SECP256R1_ORDER - 1) + 1
    return ec.derive_private_key(scalar, ec.SECP256R1())


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
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    signature = private_key.sign(
        signing_input.encode("ascii"),
        ec.ECDSA(hashes.SHA256(), deterministic_signing=True),
    )
    r, s = decode_dss_signature(signature)
    return _b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _leaf_hash(index: int, bit: int) -> bytes:
    return hashlib.sha256(b"\x00" + index.to_bytes(4, "big") + bytes([bit])).digest()


def _parent_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _build_status_tree(list_length: int) -> tuple[str, list[list[bytes]]]:
    level = [_leaf_hash(i, 0) for i in range(list_length)]
    levels = [level]
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            nxt.append(_parent_hash(level[i], level[i + 1]))
        level = nxt
        levels.append(level)
    return level[0].hex(), levels


def _status_siblings(levels: list[list[bytes]], index: int) -> list[str]:
    siblings: list[str] = []
    pos = index
    for level_idx in range(len(levels) - 1):
        level = levels[level_idx]
        sibling = level[pos + 1] if pos % 2 == 0 else level[pos - 1]
        siblings.append(sibling.hex())
        pos //= 2
    return siblings


@dataclass
class _SigningMaterial:
    issuer_key: ec.EllipticCurvePrivateKey
    holder_key: ec.EllipticCurvePrivateKey
    issuer_id: str
    key_id: str
    vct: str


def _as_claim(claim: Any) -> Claim:
    if isinstance(claim, Claim):
        checked = validate_claim(claim.document)
        if checked.statement_digest != claim.statement_digest or checked.dependencies != claim.dependencies:
            raise ClaimError("claim identity mismatch")
        return checked
    if isinstance(claim, dict):
        return validate_claim(claim)
    raise ClaimError("invalid claim")


def _attribute_paths(document: dict[str, Any]) -> dict[str, tuple[str, str]]:
    paths: dict[str, tuple[str, str]] = {}
    for alias, spec in document.get("attributes", {}).items():
        path = spec["path"]
        name = path[0] if isinstance(path, list) else path
        paths[alias] = (name, spec["type"])
    return paths


def _default_for_type(type_name: str) -> Any:
    base, element, _ = parse_type_name(type_name)
    if base == "set":
        if element == "ascii-code2@1":
            return ["CH", "DE"]
        if element == "swiyu.date@0":
            return [DEFAULT_ATTR_DATE]
        if element == "utf8@1":
            return [DEFAULT_UTF8]
        return ["CH"]
    if type_name == "swiyu.unix-seconds@0":
        return DEFAULT_NOW
    if type_name == "swiyu.date@0":
        return DEFAULT_DATE
    if type_name == "ascii-code2@1":
        return DEFAULT_CODE2
    if type_name == "utf8@1":
        return DEFAULT_UTF8
    if type_name == "platform.expected-session@1":
        return deepcopy(DEFAULT_SESSION)
    return None


def _default_attribute_value(type_name: str) -> Any:
    if type_name == "swiyu.date@0":
        return DEFAULT_ATTR_DATE
    if type_name == "ascii-code2@1":
        return DEFAULT_CODE2
    if type_name == "swiyu.unix-seconds@0":
        return DEFAULT_NOW
    return DEFAULT_UTF8


def _issue_credential(
    material: _SigningMaterial,
    attributes: dict[str, Any],
    *,
    nbf: int = DEFAULT_NBF,
    exp: int = DEFAULT_EXP,
    status_uri: str = DEFAULT_STATUS_URI,
    status_index: int = DEFAULT_STATUS_INDEX,
    seed: int = 1,
    iat: int | None = None,
) -> str:
    disclosures: list[str] = []
    sd_hashes: list[str] = []
    for index, (claim_name, value) in enumerate(attributes.items()):
        encoded, digest = _disclosure(f"salt-{seed}-{index}", claim_name, value)
        disclosures.append(encoded)
        sd_hashes.append(digest)

    header = {"alg": "ES256", "typ": "dc+sd-jwt", "kid": material.key_id}
    payload: dict[str, Any] = {
        "iss": material.issuer_id,
        "vct": material.vct,
        "nbf": nbf,
        "exp": exp,
        "cnf": {"jwk": _public_jwk(material.holder_key)},
        "status": {"status_list": {"uri": status_uri, "idx": status_index}},
        "_sd_alg": "sha-256",
        "_sd": sd_hashes,
    }
    if iat is not None:
        payload["iat"] = iat
    encoded_header = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    encoded_payload = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_payload}"
    signature = _sign_es256(material.issuer_key, signing_input)
    return f"{signing_input}.{signature}~" + "~".join(disclosures) + "~"


def _sign_holder(holder_key: ec.EllipticCurvePrivateKey, digest: bytes) -> str:
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    signature = holder_key.sign(
        digest,
        ec.ECDSA(Prehashed(hashes.SHA256()), deterministic_signing=True),
    )
    r, s = decode_dss_signature(signature)
    return _b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _deep_merge(base: Any, override: Any) -> Any:
    if isinstance(base, dict) and isinstance(override, dict):
        out = dict(base)
        for key, value in override.items():
            if key in out and isinstance(out[key], dict) and isinstance(value, dict):
                out[key] = _deep_merge(out[key], value)
            else:
                out[key] = deepcopy(value)
        return out
    return deepcopy(override)


def _given_type(spec: Any) -> str:
    if isinstance(spec, dict):
        return spec["type"]
    return spec


def make_fixture(
    claim: Any,
    attributes: dict[str, Any] | None = None,
    given_overrides: dict[str, Any] | None = None,
    *,
    seed: int = 1,
    nbf: int = DEFAULT_NBF,
    exp: int = DEFAULT_EXP,
) -> dict[str, dict[str, Any]]:
    """Build a coherent signed fixture and frozen given inputs.

    Optional keyword ``nbf`` / ``exp`` set credential validity window for
    boundary-test recipes without reimplementing issuance.
    """
    validated = _as_claim(claim)
    document = validated.document
    paths = _attribute_paths(document)

    attrs: dict[str, Any] = {}
    for alias, (_path_name, type_name) in paths.items():
        if attributes and alias in attributes:
            attrs[alias] = attributes[alias]
        else:
            attrs[alias] = _default_attribute_value(type_name)

    issuer_key = derive_fixture_private_key(seed, "issuer")
    holder_key = derive_fixture_private_key(seed, "holder")
    issuer_id = f"synthetic-issuer-{seed}"
    key_id = f"synthetic-key-{seed}"
    vct = "swiyu.synthetic-eid@0"
    material = _SigningMaterial(
        issuer_key=issuer_key,
        holder_key=holder_key,
        issuer_id=issuer_id,
        key_id=key_id,
        vct=vct,
    )

    given_spec = document.get("given", {})
    given: dict[str, Any] = {}
    status_name: str | None = None
    issuer_name: str | None = None
    for name, spec in given_spec.items():
        type_name = _given_type(spec)
        if type_name == "platform.expected-issuer@1":
            issuer_name = name
            given[name] = {
                "public_key": _public_jwk(issuer_key, kid=key_id),
                "issuer_id": issuer_id,
                "key_id": key_id,
                "allowed_vcts": [vct],
            }
        elif type_name == "platform.expected-status@1":
            status_name = name
            given[name] = {
                "id": "status-snapshot-1",
                "issuer_id": issuer_id,
                "key_id": key_id,
                "subject": DEFAULT_STATUS_URI,
                "commitment": "",
                "epoch": "1",
                "list_length": DEFAULT_LIST_LENGTH,
                "valid_before": "1900000000",
            }
        else:
            default = _default_for_type(type_name)
            if default is None:
                raise ClaimError("unsupported given type")
            given[name] = default

    if given_overrides:
        for key, value in given_overrides.items():
            if key not in given_spec:
                given[key] = deepcopy(value)
            else:
                given[key] = _deep_merge(given.get(key), value)

    list_length = DEFAULT_LIST_LENGTH
    status_index = DEFAULT_STATUS_INDEX
    status_uri = DEFAULT_STATUS_URI
    if status_name is not None:
        list_length = given[status_name].get("list_length", DEFAULT_LIST_LENGTH)
        status_uri = given[status_name].get("subject", DEFAULT_STATUS_URI)
        commitment, levels = _build_status_tree(list_length)
        status_override = (given_overrides or {}).get(status_name)
        commitment_overridden = isinstance(status_override, dict) and "commitment" in status_override
        if not commitment_overridden:
            given[status_name]["commitment"] = commitment
        else:
            _, levels = _build_status_tree(list_length)
        issuer_override = (given_overrides or {}).get(issuer_name) if issuer_name else None
        if not (isinstance(issuer_override, dict) and "issuer_id" in issuer_override):
            given[status_name]["issuer_id"] = given[issuer_name]["issuer_id"] if issuer_name else issuer_id
        if not (isinstance(issuer_override, dict) and "key_id" in issuer_override):
            given[status_name]["key_id"] = given[issuer_name]["key_id"] if issuer_name else key_id
    else:
        commitment, levels = _build_status_tree(list_length)

    if issuer_name is not None:
        issuer_override = (given_overrides or {}).get(issuer_name)
        if not isinstance(issuer_override, dict) or "public_key" not in issuer_override:
            given[issuer_name]["public_key"] = _public_jwk(issuer_key, kid=given[issuer_name].get("key_id", key_id))
        if not isinstance(issuer_override, dict) or "key_id" not in issuer_override:
            given[issuer_name]["key_id"] = key_id
            given[issuer_name]["public_key"]["kid"] = key_id
        if not isinstance(issuer_override, dict) or "issuer_id" not in issuer_override:
            given[issuer_name]["issuer_id"] = issuer_id
        if not isinstance(issuer_override, dict) or "allowed_vcts" not in issuer_override:
            given[issuer_name]["allowed_vcts"] = [vct]

    disclosure_values = {paths[alias][0]: value for alias, value in attrs.items()}
    compact = _issue_credential(
        material,
        disclosure_values,
        nbf=nbf,
        exp=exp,
        status_uri=status_uri,
        status_index=status_index,
        seed=seed,
    )
    transcript = expected_transcript(validated, given)
    fixture: dict[str, Any] = {
        "credential": compact,
        "holder_signature": _sign_holder(holder_key, transcript),
        "presentation_context": transcript.hex(),
    }
    if status_name is not None:
        fixture["status_witness"] = {
            "index": status_index,
            "bit": 0,
            "siblings": _status_siblings(levels, status_index),
        }
    return {"fixture": fixture, "given": given}


def reauthorize_fixture(
    claim: Any,
    fixture: dict[str, Any],
    given: dict[str, Any],
    *,
    seed: int = 1,
) -> dict[str, dict[str, Any]]:
    """Rebuild holder authorization and context for an existing credential.

    Uses the same seed-derived holder key as ``make_fixture``. Does not
    reissue the issuer signature. Call after intentional given changes that
    must remain bound to the request digest.
    """
    validated = _as_claim(claim)
    holder_key = derive_fixture_private_key(seed, "holder")
    transcript = expected_transcript(validated, given)
    refreshed = dict(fixture)
    refreshed["holder_signature"] = _sign_holder(holder_key, transcript)
    refreshed["presentation_context"] = transcript.hex()
    return {"fixture": refreshed, "given": given}

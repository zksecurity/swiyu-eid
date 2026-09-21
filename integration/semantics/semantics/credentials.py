"""SD-JWT ES256 credential authentication."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from semantics.canonical import parse_json_strict

MAX_COMPACT_BYTES = 64 * 1024
MIN_DISCLOSURES = 1
MAX_DISCLOSURES = 16
MAX_UTF8 = 4096
UINT64_MAX = (1 << 64) - 1

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_B64URL32_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")

RESERVED_DISCLOSURE_NAMES = frozenset(
    {
        "iss",
        "sub",
        "aud",
        "exp",
        "nbf",
        "iat",
        "jti",
        "vct",
        "cnf",
        "status",
        "_sd",
        "_sd_alg",
    }
)


class CredentialError(ValueError):
    """Raised when credential authentication fails."""

    def __init__(self, message: str = "credential authentication failed") -> None:
        super().__init__(message)


@dataclass(frozen=True)
class AuthenticatedCredential:
    attributes: dict[str, Any]
    issuer_id: str
    key_id: str
    credential_type: str
    holder_key: dict[str, str]
    nbf: int
    exp: int
    status_uri: str
    status_index: int
    iat: int | None = None


def _fail(message: str) -> None:
    raise CredentialError(message) from None


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    if not isinstance(data, str) or not data or not _B64URL_RE.fullmatch(data):
        _fail("invalid base64url encoding")
    padding = "=" * (-len(data) % 4)
    try:
        raw = base64.urlsafe_b64decode(data + padding)
    except Exception:
        _fail("invalid base64url encoding")
    if _b64url_encode(raw) != data:
        _fail("noncanonical base64url encoding")
    return raw


def _require_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(f"invalid {label}")
    if value < 0 or value > UINT64_MAX:
        _fail(f"invalid {label}")
    return value


def _require_utf8(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"invalid {label}")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        _fail(f"invalid {label}")
    if len(encoded) > MAX_UTF8:
        _fail(f"invalid {label}")
    return value


def _parse_jwk_numbers(jwk: dict[str, Any], *, require_kid: bool) -> ec.EllipticCurvePublicKey:
    if not isinstance(jwk, dict):
        _fail("invalid JWK")
    allowed = {"kty", "crv", "x", "y", "kid"}
    keys = set(jwk.keys())
    if keys - allowed or "d" in jwk:
        _fail("unsafe JWK encoding")
    required = {"kty", "crv", "x", "y"}
    if require_kid:
        required.add("kid")
    if not required <= keys:
        _fail("invalid JWK")
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        _fail("unsupported JWK curve")
    if "kid" in jwk:
        _require_utf8(jwk["kid"], "kid")
    for coord in ("x", "y"):
        val = jwk.get(coord)
        if not isinstance(val, str) or not _B64URL32_RE.fullmatch(val):
            _fail("non-canonical JWK coordinates")
        raw = _b64url_decode(val)
        if len(raw) != 32:
            _fail("non-canonical JWK coordinates")
    try:
        x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    except CredentialError:
        raise
    except Exception:
        _fail("invalid curve point")


def _verify_es256(public_key: ec.EllipticCurvePublicKey, signing_input: str, signature: str) -> None:
    sig_bytes = _b64url_decode(signature)
    if len(sig_bytes) != 64:
        _fail("invalid signature length")
    r = int.from_bytes(sig_bytes[:32], "big")
    s = int.from_bytes(sig_bytes[32:], "big")
    der = encode_dss_signature(r, s)
    try:
        public_key.verify(der, signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    except Exception:
        _fail("signature verification failed")


def _disclosure_value_allowed(value: Any) -> bool:
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, int) and not isinstance(value, bool):
        return -UINT64_MAX <= value <= UINT64_MAX
    if isinstance(value, str):
        try:
            return len(value.encode("utf-8")) <= MAX_UTF8
        except UnicodeEncodeError:
            return False
    return False


def _decode_disclosure(encoded: str) -> tuple[str, Any]:
    try:
        raw_text = _b64url_decode(encoded).decode("utf-8")
        raw = parse_json_strict(raw_text)
    except CredentialError:
        raise
    except Exception:
        _fail("invalid disclosure encoding")
    if not isinstance(raw, list) or len(raw) != 3:
        _fail("invalid disclosure tuple")
    salt, claim_name, claim_value = raw
    if not isinstance(salt, str) or not isinstance(claim_name, str):
        _fail("invalid disclosure fields")
    try:
        if len(salt.encode("utf-8")) > MAX_UTF8 or len(claim_name.encode("utf-8")) > MAX_UTF8:
            _fail("invalid disclosure fields")
    except UnicodeEncodeError:
        _fail("invalid disclosure fields")
    if not claim_name:
        _fail("invalid disclosure fields")
    if isinstance(claim_value, (dict, list)):
        _fail("nested claim values are not permitted")
    if not _disclosure_value_allowed(claim_value):
        _fail("malformed disclosure value")
    if claim_name in RESERVED_DISCLOSURE_NAMES:
        _fail("reserved metadata disclosed as attribute")
    return claim_name, claim_value


def _disclosure_digest(encoded: str) -> str:
    return _b64url_encode(hashlib.sha256(encoded.encode("ascii")).digest())


def authenticate(
    compact_sd_jwt: str,
    issuer_record: dict[str, Any],
    attribute_definitions: dict[str, str],
) -> AuthenticatedCredential:
    if not isinstance(compact_sd_jwt, str) or len(compact_sd_jwt.encode("utf-8")) > MAX_COMPACT_BYTES:
        _fail("credential size out of bounds")
    if not compact_sd_jwt.endswith("~"):
        _fail("missing trailing disclosure separator")
    if compact_sd_jwt.count("~") < 2:
        _fail("missing disclosures")

    issuer_jwt, disclosure_blob = compact_sd_jwt[:-1].split("~", 1)
    disclosures = disclosure_blob.split("~") if disclosure_blob else []
    if not (MIN_DISCLOSURES <= len(disclosures) <= MAX_DISCLOSURES):
        _fail("disclosure count out of bounds")

    jwt_parts = issuer_jwt.split(".")
    if len(jwt_parts) != 3:
        _fail("invalid issuer JWT")
    for part in jwt_parts:
        _b64url_decode(part)

    try:
        header = parse_json_strict(_b64url_decode(jwt_parts[0]).decode("utf-8"))
        payload = parse_json_strict(_b64url_decode(jwt_parts[1]).decode("utf-8"))
    except CredentialError:
        raise
    except Exception:
        _fail("invalid JWT JSON")

    header_allowed = {"alg", "typ", "kid", "profile_version"}
    if not isinstance(header, dict) or not set(header.keys()).issubset(header_allowed):
        _fail("unexpected JWT header fields")
    if header.get("alg") != "ES256" or header.get("typ") != "dc+sd-jwt":
        _fail("unsupported JWT header")
    _require_utf8(header.get("kid"), "kid")
    if "profile_version" in header:
        _require_utf8(header["profile_version"], "profile_version")

    payload_required = {"iss", "vct", "nbf", "exp", "cnf", "status", "_sd_alg", "_sd"}
    payload_optional = {"iat"}
    if not isinstance(payload, dict):
        _fail("unexpected JWT payload fields")
    keys = set(payload.keys())
    if not payload_required <= keys or keys - payload_required - payload_optional:
        _fail("unexpected JWT payload fields")

    if payload.get("_sd_alg") != "sha-256":
        _fail("unsupported disclosure algorithm")
    sd_hashes = payload["_sd"]
    if not isinstance(sd_hashes, list) or not sd_hashes:
        _fail("invalid _sd")
    if any(not isinstance(item, str) for item in sd_hashes):
        _fail("invalid _sd")
    if len(sd_hashes) != len(set(sd_hashes)):
        _fail("duplicate _sd digest")

    nbf = _require_int(payload["nbf"], "nbf")
    exp = _require_int(payload["exp"], "exp")
    iat = _require_int(payload["iat"], "iat") if "iat" in payload else None
    iss = _require_utf8(payload["iss"], "iss")
    vct = _require_utf8(payload["vct"], "vct")

    cnf = payload["cnf"]
    if not isinstance(cnf, dict) or set(cnf.keys()) != {"jwk"}:
        _fail("invalid cnf")
    holder_key = cnf["jwk"]
    if not isinstance(holder_key, dict):
        _fail("invalid holder key")
    _parse_jwk_numbers(holder_key, require_kid=False)

    status = payload["status"]
    if not isinstance(status, dict) or set(status.keys()) != {"status_list"}:
        _fail("invalid status")
    status_list = status["status_list"]
    if not isinstance(status_list, dict) or set(status_list.keys()) != {"uri", "idx"}:
        _fail("invalid status_list")
    status_uri = _require_utf8(status_list["uri"], "status uri")
    status_index = _require_int(status_list["idx"], "status index")

    issuer_required = {"public_key", "issuer_id", "key_id", "allowed_vcts"}
    if not isinstance(issuer_record, dict) or set(issuer_record.keys()) != issuer_required:
        _fail("invalid issuer record")
    issuer_public = _parse_jwk_numbers(issuer_record["public_key"], require_kid=True)
    if issuer_record["key_id"] != issuer_record["public_key"]["kid"]:
        _fail("issuer key_id mismatch")
    if header["kid"] != issuer_record["key_id"]:
        _fail("issuer key substitution")

    signing_input = f"{jwt_parts[0]}.{jwt_parts[1]}"
    _verify_es256(issuer_public, signing_input, jwt_parts[2])

    seen_names: set[str] = set()
    digest_to_value: dict[str, tuple[str, Any]] = {}
    for encoded in disclosures:
        digest = _disclosure_digest(encoded)
        if digest in digest_to_value:
            _fail("duplicate disclosure digest")
        claim_name, claim_value = _decode_disclosure(encoded)
        if claim_name in seen_names:
            _fail("duplicate disclosed name")
        seen_names.add(claim_name)
        digest_to_value[digest] = (claim_name, claim_value)

    if set(sd_hashes) != set(digest_to_value):
        _fail("unreachable disclosure")

    if not isinstance(attribute_definitions, dict):
        _fail("invalid attribute definition")
    attributes: dict[str, Any] = {}
    for alias, path_name in attribute_definitions.items():
        if not isinstance(alias, str) or not isinstance(path_name, str):
            _fail("invalid attribute definition")
        if path_name in RESERVED_DISCLOSURE_NAMES:
            _fail("reserved attribute path")
        if "/" in path_name or "." in path_name:
            _fail("nested claim paths are not permitted")
        matched = False
        for digest in sd_hashes:
            name, value = digest_to_value[digest]
            if name == path_name:
                attributes[alias] = value
                matched = True
                break
        if not matched:
            _fail("missing disclosed attribute")

    return AuthenticatedCredential(
        attributes=attributes,
        issuer_id=iss,
        key_id=header["kid"],
        credential_type=vct,
        holder_key=dict(holder_key),
        nbf=nbf,
        exp=exp,
        status_uri=status_uri,
        status_index=status_index,
        iat=iat,
    )

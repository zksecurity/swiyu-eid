"""Runtime type validation for claim attributes and given inputs."""

from __future__ import annotations

import base64
import calendar
import copy
import re
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec


class ClaimError(ValueError):
    """Raised when claim documents, types, or operands are invalid."""

_DATE_RE = re.compile(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})$")
_ASCII_CODE2_RE = re.compile(r"^[A-Z]{2}$")
_UINT64_RE = re.compile(r"^(0|[1-9][0-9]*)$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_B64URL32_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")

_DATE_MIN_YEAR = 1900
_DATE_MAX_YEAR = 2199
_UTF8_MAX_BYTES = 4096
_SET_MAX_ITEMS = 16
_ALLOWLIST_MAX_ITEMS = 16

KNOWN_TYPES = frozenset(
    {
        "swiyu.date@0",
        "swiyu.date-yyyymmdd@0",
        "swiyu.unix-seconds@0",
        "ascii-code2@1",
        "utf8@1",
        "platform.expected-issuer@1",
        "platform.expected-session@1",
        "platform.expected-status@1",
        "platform.expected-challenge@1",
    }
)

RESERVED_ATTRIBUTE_PATHS = frozenset(
    {"iss", "vct", "nbf", "exp", "cnf", "status", "_sd", "_sd_alg", "iat"}
)

GIVEN_ARG_TYPES = {
    "issuer": "platform.expected-issuer@1",
    "time": "swiyu.unix-seconds@0",
    "reference": "platform.expected-status@1",
    "session": "platform.expected-session@1",
    "challenge": "platform.expected-challenge@1",
}


def parse_type_name(type_name: str) -> tuple[str, str | None, int | None]:
    """Return (base_type, element_type, max_items) for scalar or set types."""
    if not isinstance(type_name, str):
        raise ClaimError("invalid type name")
    if type_name.startswith("set<") and type_name.endswith(">"):
        inner = type_name[4:-1]
        return ("set", inner, None)
    return (type_name, None, None)


def validate_type_name(type_name: str) -> None:
    base, element, _ = parse_type_name(type_name)
    if base == "set":
        if element not in {"swiyu.date@0", "swiyu.unix-seconds@0", "ascii-code2@1", "utf8@1"}:
            raise ClaimError("unknown element type")
        return
    if base not in KNOWN_TYPES:
        raise ClaimError("unknown type")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _valid_date(value: str) -> bool:
    match = _DATE_RE.fullmatch(value)
    if not match:
        return False
    year, month, day = (int(match.group(i)) for i in range(1, 4))
    if year < _DATE_MIN_YEAR or year > _DATE_MAX_YEAR:
        return False
    if month < 1 or month > 12:
        return False
    max_day = calendar.monthrange(year, month)[1]
    return 1 <= day <= max_day


def _valid_uint64_string(value: str) -> bool:
    if not isinstance(value, str) or not _UINT64_RE.fullmatch(value):
        return False
    try:
        n = int(value)
    except ValueError:
        return False
    return 0 <= n <= (1 << 64) - 1


def _valid_utf8(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return 0 < len(encoded) <= _UTF8_MAX_BYTES


def _valid_ascii_code2(value: str) -> bool:
    return isinstance(value, str) and bool(_ASCII_CODE2_RE.fullmatch(value))


def _valid_p256_public_key(key: Any) -> bool:
    if not isinstance(key, dict):
        return False
    expected = frozenset({"kty", "crv", "x", "y", "kid"})
    if set(key.keys()) != expected:
        return False
    if key.get("kty") != "EC" or key.get("crv") != "P-256":
        return False
    if not isinstance(key.get("kid"), str) or not key["kid"]:
        return False
    for coord in ("x", "y"):
        val = key.get(coord)
        if not isinstance(val, str) or not _B64URL32_RE.fullmatch(val):
            return False
        try:
            raw = _b64url_decode(val)
        except Exception:
            return False
        if len(raw) != 32:
            return False
    try:
        x = int.from_bytes(_b64url_decode(key["x"]), "big")
        y = int.from_bytes(_b64url_decode(key["y"]), "big")
        ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    except Exception:
        return False
    return True


def validate_scalar(type_name: str, value: Any) -> Any:
    if type_name == "swiyu.date@0":
        if not isinstance(value, str) or not _valid_date(value):
            raise ClaimError("invalid date")
        return value
    if type_name == "swiyu.date-yyyymmdd@0":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ClaimError("invalid date-yyyymmdd")
        if value < 19000101 or value > 21991231:
            raise ClaimError("invalid date-yyyymmdd")
        month = (value // 100) % 100
        day = value % 100
        year = value // 10000
        if year < _DATE_MIN_YEAR or year > _DATE_MAX_YEAR or month < 1 or month > 12:
            raise ClaimError("invalid date-yyyymmdd")
        if day < 1 or day > calendar.monthrange(year, month)[1]:
            raise ClaimError("invalid date-yyyymmdd")
        return value
    if type_name == "swiyu.unix-seconds@0":
        if not isinstance(value, str) or not _valid_uint64_string(value):
            raise ClaimError("invalid unix seconds")
        return value
    if type_name == "ascii-code2@1":
        if not _valid_ascii_code2(value):
            raise ClaimError("invalid ascii code2")
        return value
    if type_name == "utf8@1":
        if not _valid_utf8(value):
            raise ClaimError("invalid utf8")
        return value
    raise ClaimError("unknown scalar type")


def validate_given_record(type_name: str, value: Any, *, max_items: int | None = None) -> Any:
    if type_name == "platform.expected-issuer@1":
        return _validate_issuer(value)
    if type_name == "platform.expected-session@1":
        return _validate_session(value)
    if type_name == "platform.expected-status@1":
        return _validate_status(value)
    if type_name == "platform.expected-challenge@1":
        if not isinstance(value, str) or not _HEX64_RE.fullmatch(value):
            raise ClaimError("invalid challenge nonce")
        return value
    base, element, _ = parse_type_name(type_name)
    if base == "set":
        return _validate_set(element, value, max_items=max_items or _SET_MAX_ITEMS)
    return validate_scalar(type_name, value)


def _validate_issuer(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ClaimError("invalid issuer")
    expected = frozenset({"public_key", "issuer_id", "key_id", "allowed_vcts"})
    if set(value.keys()) != expected:
        raise ClaimError("invalid issuer shape")
    if not _valid_p256_public_key(value["public_key"]):
        raise ClaimError("invalid issuer public key")
    if not _valid_utf8(value["issuer_id"]) or not _valid_utf8(value["key_id"]):
        raise ClaimError("invalid issuer identifiers")
    if value["key_id"] != value["public_key"]["kid"]:
        raise ClaimError("issuer key_id mismatch")
    vcts = value["allowed_vcts"]
    if not isinstance(vcts, list) or not vcts or len(vcts) > _ALLOWLIST_MAX_ITEMS:
        raise ClaimError("invalid allowed_vcts")
    seen: set[str] = set()
    for item in vcts:
        if not _valid_utf8(item) or item in seen:
            raise ClaimError("invalid allowed_vcts")
        seen.add(item)
    return copy.deepcopy(value)


def _validate_session(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ClaimError("invalid session")
    expected = frozenset(
        {"nonce", "client_id", "response_uri", "state", "query_id"}
    )
    if set(value.keys()) != expected:
        raise ClaimError("invalid session shape")
    for key in expected:
        if not _valid_utf8(value[key]):
            raise ClaimError("invalid session field")
    return copy.deepcopy(value)


def _validate_status(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ClaimError("invalid status")
    expected = frozenset(
        {
            "id",
            "issuer_id",
            "key_id",
            "subject",
            "commitment",
            "epoch",
            "list_length",
            "valid_before",
        }
    )
    if set(value.keys()) != expected:
        raise ClaimError("invalid status shape")
    for text_key in ("id", "issuer_id", "key_id", "subject"):
        if not _valid_utf8(value[text_key]):
            raise ClaimError("invalid status text field")
    if not isinstance(value["commitment"], str) or not _HEX64_RE.fullmatch(
        value["commitment"]
    ):
        raise ClaimError("invalid status commitment")
    if not _valid_uint64_string(value["epoch"]) or not _valid_uint64_string(
        value["valid_before"]
    ):
        raise ClaimError("invalid status time fields")
    list_length = value["list_length"]
    if not isinstance(list_length, int) or isinstance(list_length, bool):
        raise ClaimError("invalid list_length")
    if list_length < 2 or list_length > 256:
        raise ClaimError("invalid list_length")
    if list_length & (list_length - 1):
        raise ClaimError("invalid list_length")
    return copy.deepcopy(value)


def _validate_set(
    element_type: str, value: Any, *, max_items: int
) -> list[Any]:
    if not isinstance(max_items, int) or isinstance(max_items, bool):
        raise ClaimError("invalid max_items")
    if max_items < 1 or max_items > _SET_MAX_ITEMS:
        raise ClaimError("invalid max_items")
    if element_type not in KNOWN_TYPES:
        raise ClaimError("unknown element type")
    if not isinstance(value, list):
        raise ClaimError("invalid set")
    if not value or len(value) > max_items:
        raise ClaimError("invalid set size")
    seen: set[Any] = set()
    out: list[Any] = []
    for item in value:
        validated = validate_scalar(element_type, item)
        if validated in seen:
            raise ClaimError("duplicate set member")
        seen.add(validated)
        out.append(validated)
    return out


def validate_attribute_path(path: list[Any]) -> None:
    if not isinstance(path, list) or not path or len(path) != 1:
        raise ClaimError("invalid attribute path")
    segment = path[0]
    if not isinstance(segment, str) or not segment:
        raise ClaimError("invalid attribute path")
    if segment in RESERVED_ATTRIBUTE_PATHS:
        raise ClaimError("reserved attribute path")

"""Claim-derived observer transcript differential engine.

Compares full HTTP traces after claim-approved semantic classification.
Not a cryptographic privacy proof and not a sampling-based side-channel study.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
from typing import Any
from urllib.parse import parse_qs, urlsplit, urlunsplit

from semantics.claim_types import validate_given_record
from semantics.claims import ClaimError, evaluate_where, load_claim
from semantics.credentials import CredentialError, authenticate

SCHEMA = "swiyu.transcript-campaign.v1"
MAX_DECODE_BYTES = 8_388_608
MAX_DECODE_DEPTH = 8
MAX_NODES = 4096
MIN_FRESH_LEN = 12
MAX_STATUS_LIST_LENGTH = 65536
HASH_RE = re.compile(r"\A[0-9a-fA-F]{64}\Z")
HEX64_RE = re.compile(r"\A[0-9a-f]{64}\Z")
UINT64_RE = re.compile(r"\A(0|[1-9][0-9]*)\Z")
B64URL_RE = re.compile(r"\A[A-Za-z0-9_-]+\Z")
SUPPORTED_RELEASE_SUFFIXES = ("issuer", "key_id", "credential_type")
STATUS_ENVELOPE_KEYS = frozenset(
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
ORIGIN_KEYS = frozenset({"client_id", "audience", "issuer_id", "host", "origin"})
OPAQUE_FIELD_KEYS = frozenset({"event", "side", "path", "channel"})
PUBLIC_FIELD_KEYS = frozenset({"event", "side", "path", "expected_key"})
FINDING_KINDS = frozenset(
    {
        "secret_disclosure",
        "freshness_binding_mismatch",
        "opaque_length_mismatch",
        "unknown_identifier_differential",
        "unexpected_reject",
        "unexpected_accept",
        "opaque_invalid",
        "content_length_mismatch",
        "transcript_mismatch",
    }
)
EXCEPTION_KINDS = frozenset(
    {
        "truncated_decode",
        "missing_events",
        "malformed_event",
        "invalid_auth",
        "policy_error",
        "invalid_accepted",
        "opaque_invalid",
    }
)

def _oracle_note(verifier_evaluated: list[str]) -> str:
    independent = (
        'Independent checks are exactly those listed in the independent array for this claim. '
    )
    if verifier_evaluated:
        labels = ", ".join(verifier_evaluated)
        return (
            independent
            + f"{labels} are verifier_evaluated (submitted verifier/native adapter). "
            "Compact JWS signatures are an explicit unverified crypto assumption: "
            "header alg and signature length only."
        )
    return (
        independent
        + "Compact JWS signatures are an explicit unverified crypto assumption: "
        "header alg and signature length only."
    )
CRYPTO_ASSUMPTIONS = [
    "compact-jws signatures compared by alg and canonical length only; not verified",
]


class ClassifyError(ValueError):
    """Invalid claim, credential, given, or unsupported release."""


class _Budget:
    def __init__(self) -> None:
        self.bytes = 0
        self.nodes = 0
        self.truncated = False

    def consume(self, n: int) -> bool:
        self.bytes += n
        self.nodes += 1
        if self.bytes > MAX_DECODE_BYTES or self.nodes > MAX_NODES:
            self.truncated = True
            return False
        return True


def _b64url_decode_canonical(data: str) -> bytes | None:
    if not isinstance(data, str) or not data or not B64URL_RE.fullmatch(data):
        return None
    pad = "=" * (-len(data) % 4)
    try:
        raw = base64.urlsafe_b64decode(data + pad)
    except Exception:
        return None
    recoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    if recoded != data:
        return None
    return raw


def _attr_defs(claim) -> dict[str, str]:
    return {
        alias: spec["path"][0]
        for alias, spec in claim.document["attributes"].items()
    }


def _require_given_name(claim, assertion: str, arg: str) -> str:
    for entry in claim.document.get("require", []):
        if entry.get("assert") != assertion:
            continue
        operand = (entry.get("args") or {}).get(arg)
        if isinstance(operand, dict) and "given" in operand:
            return operand["given"]
    raise ClassifyError(f"missing require operand {assertion}.{arg}")


def _optional_given_name(claim, assertion: str, arg: str) -> str | None:
    try:
        return _require_given_name(claim, assertion, arg)
    except ClassifyError:
        return None


def _session_keys(claim) -> list[str]:
    names = []
    for name, spec in claim.document.get("given", {}).items():
        type_name = spec["type"] if isinstance(spec, dict) else spec
        if type_name == "platform.expected-session@1":
            names.append(name)
    return names


def _validate_status_envelope(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value.keys()) != STATUS_ENVELOPE_KEYS:
        raise ClassifyError("invalid status envelope")
    for text_key in ("id", "issuer_id", "key_id", "subject"):
        if not isinstance(value[text_key], str) or not value[text_key]:
            raise ClassifyError("invalid status envelope")
    if not isinstance(value["commitment"], str) or not HEX64_RE.fullmatch(
        value["commitment"]
    ):
        raise ClassifyError("invalid status envelope")
    if not isinstance(value["epoch"], str) or not UINT64_RE.fullmatch(value["epoch"]):
        raise ClassifyError("invalid status envelope")
    if not isinstance(value["valid_before"], str) or not UINT64_RE.fullmatch(
        value["valid_before"]
    ):
        raise ClassifyError("invalid status envelope")
    list_length = value["list_length"]
    if not isinstance(list_length, int) or isinstance(list_length, bool):
        raise ClassifyError("invalid status envelope")
    if (
        list_length < 2
        or list_length > MAX_STATUS_LIST_LENGTH
        or list_length & (list_length - 1)
    ):
        raise ClassifyError("invalid status envelope")
    return copy.deepcopy(value)


def _validate_given_independent(claim, given: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(given, dict):
        raise ClassifyError("invalid given")
    spec = claim.document.get("given", {})
    if set(given.keys()) != set(spec.keys()):
        raise ClassifyError("given keys mismatch")
    out: dict[str, Any] = {}
    for name, type_spec in spec.items():
        type_name = type_spec["type"] if isinstance(type_spec, dict) else type_spec
        max_items = type_spec.get("max_items") if isinstance(type_spec, dict) else None
        value = given[name]
        if type_name == "platform.expected-status@1":
            out[name] = _validate_status_envelope(value)
            continue
        try:
            out[name] = validate_given_record(type_name, value, max_items=max_items)
        except ClaimError as exc:
            raise ClassifyError(str(exc) or "invalid given") from exc
    return out


def _public_context(claim, given: dict[str, Any]) -> dict[str, Any]:
    ctx = copy.deepcopy(given)
    for name, spec in claim.document.get("given", {}).items():
        type_name = spec["type"] if isinstance(spec, dict) else spec
        if type_name == "platform.expected-session@1":
            session = ctx.get(name)
            if isinstance(session, dict):
                session.pop("nonce", None)
                session.pop("state", None)
        elif type_name == "platform.expected-challenge@1":
            ctx.pop(name, None)
    return ctx


def _rename_text(text: str, fresh: dict[str, str]) -> str:
    out = text
    for name, token in sorted(fresh.items(), key=lambda kv: len(kv[1]), reverse=True):
        if token and token in out:
            out = out.replace(token, "{" + name + "}")
    return out


def _rename_url(url: str, fresh: dict[str, str]) -> str:
    parts = urlsplit(url)
    if parts.scheme and parts.netloc:
        return urlunsplit(
            (
                parts.scheme,
                parts.netloc,
                _rename_text(parts.path, fresh),
                _rename_text(parts.query, fresh),
                _rename_text(parts.fragment, fresh),
            )
        )
    return _rename_text(url, fresh)


def _alpha_value(value: Any, fresh: dict[str, str], key: str | None = None) -> Any:
    if key in ORIGIN_KEYS:
        return value
    if isinstance(value, str):
        if "://" in value:
            return _rename_url(value, fresh)
        return _rename_text(value, fresh)
    if isinstance(value, dict):
        return {k: _alpha_value(v, fresh, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_alpha_value(item, fresh) for item in value]
    return value


def _fresh_provenance(
    claim,
    given: dict[str, Any],
    fresh: dict[str, str],
    markers: list[str],
    session_meta: dict[str, str] | None = None,
) -> str | None:
    err = _validate_fresh(fresh, markers)
    if err:
        return err
    sessions = []
    for name in _session_keys(claim):
        rec = given.get(name)
        if isinstance(rec, dict):
            sessions.append(rec)
    if isinstance(session_meta, dict):
        sessions.append(session_meta)
    blob = [
        value
        for rec in sessions
        for value in rec.values()
        if isinstance(value, str)
    ]
    for name, token in fresh.items():
        if name in {"nonce", "state"}:
            if not any(rec.get(name) == token for rec in sessions):
                return "fresh provenance mismatch"
            continue
        if not any(token in item for item in blob):
            return "fresh provenance mismatch"
    return None


def _supported_release_keys(claim) -> set[str]:
    cred = claim.document["credential"]["id"]
    allowed = {"acceptance"} | {f"{cred}.{suffix}" for suffix in SUPPORTED_RELEASE_SUFFIXES}
    return allowed


def _release_map(claim, auth, acceptance: bool) -> dict[str, Any]:
    requested = list(claim.document["release"]["semantic_values"])
    allowed = _supported_release_keys(claim)
    if set(requested) - allowed:
        raise ClassifyError("unsupported release semantic_values")
    cred = claim.document["credential"]["id"]
    release = {"acceptance": acceptance}
    for suffix in SUPPORTED_RELEASE_SUFFIXES:
        key = f"{cred}.{suffix}"
        if key in requested:
            if suffix == "issuer":
                release[key] = auth.issuer_id
            elif suffix == "key_id":
                release[key] = auth.key_id
            elif suffix == "credential_type":
                release[key] = auth.credential_type
    return release


def _public_strings(value: Any, out: set[str]) -> None:
    if isinstance(value, str) and value:
        out.add(value)
    elif isinstance(value, dict):
        for item in value.values():
            _public_strings(item, out)
    elif isinstance(value, list):
        for item in value:
            _public_strings(item, out)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        out.add(str(value))


def _hidden_values(claim, auth, given: dict[str, Any], release: dict[str, Any]) -> list[dict[str, str]]:
    public: set[str] = set()
    _public_strings(_public_context(claim, given), public)
    _public_strings(release, public)
    markers: list[dict[str, str]] = []

    def add(kind: str, ident: str, raw: Any) -> None:
        if raw is None:
            return
        text = raw if isinstance(raw, str) else json.dumps(raw, separators=(",", ":"), sort_keys=True)
        if not text or text in public:
            return
        if len(text) < 4:
            return
        markers.append({"kind": kind, "id": ident, "value": text})

    for alias, value in auth.attributes.items():
        add("signed_attribute", f"attribute.{alias}", value)
    add("holder_key", "holder.jwk", auth.holder_key)
    for coord in ("x", "y", "kid"):
        if coord in auth.holder_key:
            add("holder_key", f"holder.jwk.{coord}", auth.holder_key[coord])
    add("status", "status.uri", auth.status_uri)
    add("status", "status.index", str(auth.status_index))
    return markers


def _oracle_scope(claim) -> dict[str, Any]:
    independent = ["credential.authentic@1"]
    if _optional_given_name(claim, "credential.expected-metadata@1", "issuer"):
        independent.append("credential.expected-metadata@1")
    if _optional_given_name(claim, "credential.valid-at@1", "time"):
        independent.append("credential.valid-at@1")
    if claim.document.get("where"):
        independent.append("where")
    verifier = []
    for entry in claim.document.get("require", []):
        name = entry.get("assert")
        if name in {
            "holder.signature-valid@1",
            "status.zero-at-reference@1",
            "presentation.challenge-bound@1",
        }:
            verifier.append(name)
    return {
        "independent": independent,
        "verifier_evaluated": verifier,
        "note": _oracle_note(verifier),
        "crypto_assumptions": list(CRYPTO_ASSUMPTIONS),
    }


def _classify(claim_path: str | Any, credential: str, given: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    try:
        claim = load_claim(claim_path)
        typed_given = _validate_given_independent(claim, given)
        issuer_name = _require_given_name(claim, "credential.authentic@1", "issuer")
        time_name = _optional_given_name(claim, "credential.valid-at@1", "time")
        issuer = typed_given[issuer_name]
        auth = authenticate(credential, issuer, _attr_defs(claim))
        metadata_ok = (
            auth.issuer_id == issuer["issuer_id"]
            and auth.key_id == issuer["key_id"]
            and auth.credential_type in issuer["allowed_vcts"]
        )
        if time_name:
            now = int(typed_given[time_name])
            valid = auth.nbf <= now < auth.exp
        else:
            valid = True
        where_ok = evaluate_where(claim, auth.attributes, typed_given)
        acceptance = bool(metadata_ok and valid and where_ok)
        release = _release_map(claim, auth, acceptance)
        markers = _hidden_values(claim, auth, typed_given, release)
    except (ClaimError, CredentialError, ClassifyError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, ClassifyError):
            raise
        raise ClassifyError(str(exc) or "classification failed") from exc
    public = {
        "statement_digest": claim.statement_digest,
        "acceptance": acceptance,
        "release": release,
        "public_context": _public_context(claim, typed_given),
        "hidden_markers": [{"id": m["id"], "kind": m["kind"]} for m in markers],
        "oracle_scope": _oracle_scope(claim),
    }
    return public, [m["value"] for m in markers]


def classify_fixture(claim_path: str | Any, credential: str, given: dict[str, Any]) -> dict[str, Any]:
    public, _markers = _classify(claim_path, credential, given)
    return public


def decode_body(body: str, *, budget: _Budget | None = None) -> dict[str, Any]:
    budget = budget or _Budget()
    value = _decode_any(body, budget, 0)
    return {"value": value, "truncated": budget.truncated}


def _decode_any(raw: Any, budget: _Budget, depth: int) -> Any:
    if depth > MAX_DECODE_DEPTH or budget.truncated:
        budget.truncated = True
        return {"truncated": True}
    if isinstance(raw, dict):
        if not budget.consume(1):
            return {"truncated": True}
        return {str(k): _decode_any(v, budget, depth + 1) for k, v in raw.items()}
    if isinstance(raw, list):
        if not budget.consume(1):
            return {"truncated": True}
        return [_decode_any(v, budget, depth + 1) for v in raw]
    if not isinstance(raw, str):
        if not budget.consume(1):
            return {"truncated": True}
        return raw
    if not budget.consume(max(1, len(raw))):
        return {"truncated": True}
    text = raw
    if not text:
        return ""
    if text[:1] in "{[":
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, (dict, list)):
            return _decode_any(parsed, budget, depth + 1)
    if "=" in text and "&" in text and " " not in text.split("=", 1)[0]:
        form = parse_qs(text, keep_blank_values=True, strict_parsing=False)
        if form:
            out: dict[str, Any] = {}
            for key, values in form.items():
                decoded_vals = [_decode_any(v, budget, depth + 1) for v in values]
                out[key] = decoded_vals if len(decoded_vals) != 1 else decoded_vals[0]
            return out
    jwt_text = text
    disclosure_parts = None
    if "~" in text:
        jwt_part, *disclosure_parts = text.split("~")
        jwt_text = jwt_part
    if jwt_text.count(".") == 2:
        parts = jwt_text.split(".")
        if all(p and B64URL_RE.fullmatch(p) for p in parts):
            header = _try_json_b64(parts[0])
            payload = _try_json_b64(parts[1])
            if isinstance(header, dict) and isinstance(payload, dict):
                token = {
                    "header": _decode_any(header, budget, depth + 1),
                    "payload": _decode_any(payload, budget, depth + 1),
                    "signature": {
                        "encoding": "compact-jws",
                        "length": len(parts[2]),
                        "alg": header.get("alg"),
                        "assumption": "unverified-compact-jws",
                    },
                }
                if disclosure_parts is not None:
                    decoded_disclosures = []
                    for item in disclosure_parts:
                        raw = _b64url_decode_canonical(item) if item else None
                        if raw is None:
                            decoded_disclosures.append(item)
                            continue
                        try:
                            inner = raw.decode("utf-8")
                        except UnicodeDecodeError:
                            decoded_disclosures.append({"encoding": "sd-jwt-disclosure", "length": len(raw)})
                            continue
                        decoded_disclosures.append(_decode_any(inner, budget, depth + 1))
                    token["disclosures"] = decoded_disclosures
                return token
    blob = _b64url_decode_canonical(text)
    if blob is not None and 1 < len(blob) <= MAX_DECODE_BYTES:
        if not budget.consume(len(blob)):
            return {"truncated": True}
        try:
            inner = blob.decode("utf-8")
        except UnicodeDecodeError:
            inner = None
        if inner and inner[:1] in "{[":
            try:
                parsed = json.loads(inner)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, (dict, list)):
                return _decode_any(parsed, budget, depth + 1)
    return text


def _try_json_b64(segment: str) -> Any:
    raw = _b64url_decode_canonical(segment)
    if raw is None:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


def _pointer_get(doc: Any, pointer: str) -> tuple[bool, Any]:
    if pointer == "" or pointer == "/":
        return True, doc
    if not pointer.startswith("/"):
        return False, None
    cur = doc
    for token in pointer[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, dict) and token in cur:
            cur = cur[token]
        elif isinstance(cur, list) and token.isdigit() and int(token) < len(cur):
            cur = cur[int(token)]
        else:
            return False, None
    return True, cur


def _pointer_set(doc: Any, pointer: str, value: Any) -> bool:
    if not pointer.startswith("/") or pointer == "/":
        return False
    tokens = [t.replace("~1", "/").replace("~0", "~") for t in pointer[1:].split("/")]
    cur = doc
    for token in tokens[:-1]:
        if isinstance(cur, dict) and token in cur:
            cur = cur[token]
        elif isinstance(cur, list) and token.isdigit() and int(token) < len(cur):
            cur = cur[int(token)]
        else:
            return False
    last = tokens[-1]
    if isinstance(cur, dict) and last in cur:
        cur[last] = value
        return True
    if isinstance(cur, list) and last.isdigit() and int(last) < len(cur):
        cur[int(last)] = value
        return True
    return False


def _walk_strings(value: Any, pointer: str, acc: list[tuple[str, str]]) -> None:
    if isinstance(value, str):
        acc.append((pointer, value))
    elif isinstance(value, dict):
        for key, item in value.items():
            _walk_strings(item, f"{pointer}/{_escape(key)}", acc)
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            _walk_strings(item, f"{pointer}/{idx}", acc)


def _escape(key: str) -> str:
    return key.replace("~", "~0").replace("/", "~1")


def _contains_marker(haystack: str, markers: list[str]) -> bool:
    return any(m and m in haystack for m in markers)


def _scan_event(event: dict[str, Any], markers: list[str]) -> list[dict[str, Any]]:
    findings = []
    for side in ("request", "response"):
        msg = event.get(side) or {}
        url = str(msg.get("url") or "")
        if _contains_marker(url, markers):
            findings.append(_secret_finding(event.get("boundary"), side, "url"))
        headers = msg.get("headers") or []
        if isinstance(headers, list):
            for pair in headers:
                if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                    continue
                key, val = pair
                if _contains_marker(str(key), markers) or _contains_marker(
                    str(val), markers
                ):
                    findings.append(_secret_finding(event.get("boundary"), side, "header"))
        body = msg.get("body")
        if isinstance(body, str):
            if _contains_marker(body, markers):
                findings.append(_secret_finding(event.get("boundary"), side, "body"))
            decoded = decode_body(body)
            blob = json.dumps(decoded["value"])
            if _contains_marker(blob, markers):
                findings.append(_secret_finding(event.get("boundary"), side, "decoded-body"))
    return findings


def _secret_finding(boundary: Any, side: str, loc: str) -> dict[str, Any]:
    return {
        "kind": "secret_disclosure",
        "boundary": boundary,
        "side": side,
        "location": loc,
        "explanation": "hidden marker observed on the wire before opaque masking",
    }


def _validate_policy(policy: dict[str, Any], claim) -> str | None:
    if not isinstance(policy, dict):
        return "invalid policy"
    if not policy.get("id") or not policy.get("observer"):
        return "invalid policy"
    if not isinstance(policy.get("opaque_fields"), list) or not isinstance(
        policy.get("public_fields"), list
    ):
        return "invalid policy"
    if policy.get("ignored_headers") != []:
        return "ignored_headers not allowed"
    if policy.get("response_clock_headers", []) not in ([], ["date"]):
        return "unsupported clock header exemption"
    if not isinstance(policy.get("rename_session_tokens", False), bool):
        return "invalid session normalization policy"
    boundaries = policy.get("expected_boundaries")
    if boundaries is not None and (not isinstance(boundaries, list) or not boundaries or any(not isinstance(x, str) for x in boundaries)):
        return "invalid expected boundaries"
    opaque_ok = set(claim.document.get("release", {}).get("opaque_channels") or [])
    for item in policy["opaque_fields"]:
        if not isinstance(item, dict) or set(item.keys()) - OPAQUE_FIELD_KEYS:
            return "invalid opaque field"
        if item.get("channel") != "proof" or "proof" not in opaque_ok:
            return "opaque channel not declared"
        if item.get("side") not in {"request", "response"}:
            return "invalid opaque field"
        if not isinstance(item.get("event"), (int, str)) or isinstance(item.get("event"), bool):
            return "invalid opaque field"
        if not isinstance(item.get("path"), str) or not item["path"].startswith("/"):
            return "invalid opaque field"
    for item in policy["public_fields"]:
        if not isinstance(item, dict) or set(item.keys()) - PUBLIC_FIELD_KEYS:
            return "invalid public field"
        if item.get("side") not in {"request", "response"}:
            return "invalid public field"
        if not isinstance(item.get("event"), (int, str)) or isinstance(item.get("event"), bool):
            return "invalid public field"
        if not isinstance(item.get("path"), str):
            return "invalid public field"
        if not isinstance(item.get("expected_key"), str):
            return "invalid public field"
    return None


def _validate_fresh(fresh: dict[str, Any], markers: list[str]) -> str | None:
    if not isinstance(fresh, dict):
        return "invalid fresh mapping"
    values = list(fresh.values())
    if any(not isinstance(v, str) for v in values):
        return "invalid fresh mapping"
    if any(len(v) < MIN_FRESH_LEN for v in values):
        return "fresh value too short"
    if len(values) != len(set(values)):
        return "colliding fresh values"
    for i, left in enumerate(values):
        for j, right in enumerate(values):
            if i != j and left in right:
                return "overlapping fresh values"
    for val in values:
        if val in markers:
            return "fresh value equals hidden marker"
    return None


def _field_applies(
    field: dict[str, Any], event_index: int, boundary: Any, side: str
) -> bool:
    if field.get("side") != side:
        return False
    event = field.get("event")
    if event == event_index:
        return True
    return isinstance(event, str) and event == boundary


def _normalize_headers(
    headers: list,
    *,
    raw_body: str,
) -> tuple[list[list[str]], list[dict[str, Any]], bool]:
    findings: list[dict[str, Any]] = []
    expected_len = str(len(raw_body.encode("utf-8")))
    out: list[list[str]] = []
    well_formed = True
    if not isinstance(headers, list):
        findings.append(
            {
                "kind": "malformed_event",
                "explanation": "headers must be a list of pairs",
            }
        )
        return [], findings, False
    for pair in headers:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            findings.append(
                {
                    "kind": "malformed_event",
                    "explanation": "malformed header pair",
                }
            )
            well_formed = False
            continue
        key, val = str(pair[0]), str(pair[1])
        if key.lower() == "content-length":
            if val != expected_len:
                findings.append(
                    {
                        "kind": "content_length_mismatch",
                        "explanation": "Content-Length did not match raw body UTF-8 byte size",
                    }
                )
            out.append([key.lower(), expected_len])
        else:
            out.append([key.lower(), val])
    out.sort(key=lambda kv: (kv[0], kv[1]))
    return out, findings, well_formed


def _mask_public(
    decoded: Any,
    fields: list[dict[str, Any]],
    event_index: int,
    boundary: Any,
    side: str,
    fresh: dict[str, str],
) -> list[dict[str, Any]]:
    findings = []
    for field in fields:
        if not _field_applies(field, event_index, boundary, side):
            continue
        expected_key = field["expected_key"]
        expected = fresh.get(expected_key)
        ok, actual = _pointer_get(decoded, field["path"])
        if not ok or not isinstance(actual, str) or actual != expected:
            findings.append(
                {
                    "kind": "freshness_binding_mismatch",
                    "pointer": field["path"],
                    "explanation": "public session field did not match harness fresh value",
                }
            )
            continue
        _pointer_set(decoded, field["path"], {"fresh": expected_key})
    return findings


def _mask_opaque(
    decoded: Any,
    fields: list[dict[str, Any]],
    event_index: int,
    boundary: Any,
    side: str,
    *,
    missing_ok: bool = False,
) -> list[dict[str, Any]]:
    findings = []
    for field in fields:
        if not _field_applies(field, event_index, boundary, side):
            continue
        ok, actual = _pointer_get(decoded, field["path"])
        if not ok:
            if missing_ok:
                continue
            findings.append(
                {
                    "kind": "opaque_invalid",
                    "pointer": field["path"],
                    "explanation": "opaque path missing or unknown key",
                }
            )
            continue
        if isinstance(actual, (dict, list)) or not isinstance(actual, str):
            findings.append(
                {
                    "kind": "opaque_invalid",
                    "pointer": field["path"],
                    "explanation": "opaque proof must be a nonempty scalar, not an object",
                }
            )
            continue
        raw = _b64url_decode_canonical(actual)
        if raw is None or not raw:
            findings.append(
                {
                    "kind": "opaque_invalid",
                    "pointer": field["path"],
                    "explanation": "opaque proof is not nonempty canonical base64url",
                }
            )
            continue
        _pointer_set(
            decoded,
            field["path"],
            {"channel": "proof", "length": len(raw)},
        )
    return findings


def _looks_identifier(value: Any) -> bool:
    if not isinstance(value, str) or len(value) < 32:
        return False
    return bool(HASH_RE.fullmatch(value)) or (
        B64URL_RE.fullmatch(value) is not None and len(value) >= 32
    )


def _normalize_session(
    session: dict[str, Any],
    policy: dict[str, Any],
    markers: list[str],
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    truncated = False
    events = session.get("events") or []
    if not events:
        return {
            "ok": False,
            "status": "inconclusive",
            "findings": [
                {
                    "kind": "missing_events",
                    "explanation": "empty trace",
                    "session": session.get("id"),
                }
            ],
            "views": [],
        }
    fresh_err = _validate_fresh(session.get("fresh") or {}, markers)
    if fresh_err:
        return {
            "ok": False,
            "status": "error",
            "findings": [{"kind": "policy_error", "explanation": fresh_err}],
            "views": [],
        }
    expected_boundaries = policy.get("expected_boundaries")
    if expected_boundaries is not None and [e.get("boundary") if isinstance(e, dict) else None for e in events] != expected_boundaries:
        return {"ok": False, "status": "inconclusive", "findings": [{"kind": "missing_events", "session": session.get("id"), "explanation": "observed sequence does not match selected flow"}], "views": []}
    views = []
    malformed = False
    for idx, event in enumerate(events):
        if not isinstance(event, dict):
            findings.append(
                {
                    "kind": "malformed_event",
                    "explanation": "event is not an object",
                    "session": session.get("id"),
                }
            )
            malformed = True
            continue
        findings.extend(_scan_event(event, markers))
        view = {"boundary": event.get("boundary"), "index": idx}
        for side in ("request", "response"):
            msg = event.get(side) or {}
            if not isinstance(msg, dict):
                findings.append(
                    {
                        "kind": "malformed_event",
                        "explanation": f"{side} is not an object",
                        "session": session.get("id"),
                    }
                )
                malformed = True
                continue
            required_types = {"body": str, "headers": list}
            required_types.update({"method": str, "url": str} if side == "request" else {"status": int})
            if any(not isinstance(msg.get(k), kind) or (kind is int and isinstance(msg.get(k), bool)) for k, kind in required_types.items()):
                malformed = True
                findings.append({"kind": "malformed_event", "explanation": "HTTP observation is missing a required field", "session": session.get("id")})
                continue
            raw_body = msg["body"]
            headers, header_findings, headers_ok = _normalize_headers(
                msg.get("headers") or [],
                raw_body=raw_body,
            )
            findings.extend(header_findings)
            if not headers_ok:
                malformed = True
            budget = _Budget()
            decoded_wrap = decode_body(raw_body, budget=budget)
            if decoded_wrap["truncated"]:
                truncated = True
            decoded = copy.deepcopy(decoded_wrap["value"])
            findings.extend(
                _mask_public(
                    decoded,
                    policy["public_fields"],
                    idx,
                    event.get("boundary"),
                    side,
                    session.get("fresh") or {},
                )
            )
            findings.extend(
                _mask_opaque(
                    decoded,
                    policy["opaque_fields"],
                    idx,
                    event.get("boundary"),
                    side,
                    missing_ok=bool(policy.get("opaque_missing_ok")),
                )
            )
            if policy.get("rename_session_tokens"):
                decoded = _alpha_value(decoded, session.get("fresh") or {})
                headers = [[k, _alpha_value(v, session.get("fresh") or {}, k)] for k, v in headers]
            if side == "response" and policy.get("response_clock_headers") == ["date"]:
                from email.utils import parsedate_to_datetime
                date_count = sum(1 for key, _value in headers if key == "date")
                normalized_headers = []
                for key, value in headers:
                    if key == "date":
                        try:
                            instant = parsedate_to_datetime(value)
                            if instant.tzinfo is None or instant.strftime("%a, %d %b %Y %H:%M:%S GMT") != value:
                                raise ValueError("noncanonical HTTP date")
                            if date_count == 1:
                                value = "{server-clock:date}"
                        except (TypeError, ValueError, OverflowError):
                            malformed = True
                            findings.append({"kind": "malformed_event", "explanation": "response Date is not a valid HTTP clock value"})
                    normalized_headers.append([key, value])
                headers = normalized_headers
            if policy.get("request_object_clock") and side == "response" and event.get("boundary") == "verifier:request_object":
                payload = decoded.get("payload", {}) if isinstance(decoded, dict) else {}
                if isinstance(payload, dict) and ("iat" in payload or "exp" in payload):
                    issued, expires = payload.get("iat"), payload.get("exp")
                    signature = decoded.get("signature", {})
                    if type(issued) is not int or type(expires) is not int or issued < 0 or expires < issued or signature.get("encoding") != "compact-jws":
                        malformed = True
                        findings.append({"kind": "malformed_event", "explanation": "invalid request-object issuance or expiration clock"})
                    else:
                        payload["iat"] = {"public_session_clock": "issuance"}
                        payload["exp"] = {"seconds_after_issuance": expires - issued}
            url = str(msg.get("url") or "")
            if side == "request":
                view["method"] = msg.get("method")
                view["url"] = _rename_url(url, session.get("fresh") or {})
            else:
                view["status"] = msg.get("status")
            view[side] = {
                "headers": headers,
                "body": decoded,
                "body_size": len(raw_body.encode("utf-8")),
            }
        views.append(view)
    if malformed:
        findings.append(
            {
                "kind": "malformed_event",
                "explanation": "malformed HTTP event shape",
                "session": session.get("id"),
            }
        )
        return {"ok": False, "status": "inconclusive", "findings": findings, "views": views}
    if truncated:
        findings.append(
            {
                "kind": "truncated_decode",
                "explanation": "decode budget exhausted",
                "session": session.get("id"),
            }
        )
        return {"ok": False, "status": "inconclusive", "findings": findings, "views": views}
    return {"ok": True, "status": "ok", "findings": findings, "views": views}


def _class_key(row: dict[str, Any]) -> str:
    payload = {
        "acceptance": row["classification"]["acceptance"],
        "release": row["classification"]["release"],
        "public_context": row["classification"]["public_context"],
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _diff_views(left: list[dict[str, Any]], right: list[dict[str, Any]]) -> list[dict[str, Any]]:
    diffs: list[dict[str, Any]] = []
    if len(left) != len(right):
        diffs.append(
            {
                "pointer": "/events",
                "left_boundary": left[0]["boundary"] if left else None,
                "right_boundary": right[0]["boundary"] if right else None,
                "explanation": "event count differed",
            }
        )
        return diffs
    for l_ev, r_ev in zip(left, right):
        _diff_value(
            l_ev,
            r_ev,
            "",
            diffs,
            l_ev.get("boundary"),
            r_ev.get("boundary"),
        )
    return diffs


def _diff_value(
    left: Any,
    right: Any,
    pointer: str,
    diffs: list[dict[str, Any]],
    left_b: Any,
    right_b: Any,
) -> None:
    if type(left) is not type(right) and not (
        isinstance(left, (int, float)) and isinstance(right, (int, float))
    ):
        diffs.append(
            {
                "pointer": pointer or "/",
                "left_boundary": left_b,
                "right_boundary": right_b,
                "explanation": "value shape differed",
            }
        )
        return
    if isinstance(left, dict) and isinstance(right, dict):
        if (
            left.get("channel") == "proof"
            and right.get("channel") == "proof"
            and "length" in left
            and "length" in right
        ):
            if left["length"] != right["length"]:
                diffs.append(
                    {
                        "pointer": pointer or "/",
                        "left_boundary": left_b,
                        "right_boundary": right_b,
                        "explanation": "opaque proof decoded length differed",
                        "kind": "opaque_length_mismatch",
                    }
                )
            return
        keys = set(left) | set(right)
        for key in sorted(keys):
            child = f"{pointer}/{_escape(str(key))}"
            if key not in left or key not in right:
                diffs.append(
                    {
                        "pointer": child,
                        "left_boundary": left_b,
                        "right_boundary": right_b,
                        "explanation": "field presence differed",
                    }
                )
                continue
            _diff_value(left[key], right[key], child, diffs, left_b, right_b)
        return
    if isinstance(left, list) and isinstance(right, list):
        if len(left) != len(right):
            diffs.append(
                {
                    "pointer": pointer or "/",
                    "left_boundary": left_b,
                    "right_boundary": right_b,
                    "explanation": "array length differed",
                }
            )
            return
        for idx, (a, b) in enumerate(zip(left, right)):
            _diff_value(a, b, f"{pointer}/{idx}", diffs, left_b, right_b)
        return
    if left != right:
        kind = "structure_mismatch"
        if _looks_identifier(left) and _looks_identifier(right):
            kind = "unknown_identifier_differential"
        diffs.append(
            {
                "pointer": pointer or "/",
                "left_boundary": left_b,
                "right_boundary": right_b,
                "explanation": (
                    "unknown hash-like identifier differed"
                    if kind == "unknown_identifier_differential"
                    else "scalar leaf differed"
                ),
                "kind": kind,
            }
        )


def _scrub(report: dict[str, Any], secrets: list[str]) -> dict[str, Any]:
    blob = json.dumps(report)
    for marker in sorted({s for s in secrets if s}, key=len, reverse=True):
        if marker in blob:
            blob = blob.replace(marker, "<redacted>")
    return json.loads(blob)


def analyze_transcripts(
    claim_path: str | Any,
    sessions: list[dict[str, Any]],
    policy: dict[str, Any],
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    try:
        claim = load_claim(claim_path)
    except (ClaimError, OSError) as exc:
        return {
            "schema": SCHEMA,
            "status": "error",
            "findings": [{"kind": "policy_error", "explanation": str(exc)}],
            "pairs": [],
            "coverage": {"sessions": 0},
            "oracle_scope": {
                "note": _oracle_note([]),
                "crypto_assumptions": list(CRYPTO_ASSUMPTIONS),
            },
            "method": _method(),
            "exceptions": ["policy_error"],
        }
    policy_err = _validate_policy(policy, claim)
    if policy_err:
        return {
            "schema": SCHEMA,
            "status": "error",
            "findings": [{"kind": "policy_error", "explanation": policy_err}],
            "pairs": [],
            "coverage": {"sessions": 0},
            "oracle_scope": _oracle_scope(claim),
            "method": _method(),
            "exceptions": ["policy_error"],
        }

    rows = []
    all_markers: list[str] = []
    fresh_secrets: list[str] = []
    statuses = []
    for session in sessions:
        try:
            classification, markers = _classify(
                claim_path, session["credential"], session["given"]
            )
        except ClassifyError:
            findings.append(
                {
                    "kind": "invalid_auth",
                    "session": session.get("id"),
                    "explanation": "credential or given could not be classified",
                }
            )
            statuses.append("error")
            continue
        all_markers.extend(markers)
        fresh = session.get("fresh") or {}
        if isinstance(fresh, dict):
            fresh_secrets.extend(v for v in fresh.values() if isinstance(v, str))
        prov = _fresh_provenance(
            claim,
            session.get("given") or {},
            fresh if isinstance(fresh, dict) else {},
            markers,
            session.get("session_meta") if isinstance(session.get("session_meta"), dict) else None,
        )
        if prov:
            findings.append({"kind": "policy_error", "session": session.get("id"), "explanation": prov})
            statuses.append("error")
            findings.extend(_normalize_session(session, policy, markers)["findings"])
            continue
        classification = dict(classification)
        classification["public_context"] = _alpha_value(
            classification["public_context"], fresh if isinstance(fresh, dict) else {}
        )
        normalized = _normalize_session(session, policy, markers)
        findings.extend(normalized["findings"])
        accepted = session.get("accepted")
        if not isinstance(accepted, bool):
            findings.append(
                {
                    "kind": "invalid_accepted",
                    "session": session.get("id"),
                    "explanation": "accepted must be a JSON boolean",
                }
            )
            statuses.append("error")
            continue
        if accepted != classification["acceptance"]:
            findings.append(
                {
                    "kind": "unexpected_reject"
                    if classification["acceptance"] and not accepted
                    else "unexpected_accept",
                    "session": session.get("id"),
                    "explanation": "session accepted flag disagreed with claim classification",
                }
            )
            statuses.append("findings")
            continue
        if not normalized["ok"]:
            statuses.append(normalized["status"])
            continue
        rows.append(
            {
                "id": session.get("id"),
                "variant": session.get("variant"),
                "classification": classification,
                "views": normalized["views"],
            }
        )
        statuses.append("ok")

    pairs = []
    for i, left in enumerate(rows):
        for right in rows[i + 1 :]:
            same = _class_key(left) == _class_key(right)
            if not same:
                pairs.append(
                    {
                        "left": left["id"],
                        "right": right["id"],
                        "eligibility": "input_non_equivalent",
                        "status": "not_compared",
                        "diffs": [],
                    }
                )
                continue
            diffs = _diff_views(left["views"], right["views"])
            if any(d.get("kind") == "opaque_length_mismatch" for d in diffs):
                findings.append(
                    {
                        "kind": "opaque_length_mismatch",
                        "left": left["id"],
                        "right": right["id"],
                        "explanation": "opaque proof decoded length differed",
                    }
                )
            if any(d.get("kind") == "unknown_identifier_differential" for d in diffs):
                findings.append(
                    {
                        "kind": "unknown_identifier_differential",
                        "left": left["id"],
                        "right": right["id"],
                        "explanation": "unknown hash-like identifier differed across equivalent sessions",
                    }
                )
            pair_status = "equivalent" if not diffs else "mismatch"
            if diffs:
                statuses.append("findings")
                findings.append(
                    {
                        "kind": "transcript_mismatch",
                        "left": left["id"],
                        "right": right["id"],
                        "explanation": "normalized observer transcripts differed",
                        "pointers": [d["pointer"] for d in diffs],
                    }
                )
            pairs.append(
                {
                    "left": left["id"],
                    "right": right["id"],
                    "eligibility": "compared",
                    "status": pair_status,
                    "diffs": [
                        {
                            "pointer": d["pointer"],
                            "left_boundary": d.get("left_boundary"),
                            "right_boundary": d.get("right_boundary"),
                            "explanation": d["explanation"],
                        }
                        for d in diffs
                    ],
                }
            )

    findings = _dedupe(findings)
    status = _overall(statuses, findings, pairs)
    report = {
        "schema": SCHEMA,
        "status": status,
        "policy": copy.deepcopy(policy),
        "unassessed_channels": ["timing distributions"] + (["response Date values"] if policy.get("response_clock_headers") else []) + (["request-object absolute issuance time"] if policy.get("request_object_clock") else []),
        "oracle_scope": _oracle_scope(claim),
        "classifications": [
            {
                "session": row["id"],
                "statement_digest": row["classification"]["statement_digest"],
                "acceptance": row["classification"]["acceptance"],
                "release": row["classification"]["release"],
                "public_context": row["classification"]["public_context"],
                "hidden_markers": row["classification"]["hidden_markers"],
            }
            for row in rows
        ],
        "pairs": pairs,
        "findings": findings,
        "coverage": {
            "sessions": len(sessions),
            "classified": len(rows),
            "compared_pairs": sum(1 for p in pairs if p["eligibility"] == "compared"),
        },
        "exceptions": sorted({f["kind"] for f in findings if f.get("kind") in EXCEPTION_KINDS}),
        "method": _method(),
    }
    return _scrub(report, all_markers + fresh_secrets)


def _overall(
    statuses: list[str],
    findings: list[dict[str, Any]],
    pairs: list,
) -> str:
    kinds = {f.get("kind") for f in findings}
    if "secret_disclosure" in kinds:
        return "findings"
    if kinds & {"truncated_decode", "malformed_event", "missing_events"}:
        return "inconclusive"
    if kinds & FINDING_KINDS:
        return "findings"
    if any(p.get("status") == "mismatch" for p in pairs):
        return "findings"
    if any(s == "error" for s in statuses) and not any(s == "ok" for s in statuses):
        return "error"
    if any(s == "inconclusive" for s in statuses):
        return "inconclusive"
    compared = [p for p in pairs if p.get("eligibility") == "compared"]
    if not compared:
        return "inconclusive"
    if any(s == "error" for s in statuses):
        return "error"
    return "clean"


def _dedupe(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique = []
    seen = set()
    for item in findings:
        key = json.dumps(item, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def _method() -> str:
    return (
        "Claim classification (authentic SD-JWT, metadata, validity, where, "
        "and exact public status envelope fields) then observer HTTP structural "
        "equality after named public fresh alpha-rename and declared proof-length "
        "opacity. Secret markers are scanned on raw and decoded bodies before "
        "masking. Compact JWS signatures are unverified (alg+length). "
        "Two-to-four samples do not establish timing or size side channels."
    )

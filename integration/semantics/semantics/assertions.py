"""Claim assertion evaluation and transcript derivation."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature

from semantics.canonical import canonical_json_bytes
from semantics.claims import Claim, ClaimError, evaluate_where, validate_claim, validate_given
from semantics.credentials import CredentialError, authenticate, _b64url_decode

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_B64URL_SIG = re.compile(r"^[A-Za-z0-9_-]{86}$")
AUTH_OPERATION = "credential.authentic@1"
STATUS_OPERATION = "status.zero-at-reference@1"
CONTEXT_OPERATION = "presentation.context-bound@1"
CHALLENGE_BOUND_OPERATION = "presentation.challenge-bound@1"


def _ok(value: bool) -> dict[str, Any]:
    return {"value": bool(value), "status": "ok"}


def _not_run() -> dict[str, Any]:
    return {"value": False, "status": "not_run"}


def _invalid_input() -> dict[str, Any]:
    return {"status": "invalid_input"}


def _as_claim(claim: Any) -> Claim:
    if isinstance(claim, Claim):
        checked = validate_claim(claim.document)
        if checked.statement_digest != claim.statement_digest or checked.dependencies != claim.dependencies:
            raise ClaimError("claim identity mismatch")
        return checked
    if isinstance(claim, dict):
        return validate_claim(claim)
    raise ClaimError("invalid claim")


def expected_transcript(claim: Any, given: dict[str, Any]) -> bytes:
    """Return 32-byte claim.context@1 digest bytes."""
    validated = _as_claim(claim)
    payload = {
        "statement_digest": validated.statement_digest,
        "given": given,
    }
    body = canonical_json_bytes(payload)
    prefix = b"swiyu-claim-v1\0" + len(body).to_bytes(4, "big")
    return hashlib.sha256(prefix + body).digest()


def _resolve_operand(
    spec: dict[str, Any],
    *,
    claim: Claim,
    fixture: dict[str, Any],
    given: dict[str, Any],
    authenticated: Any | None,
    assertion_outputs: dict[str, dict[str, Any]],
) -> Any:
    if "credential" in spec:
        credential_id = spec["credential"]
        if credential_id != claim.document["credential"]["id"]:
            raise ValueError("unknown credential")
        return fixture.get("credential")
    if "given" in spec:
        key = spec["given"]
        if key not in given:
            raise ValueError("missing given input")
        return given[key]
    if "assertion" in spec:
        assertion_id = spec["assertion"]
        output = spec.get("output")
        if assertion_id in assertion_outputs and output in assertion_outputs[assertion_id]:
            return assertion_outputs[assertion_id][output]
        if output == "expected_transcript":
            return expected_transcript(claim, given)
        raise ValueError("unresolved assertion output")
    if "attribute" in spec:
        alias = spec["attribute"]
        if authenticated is None:
            raise ValueError("missing authenticated credential")
        return authenticated.attributes[alias]
    if "const" in spec:
        return spec["const"]
    raise ValueError("unknown operand")


def _leaf_hash(index: int, bit: int) -> bytes:
    return hashlib.sha256(b"\x00" + index.to_bytes(4, "big") + bytes([bit])).digest()


def _parent_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _status_depth(list_length: int) -> int:
    depth = 0
    n = list_length
    while n > 1:
        n //= 2
        depth += 1
    return depth


def _verify_status_path(
    *,
    index: int,
    bit: int,
    siblings: list[str],
    root_hex: str,
    list_length: int,
) -> bool:
    if bit != 0:
        return False
    if len(siblings) != _status_depth(list_length):
        return False
    current = _leaf_hash(index, bit)
    pos = index
    for sibling_hex in siblings:
        if not isinstance(sibling_hex, str) or not _HEX64.fullmatch(sibling_hex):
            return False
        sibling = bytes.fromhex(sibling_hex)
        if pos % 2 == 0:
            current = _parent_hash(current, sibling)
        else:
            current = _parent_hash(sibling, current)
        pos //= 2
    return current.hex() == root_hex


def _verify_holder_signature(holder_jwk: dict[str, str], digest: bytes, signature_b64: str) -> bool:
    if not isinstance(digest, bytes) or len(digest) != 32:
        return False
    try:
        numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(_b64url_decode(holder_jwk["x"]), "big"),
            int.from_bytes(_b64url_decode(holder_jwk["y"]), "big"),
            ec.SECP256R1(),
        )
        public_key = numbers.public_key()
        sig = _b64url_decode(signature_b64)
        if len(sig) != 64:
            return False
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        der = encode_dss_signature(r, s)
        public_key.verify(der, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except Exception:
        return False


def _attribute_definitions(claim: Claim) -> dict[str, str]:
    definitions: dict[str, str] = {}
    for alias, spec in claim.document.get("attributes", {}).items():
        path = spec.get("path", [])
        if not isinstance(path, list) or len(path) != 1 or not isinstance(path[0], str):
            raise ValueError("unsupported attribute path")
        definitions[alias] = path[0]
    return definitions


def _topological_order(require: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {entry["id"]: entry for entry in require}
    deps: dict[str, set[str]] = {entry["id"]: set() for entry in require}
    for entry in require:
        for value in entry.get("args", {}).values():
            if isinstance(value, dict) and "assertion" in value:
                deps[entry["id"]].add(value["assertion"])
    ordered: list[dict[str, Any]] = []
    seen: set[str] = set()

    def visit(node_id: str) -> None:
        if node_id in seen:
            return
        for dep in deps.get(node_id, set()):
            if dep in by_id:
                visit(dep)
        seen.add(node_id)
        ordered.append(by_id[node_id])

    for entry in require:
        visit(entry["id"])
    return ordered


def _evaluation_order(require: list[dict[str, Any]]) -> list[dict[str, Any]]:
    auth = [entry for entry in require if entry.get("assert") == AUTH_OPERATION]
    rest = [entry for entry in require if entry.get("assert") != AUTH_OPERATION]
    return auth + _topological_order(rest)


def _has_status(require: list[dict[str, Any]]) -> bool:
    return any(entry.get("assert") == STATUS_OPERATION for entry in require)


def _validate_fixture(fixture: Any, *, need_status: bool) -> dict[str, Any]:
    if not isinstance(fixture, dict):
        raise ClaimError("invalid fixture")
    allowed = {"credential", "holder_signature", "presentation_context", "status_witness"}
    if set(fixture.keys()) - allowed:
        raise ClaimError("invalid fixture")
    required = {"credential", "holder_signature", "presentation_context"}
    if need_status:
        required.add("status_witness")
    if not required <= set(fixture.keys()):
        raise ClaimError("invalid fixture")
    if not isinstance(fixture["credential"], str) or not fixture["credential"]:
        raise ClaimError("invalid fixture")
    holder_sig = fixture["holder_signature"]
    context = fixture["presentation_context"]
    if not isinstance(holder_sig, str) or not _B64URL_SIG.fullmatch(holder_sig):
        raise ClaimError("invalid holder encoding")
    if not isinstance(context, str) or not _HEX64.fullmatch(context):
        raise ClaimError("invalid context encoding")
    _b64url_decode(holder_sig)
    if "status_witness" in fixture:
        witness = fixture["status_witness"]
        if not isinstance(witness, dict) or set(witness.keys()) != {"index", "bit", "siblings"}:
            raise ClaimError("invalid status witness")
        index = witness["index"]
        bit = witness["bit"]
        siblings = witness["siblings"]
        if isinstance(index, bool) or not isinstance(index, int) or index < 0:
            raise ClaimError("invalid status witness")
        if isinstance(bit, bool) or bit not in (0, 1):
            raise ClaimError("invalid status witness")
        if not isinstance(siblings, list):
            raise ClaimError("invalid status witness")
        for item in siblings:
            if not isinstance(item, str) or not _HEX64.fullmatch(item):
                raise ClaimError("invalid status witness")
    return fixture


def evaluate_claim(claim: Any, fixture: dict[str, Any], given: dict[str, Any]) -> dict[str, Any]:
    try:
        validated_claim = _as_claim(claim)
        validated_given = validate_given(validated_claim, given)
        document = validated_claim.document
        require = document.get("require", [])
        fixture = _validate_fixture(fixture, need_status=_has_status(require))
        attr_defs = _attribute_definitions(validated_claim)
    except (ClaimError, CredentialError, ValueError, TypeError, UnicodeEncodeError):
        return _invalid_input()

    assertions_out: dict[str, dict[str, Any]] = {}
    assertion_outputs: dict[str, dict[str, Any]] = {}
    authenticated = None
    auth_failed = False
    witness = fixture.get("status_witness")

    for entry in _evaluation_order(require):
        assertion_id = entry["id"]
        operation = entry["assert"]
        args = entry.get("args", {})

        if auth_failed and operation != AUTH_OPERATION:
            assertions_out[assertion_id] = _not_run()
            continue

        try:
            if operation == AUTH_OPERATION:
                issuer = _resolve_operand(
                    args["issuer"],
                    claim=validated_claim,
                    fixture=fixture,
                    given=validated_given,
                    authenticated=None,
                    assertion_outputs=assertion_outputs,
                )
                authenticated = authenticate(fixture["credential"], issuer, attr_defs)
                assertions_out[assertion_id] = _ok(True)
            elif operation == "credential.expected-metadata@1":
                issuer = _resolve_operand(
                    args["issuer"],
                    claim=validated_claim,
                    fixture=fixture,
                    given=validated_given,
                    authenticated=authenticated,
                    assertion_outputs=assertion_outputs,
                )
                value = (
                    authenticated.issuer_id == issuer["issuer_id"]
                    and authenticated.key_id == issuer["key_id"]
                    and authenticated.credential_type in issuer["allowed_vcts"]
                )
                assertions_out[assertion_id] = _ok(value)
            elif operation == "credential.valid-at@1":
                now_raw = _resolve_operand(
                    args["time"],
                    claim=validated_claim,
                    fixture=fixture,
                    given=validated_given,
                    authenticated=authenticated,
                    assertion_outputs=assertion_outputs,
                )
                now = int(now_raw)
                value = authenticated.nbf <= now < authenticated.exp
                assertions_out[assertion_id] = _ok(value)
            elif operation == CONTEXT_OPERATION:
                expected = expected_transcript(validated_claim, validated_given)
                value = fixture["presentation_context"] == expected.hex()
                assertion_outputs[assertion_id] = {"expected_transcript": expected}
                assertions_out[assertion_id] = _ok(value)
            elif operation == CHALLENGE_BOUND_OPERATION:
                challenge_hex = _resolve_operand(
                    args["challenge"],
                    claim=validated_claim,
                    fixture=fixture,
                    given=validated_given,
                    authenticated=authenticated,
                    assertion_outputs=assertion_outputs,
                )
                expected = bytes.fromhex(challenge_hex)
                value = fixture["presentation_context"] == expected.hex()
                assertion_outputs[assertion_id] = {"expected_transcript": expected}
                assertions_out[assertion_id] = _ok(value)
            elif operation == "holder.signature-valid@1":
                transcript = _resolve_operand(
                    args["transcript"],
                    claim=validated_claim,
                    fixture=fixture,
                    given=validated_given,
                    authenticated=authenticated,
                    assertion_outputs=assertion_outputs,
                )
                value = _verify_holder_signature(
                    authenticated.holder_key,
                    transcript,
                    fixture["holder_signature"],
                )
                assertions_out[assertion_id] = _ok(value)
            elif operation == STATUS_OPERATION:
                reference = _resolve_operand(
                    args["reference"],
                    claim=validated_claim,
                    fixture=fixture,
                    given=validated_given,
                    authenticated=authenticated,
                    assertion_outputs=assertion_outputs,
                )
                now_raw = _resolve_operand(
                    args["time"],
                    claim=validated_claim,
                    fixture=fixture,
                    given=validated_given,
                    authenticated=authenticated,
                    assertion_outputs=assertion_outputs,
                )
                now = int(now_raw)
                list_length = reference["list_length"]
                if isinstance(list_length, bool) or not isinstance(list_length, int):
                    raise ClaimError("invalid list_length")
                if len(witness["siblings"]) != _status_depth(list_length):
                    assertions_out[assertion_id] = _ok(False)
                    continue
                index = witness["index"]
                value = (
                    reference["issuer_id"] == authenticated.issuer_id
                    and reference["key_id"] == authenticated.key_id
                    and reference["subject"] == authenticated.status_uri
                    and index == authenticated.status_index
                    and 0 <= index < list_length
                    and now < int(reference["valid_before"])
                    and _verify_status_path(
                        index=index,
                        bit=witness["bit"],
                        siblings=witness["siblings"],
                        root_hex=reference["commitment"],
                        list_length=list_length,
                    )
                )
                assertions_out[assertion_id] = _ok(value)
            else:
                assertions_out[assertion_id] = _not_run()
        except CredentialError:
            if operation == AUTH_OPERATION:
                auth_failed = True
                authenticated = None
            assertions_out[assertion_id] = _ok(False)
        except Exception:
            assertions_out[assertion_id] = _ok(False)

    if auth_failed or authenticated is None:
        condition = _not_run()
    else:
        try:
            condition = _ok(
                evaluate_where(validated_claim, authenticated.attributes, validated_given)
            )
        except ClaimError:
            condition = _ok(False)

    selected = [entry["id"] for entry in require]
    if set(assertions_out.keys()) != set(selected):
        for assertion_id in selected:
            assertions_out.setdefault(assertion_id, _not_run())

    all_true = all(
        assertions_out[assertion_id].get("status") == "ok"
        and assertions_out[assertion_id].get("value") is True
        for assertion_id in selected
    )
    overall = all_true and condition.get("status") == "ok" and condition.get("value") is True
    return {
        "status": "ok",
        "value": overall,
        "assertions": assertions_out,
        "condition": condition,
    }

"""Claim loader, validation, and where-clause evaluation."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from semantics.canonical import (
    canonical_digest,
    canonical_json_bytes,
    parse_json_strict,
)
from semantics.catalog import Catalog, load_catalog
from semantics.claim_types import (
    GIVEN_ARG_TYPES,
    ClaimError,
    parse_type_name,
    validate_attribute_path,
    validate_given_record,
    validate_scalar,
    validate_type_name,
)
from semantics.predicates import evaluate_predicate

# Re-export for public API consumers.
__all__ = [
    "Claim",
    "ClaimError",
    "evaluate_where",
    "load_claim",
    "validate_claim",
    "validate_given",
]

CLAIM_SCHEMA = "swiyu.claim.v0"
FRAGMENT_SCHEMA = "swiyu.condition-fragment.v0"
MAX_CLAIM_BYTES = 65536
MAX_JSON_DEPTH = 32
MAX_ATTRIBUTES = 16
MAX_REQUIRE = 16
MAX_PREDICATE_LEAVES = 32
MAX_WHERE_DEPTH = 4
MIN_FANOUT = 2
MAX_FANOUT = 8

MANDATORY_ASSERTIONS = frozenset(
    {
        "credential.authentic@1",
        "credential.expected-metadata@1",
        "credential.valid-at@1",
        "holder.signature-valid@1",
        "presentation.context-bound@1",
    }
)
STATUS_ASSERTION = "status.zero-at-reference@1"
CONTEXT_ASSERTION = "presentation.context-bound@1"
CHALLENGE_BOUND_ASSERTION = "presentation.challenge-bound@1"
CONTEXT_ASSERTIONS = frozenset({CONTEXT_ASSERTION, CHALLENGE_BOUND_ASSERTION})
AUTH_ASSERTION = "credential.authentic@1"
LEGACY_RECIPE = "swiyu.show-context@0"
SYNTHETIC_RECIPE = "claim.context@1"
SYNTHETIC_FORMAT = "platform.sd-jwt-es256@1"

CLAIM_TOP_LEVEL = frozenset(
    {
        "schema",
        "id",
        "packages",
        "credential",
        "attributes",
        "given",
        "require",
        "where",
        "release",
    }
)

KNOWN_PREDICATES = frozenset(
    {
        "value.equals@1",
        "value.in-set@1",
        "date.on-or-before@1",
        "date.yyyymmdd-age-at-least@1",
    }
)

RELEASE_FIELDS = frozenset(
    {
        "observer",
        "semantic_values",
        "protocol_derived",
        "opaque_channels",
        "branch_identity",
    }
)
RELEASE_SEMANTIC_BASE = frozenset({"acceptance"})
REQUIRE_BASE_KEYS = frozenset({"id", "assert", "args"})
REQUIRE_CONTEXT_KEYS = REQUIRE_BASE_KEYS | {"recipe"}


@dataclass(frozen=True)
class Claim:
    _document: dict[str, Any]
    statement_digest: str
    _dependencies: dict[str, str]

    @property
    def document(self) -> dict[str, Any]:
        return copy.deepcopy(self._document)

    @property
    def dependencies(self) -> dict[str, str]:
        return dict(self._dependencies)


def load_claim(path: Path | str) -> Claim:
    claim_path = Path(path)
    with claim_path.open("rb") as stream:
        raw = stream.read(MAX_CLAIM_BYTES + 1)
    if len(raw) > MAX_CLAIM_BYTES:
        raise ClaimError("claim too large")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ClaimError("invalid claim encoding")
    try:
        document = parse_json_strict(text)
    except ValueError as exc:
        raise ClaimError("invalid claim json") from exc
    if not isinstance(document, dict):
        raise ClaimError("claim must be an object")
    return validate_claim(document)


def validate_claim(document: dict[str, Any], catalog: Catalog | None = None) -> Claim:
    if not isinstance(document, dict):
        raise ClaimError("claim must be an object")
    _validate_json_shape(document)
    _enforce_payload_size(document, label="claim")
    doc = copy.deepcopy(document)
    catalog = catalog or load_catalog()
    _validate_top_level(doc, catalog)
    dependencies = _package_dependencies(doc, catalog)
    statement_digest = _statement_digest(doc, dependencies)
    return Claim(
        _document=copy.deepcopy(doc),
        statement_digest=statement_digest,
        _dependencies=dict(dependencies),
    )


def _claim_document(claim: Claim) -> dict[str, Any]:
    if isinstance(claim, Claim):
        return claim._document
    document = getattr(claim, "document", None)
    if isinstance(document, dict):
        return document
    raise ClaimError("invalid claim")


def validate_given(claim: Claim, given: dict[str, Any]) -> dict[str, Any]:
    _assert_claim_integrity(claim)
    if not isinstance(given, dict):
        raise ClaimError("invalid given")
    _validate_json_shape(given)
    _enforce_payload_size(given, label="given")
    spec = _claim_document(claim).get("given", {})
    if set(given.keys()) != set(spec.keys()):
        raise ClaimError("given keys mismatch")
    out: dict[str, Any] = {}
    for name, type_spec in spec.items():
        max_items = type_spec.get("max_items") if isinstance(type_spec, dict) else None
        type_name = type_spec["type"] if isinstance(type_spec, dict) else type_spec
        out[name] = validate_given_record(type_name, given[name], max_items=max_items)
    return out


def evaluate_where(
    claim: Claim,
    attributes: dict[str, Any],
    given: dict[str, Any],
) -> bool:
    _assert_claim_integrity(claim)
    document = _claim_document(claim)
    attr_spec = document["attributes"]
    given_spec = document["given"]
    _validate_all_attributes_present(attributes, attr_spec)
    typed_attrs = _validate_attributes(attributes, attr_spec)
    referenced_given = _collect_referenced_given(document["where"])
    typed_given = _validate_given_subset(given, given_spec, referenced_given)
    return _evaluate_where_node(
        document["where"],
        typed_attrs,
        typed_given,
        attr_spec,
        given_spec,
    )


def _validate_top_level(doc: dict[str, Any], catalog: Catalog) -> None:
    if doc.get("schema") == FRAGMENT_SCHEMA:
        raise ClaimError("condition fragment rejected")
    if doc.get("schema") != CLAIM_SCHEMA:
        raise ClaimError("unknown claim schema")
    unknown = set(doc.keys()) - CLAIM_TOP_LEVEL
    if unknown:
        raise ClaimError("unknown claim field")
    if not isinstance(doc.get("id"), str) or not doc["id"]:
        raise ClaimError("invalid claim id")
    _validate_packages(doc.get("packages"), catalog)
    _validate_credential(doc)
    _validate_attributes_section(doc)
    _validate_given_section(doc)
    _validate_require(doc, catalog)
    _validate_where(doc)
    _validate_release(doc)


def _validate_packages(packages: Any, catalog: Catalog) -> None:
    if not isinstance(packages, dict):
        raise ClaimError("invalid packages")
    expected = frozenset({"format", "assertions", "predicates"})
    if set(packages.keys()) != expected:
        raise ClaimError("invalid packages")
    for key in expected:
        package_id = packages[key]
        if not isinstance(package_id, str):
            raise ClaimError("invalid package reference")
        catalog.package(package_id)


def _validate_credential(doc: dict[str, Any]) -> None:
    credential = doc.get("credential")
    if not isinstance(credential, dict):
        raise ClaimError("invalid credential")
    if set(credential.keys()) != {"id", "format"}:
        raise ClaimError("invalid credential shape")
    if not isinstance(credential["id"], str) or not credential["id"]:
        raise ClaimError("invalid credential id")
    if credential["format"] != doc["packages"]["format"]:
        raise ClaimError("credential format mismatch")


def _validate_attributes_section(doc: dict[str, Any]) -> None:
    attributes = doc.get("attributes")
    if not isinstance(attributes, dict) or not attributes:
        raise ClaimError("invalid attributes")
    if len(attributes) > MAX_ATTRIBUTES:
        raise ClaimError("too many attributes")
    credential_id = doc["credential"]["id"]
    for alias, spec in attributes.items():
        if not isinstance(alias, str) or not alias or alias in {"issuer", "key_id", "credential_type"}:
            raise ClaimError("invalid attribute alias")
        if not isinstance(spec, dict):
            raise ClaimError("invalid attribute spec")
        expected = frozenset({"credential", "path", "type"})
        if set(spec.keys()) != expected:
            raise ClaimError("invalid attribute spec shape")
        if spec["credential"] != credential_id:
            raise ClaimError("attribute credential mismatch")
        validate_attribute_path(spec["path"])
        validate_type_name(spec["type"])
        if spec["type"] not in {"swiyu.date@0", "swiyu.unix-seconds@0", "ascii-code2@1", "utf8@1"}:
            raise ClaimError("attribute requires a supported scalar type")


def _validate_given_section(doc: dict[str, Any]) -> None:
    given = doc.get("given")
    if not isinstance(given, dict) or not given:
        raise ClaimError("invalid given")
    for name, spec in given.items():
        if not isinstance(name, str) or not name:
            raise ClaimError("invalid given name")
        if not isinstance(spec, dict) or set(spec.keys()) - {"type", "max_items"}:
            raise ClaimError("invalid given spec")
        if "type" not in spec:
            raise ClaimError("missing given type")
        validate_type_name(spec["type"])
        if "max_items" in spec:
            base, _, _ = parse_type_name(spec["type"])
            if base != "set":
                raise ClaimError("max_items on scalar")
            max_items = spec["max_items"]
            if not isinstance(max_items, int) or isinstance(max_items, bool):
                raise ClaimError("invalid max_items")
            if max_items < 1 or max_items > 16:
                raise ClaimError("invalid max_items")


def _validate_require(doc: dict[str, Any], catalog: Catalog) -> None:
    require = doc.get("require")
    if not isinstance(require, list) or not require:
        raise ClaimError("invalid require")
    if len(require) > MAX_REQUIRE:
        raise ClaimError("too many require entries")
    assertion_pkg = catalog.package(doc["packages"]["assertions"]).document
    known_assertions = frozenset(assertion_pkg.get("assertions", {}).keys())
    known_recipes = frozenset(assertion_pkg.get("recipes", {}).keys())
    mandatory = frozenset(assertion_pkg.get("mandatory_assertions", MANDATORY_ASSERTIONS))
    seen_ids: set[str] = set()
    seen_asserts: set[str] = set()
    context_assertion_id: str | None = None
    holder_assertion_id: str | None = None
    graph: dict[str, set[str]] = {}
    present_mandatory = set()
    has_status = False
    assertion_defs = assertion_pkg.get("assertions", {})
    for entry in require:
        if not isinstance(entry, dict):
            raise ClaimError("invalid require entry")
        assert_name = entry.get("assert")
        allowed_keys = (
            REQUIRE_CONTEXT_KEYS
            if assert_name == CONTEXT_ASSERTION
            else REQUIRE_BASE_KEYS
        )
        unknown_entry = set(entry.keys()) - allowed_keys
        if unknown_entry:
            raise ClaimError("unknown require field")
        if assert_name != CONTEXT_ASSERTION and "recipe" in entry:
            raise ClaimError("recipe on wrong assertion")
        entry_id = entry.get("id")
        if not isinstance(entry_id, str) or not entry_id or entry_id in seen_ids:
            raise ClaimError("invalid require id")
        if not isinstance(assert_name, str) or assert_name not in known_assertions:
            raise ClaimError("unknown assertion")
        if assert_name in seen_asserts:
            raise ClaimError("duplicate assertion operation")
        seen_ids.add(entry_id)
        seen_asserts.add(assert_name)
        if assert_name in mandatory:
            present_mandatory.add(assert_name)
        if assert_name == STATUS_ASSERTION:
            has_status = True
        if assert_name == CONTEXT_ASSERTION:
            context_assertion_id = entry_id
            recipe = entry.get("recipe")
            if not isinstance(recipe, str) or recipe not in known_recipes:
                raise ClaimError("unknown recipe")
            if doc["packages"]["format"] == SYNTHETIC_FORMAT:
                if recipe == LEGACY_RECIPE:
                    raise ClaimError("legacy recipe rejected for synthetic package")
                if recipe != SYNTHETIC_RECIPE:
                    raise ClaimError("invalid synthetic recipe")
        if assert_name == CHALLENGE_BOUND_ASSERTION:
            context_assertion_id = entry_id
        if assert_name == "holder.signature-valid@1":
            holder_assertion_id = entry_id
        deps = _assertion_dependencies(entry, entry_id)
        graph[entry_id] = deps
        _validate_assertion_args(entry, doc, assertion_defs)
    if present_mandatory != mandatory:
        raise ClaimError("missing mandatory assertion")
    if _has_cycle(graph):
        raise ClaimError("cyclic assertion dependencies")
    if holder_assertion_id is not None and context_assertion_id is not None:
        transcript = _holder_transcript_ref(require, holder_assertion_id)
        if transcript["assertion"] != context_assertion_id:
            raise ClaimError("holder transcript must reference context assertion")
        if transcript["output"] != "expected_transcript":
            raise ClaimError("invalid holder transcript output")
    if not has_status and STATUS_ASSERTION in seen_asserts:
        raise ClaimError("invalid status configuration")


def _holder_transcript_ref(require: list[dict[str, Any]], holder_id: str) -> dict[str, Any]:
    for entry in require:
        if entry.get("id") == holder_id:
            transcript = entry.get("args", {}).get("transcript")
            if not isinstance(transcript, dict):
                raise ClaimError("invalid holder transcript")
            return transcript
    raise ClaimError("missing holder assertion")


def _assertion_dependencies(entry: dict[str, Any], entry_id: str) -> set[str]:
    deps: set[str] = set()
    args = entry.get("args", {})
    if not isinstance(args, dict):
        raise ClaimError("invalid assertion args")
    for value in args.values():
        if isinstance(value, dict) and "assertion" in value:
            dep = value["assertion"]
            if not isinstance(dep, str) or dep == entry_id:
                raise ClaimError("invalid assertion dependency")
            deps.add(dep)
    transcript = args.get("transcript")
    if isinstance(transcript, dict) and "assertion" in transcript:
        deps.add(transcript["assertion"])
    return deps


def _validate_assertion_args(
    entry: dict[str, Any],
    doc: dict[str, Any],
    assertion_defs: dict[str, Any],
) -> None:
    args = entry.get("args")
    if not isinstance(args, dict):
        raise ClaimError("invalid assertion args")
    assertion_def = assertion_defs[entry["assert"]]
    args_spec = assertion_def.get("args", {})
    if args_spec.get("dynamic"):
        if not args:
            raise ClaimError("invalid assertion args")
        if "session" not in args:
            raise ClaimError("missing session role")
        for arg_name, operand in args.items():
            _validate_context_operand(arg_name, operand, doc)
        return
    if set(args.keys()) != set(args_spec.keys()):
        raise ClaimError("invalid assertion args")
    for arg_name, spec in args_spec.items():
        operand = args[arg_name]
        ref = spec.get("ref")
        if ref == "credential":
            _validate_credential_operand(operand, doc["credential"]["id"])
        elif ref == "given":
            _validate_guard_given_operand(arg_name, operand, doc)
        elif ref == "assertion_output":
            _validate_assertion_output_operand(operand, doc, assertion_defs)
        else:
            raise ClaimError("unknown assertion operand ref")


def _validate_credential_operand(operand: Any, credential_id: str) -> None:
    if not isinstance(operand, dict) or operand != {"credential": credential_id}:
        raise ClaimError("invalid credential operand")


def _validate_guard_given_operand(
    arg_name: str,
    operand: Any,
    doc: dict[str, Any],
) -> None:
    if not isinstance(operand, dict) or set(operand.keys()) != {"given"}:
        raise ClaimError("invalid given operand")
    given_name = operand["given"]
    given_spec = doc["given"].get(given_name)
    if not isinstance(given_spec, dict):
        raise ClaimError("invalid given operand")
    expected_type = GIVEN_ARG_TYPES.get(arg_name)
    if expected_type is None or given_spec.get("type") != expected_type:
        raise ClaimError("invalid given operand type")


def _validate_context_operand(arg_name: str, operand: Any, doc: dict[str, Any]) -> None:
    if not isinstance(operand, dict) or set(operand.keys()) != {"given"}:
        raise ClaimError("invalid context operand")
    given_name = operand["given"]
    if given_name not in doc["given"]:
        raise ClaimError("invalid given operand")
    if arg_name == "session":
        if doc["given"][given_name]["type"] != "platform.expected-session@1":
            raise ClaimError("invalid session role")


def _validate_assertion_output_operand(
    operand: Any,
    doc: dict[str, Any],
    assertion_defs: dict[str, Any],
) -> None:
    if not isinstance(operand, dict) or set(operand.keys()) != {"assertion", "output"}:
        raise ClaimError("invalid assertion output operand")
    assertion_id = operand.get("assertion")
    output = operand.get("output")
    if not isinstance(assertion_id, str) or not isinstance(output, str):
        raise ClaimError("invalid assertion output operand")
    target_assert: str | None = None
    for entry in doc.get("require", ()):
        if entry.get("id") == assertion_id:
            target_assert = entry.get("assert")
            break
    if not isinstance(target_assert, str):
        raise ClaimError("invalid assertion dependency")
    outputs = frozenset(assertion_defs.get(target_assert, {}).get("outputs", ()))
    if output not in outputs:
        raise ClaimError("undeclared assertion output")


def _has_cycle(graph: dict[str, set[str]]) -> bool:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> bool:
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        for dep in graph.get(node, ()):
            if visit(dep):
                return True
        visiting.remove(node)
        visited.add(node)
        return False

    return any(visit(node) for node in graph)


def _validate_where(doc: dict[str, Any]) -> None:
    where = doc.get("where")
    if not isinstance(where, dict):
        raise ClaimError("invalid where")
    leaf_count = [0]
    _validate_where_node(where, doc, depth=1, leaves=leaf_count)
    if leaf_count[0] > MAX_PREDICATE_LEAVES:
        raise ClaimError("too many predicate leaves")


def _validate_where_node(
    node: dict[str, Any],
    doc: dict[str, Any],
    *,
    depth: int,
    leaves: list[int],
) -> None:
    if depth > MAX_WHERE_DEPTH:
        raise ClaimError("where depth exceeded")
    keys = set(node.keys())
    if "predicate" in keys:
        if keys != {"predicate", "args"}:
            raise ClaimError("invalid predicate node")
        predicate = node["predicate"]
        if predicate not in KNOWN_PREDICATES:
            raise ClaimError("unknown predicate")
        leaves[0] += 1
        _validate_predicate_args(node["args"], predicate, doc)
        return
    if "all" in keys or "any" in keys:
        if len(keys) != 1:
            raise ClaimError("invalid composition node")
        group_key = "all" if "all" in keys else "any"
        children = node[group_key]
        if not isinstance(children, list):
            raise ClaimError("invalid composition children")
        count = len(children)
        if count < MIN_FANOUT or count > MAX_FANOUT:
            raise ClaimError("invalid composition fan-out")
        signatures: set[str] = set()
        for child in children:
            if not isinstance(child, dict):
                raise ClaimError("invalid composition child")
            sig = canonical_digest(child)
            if sig in signatures:
                raise ClaimError("duplicate sibling expression")
            signatures.add(sig)
            _validate_where_node(child, doc, depth=depth + 1, leaves=leaves)
        return
    raise ClaimError("invalid where node")


def _validate_predicate_args(args: Any, predicate: str, doc: dict[str, Any]) -> None:
    if not isinstance(args, dict):
        raise ClaimError("invalid predicate args")
    attr_names = set(doc["attributes"].keys())
    given_names = set(doc["given"].keys())
    expected_args = _predicate_arg_names(predicate)
    if set(args.keys()) != expected_args:
        raise ClaimError("invalid predicate args")
    operand_types: dict[str, str] = {}
    for arg_name, operand in args.items():
        operand_types[arg_name] = _resolve_operand_type(operand, doc, attr_names, given_names)
    _check_predicate_operand_types(predicate, operand_types)
    if not any(
        isinstance(operand, dict) and "attribute" in operand for operand in args.values()
    ):
        raise ClaimError("predicate requires attribute operand")


def _predicate_arg_names(predicate: str) -> frozenset[str]:
    if predicate == "value.equals@1":
        return frozenset({"left", "right"})
    if predicate == "value.in-set@1":
        return frozenset({"value", "set"})
    if predicate == "date.on-or-before@1":
        return frozenset({"value", "limit"})
    if predicate == "date.yyyymmdd-age-at-least@1":
        return frozenset({"birthdate", "reference", "min_years"})
    raise ClaimError("unknown predicate")


def _resolve_operand_type(
    operand: Any,
    doc: dict[str, Any],
    attr_names: set[str],
    given_names: set[str],
) -> str:
    if not isinstance(operand, dict) or len(operand) != 1:
        raise ClaimError("invalid operand")
    if "attribute" in operand:
        alias = operand["attribute"]
        if alias not in attr_names:
            raise ClaimError("unknown attribute")
        return doc["attributes"][alias]["type"]
    if "given" in operand:
        name = operand["given"]
        if name not in given_names:
            raise ClaimError("unknown given")
        return doc["given"][name]["type"]
    if "const" in operand:
        value = operand["const"]
        if predicate_arg_type := _const_operand_type(value):
            return predicate_arg_type
        raise ClaimError("invalid const operand")
    raise ClaimError("invalid operand")


def _const_operand_type(value: Any) -> str | None:
    if isinstance(value, str) and value == "25":
        return "swiyu.unix-seconds@0"
    return None


def _check_predicate_operand_types(predicate: str, operand_types: dict[str, str]) -> None:
    if predicate == "date.on-or-before@1":
        for key in ("value", "limit"):
            if operand_types[key] != "swiyu.date@0":
                raise ClaimError("operand type mismatch")
    if predicate == "date.yyyymmdd-age-at-least@1":
        if operand_types["birthdate"] != "swiyu.date@0":
            raise ClaimError("operand type mismatch")
        if operand_types["reference"] != "swiyu.date-yyyymmdd@0":
            raise ClaimError("operand type mismatch")
        if operand_types["min_years"] != "swiyu.unix-seconds@0":
            raise ClaimError("operand type mismatch")
    if predicate == "value.in-set@1":
        value_type = operand_types["value"]
        set_type = operand_types["set"]
        base, element, _ = parse_type_name(set_type)
        if base != "set" or element != value_type:
            raise ClaimError("operand type mismatch")
    if predicate == "value.equals@1":
        if operand_types["left"] != operand_types["right"]:
            raise ClaimError("operand type mismatch")


def _validate_release(doc: dict[str, Any]) -> None:
    release = doc.get("release")
    if not isinstance(release, dict):
        raise ClaimError("invalid release")
    if set(release.keys()) != RELEASE_FIELDS:
        raise ClaimError("unknown release field")
    credential_id = doc["credential"]["id"]
    has_metadata_assertion = any(
        entry.get("assert") == "credential.expected-metadata@1"
        for entry in doc.get("require", [])
    )
    expected_metadata = (
        {
            f"{credential_id}.issuer",
            f"{credential_id}.key_id",
            f"{credential_id}.credential_type",
        }
        if has_metadata_assertion
        else frozenset()
    )
    semantic_values = release["semantic_values"]
    if not isinstance(semantic_values, list):
        raise ClaimError("invalid semantic_values")
    if len(semantic_values) != len(set(semantic_values)):
        raise ClaimError("duplicate semantic_values")
    if set(semantic_values) != RELEASE_SEMANTIC_BASE | expected_metadata:
        raise ClaimError("invalid semantic_values")
    protocol = release["protocol_derived"]
    has_context = any(
        entry.get("assert") == CONTEXT_ASSERTION for entry in doc.get("require", [])
    )
    if has_context:
        if protocol != [SYNTHETIC_RECIPE]:
            raise ClaimError("invalid protocol_derived")
    elif protocol != []:
        raise ClaimError("invalid protocol_derived")
    if release["observer"] != "verifier":
        raise ClaimError("invalid observer")
    if release["opaque_channels"] != ["proof"]:
        raise ClaimError("invalid opaque_channels")
    if release["branch_identity"] != "hidden":
        raise ClaimError("invalid branch_identity")


def _package_dependencies(doc: dict[str, Any], catalog: Catalog) -> dict[str, str]:
    deps: dict[str, str] = {}
    for role, package_id in doc["packages"].items():
        deps[f"packages.{role}"] = catalog.package(package_id).digest
    for source_name, digest in catalog.sources.items():
        deps[f"sources.{source_name}"] = digest
    return deps


def _assert_claim_integrity(claim: Claim) -> None:
    if not isinstance(claim, Claim):
        return
    expected = _statement_digest(claim._document, claim._dependencies)
    if expected != claim.statement_digest:
        raise ClaimError("claim digest mismatch")


def _enforce_payload_size(payload: Any, *, label: str) -> None:
    try:
        size = len(canonical_json_bytes(payload))
    except ValueError as exc:
        raise ClaimError(f"invalid {label}") from exc
    if size > MAX_CLAIM_BYTES:
        raise ClaimError(f"{label} too large")


def _validate_json_shape(value: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ClaimError("excessive nesting")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ClaimError("invalid object key")
            _validate_json_shape(item, depth + 1)
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_shape(item, depth + 1)
        return
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        return
    if isinstance(value, float):
        raise ClaimError("invalid number")
    if isinstance(value, str):
        return
    raise ClaimError("invalid json value")


def _statement_digest(doc: dict[str, Any], dependencies: dict[str, str]) -> str:
    payload = {
        "claim": doc,
        "dependencies": dependencies,
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _validate_all_attributes_present(
    attributes: dict[str, Any],
    attr_spec: dict[str, Any],
) -> None:
    if set(attributes.keys()) != set(attr_spec.keys()):
        raise ClaimError("missing attribute")


def _validate_attributes(
    attributes: dict[str, Any],
    attr_spec: dict[str, Any],
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for alias, spec in attr_spec.items():
        type_name = spec["type"]
        out[alias] = validate_scalar(type_name, attributes[alias])
    return out


def _collect_referenced_given(where: dict[str, Any]) -> set[str]:
    refs: set[str] = set()
    _collect_referenced_given_node(where, refs)
    return refs


def _collect_referenced_given_node(node: dict[str, Any], refs: set[str]) -> None:
    if "predicate" in node:
        for operand in node.get("args", {}).values():
            if isinstance(operand, dict) and "given" in operand:
                refs.add(operand["given"])
        return
    for key in ("all", "any"):
        if key in node:
            for child in node[key]:
                _collect_referenced_given_node(child, refs)


def _validate_given_subset(
    given: dict[str, Any],
    given_spec: dict[str, Any],
    referenced: set[str],
) -> dict[str, Any]:
    if not isinstance(given, dict):
        raise ClaimError("invalid given")
    unknown = set(given.keys()) - set(given_spec.keys())
    if unknown:
        raise ClaimError("unknown given field")
    missing = referenced - set(given.keys())
    if missing:
        raise ClaimError("missing given field")
    out: dict[str, Any] = {}
    for name in referenced:
        spec = given_spec[name]
        max_items = spec.get("max_items")
        out[name] = validate_given_record(spec["type"], given[name], max_items=max_items)
    return out


def _evaluate_where_node(
    node: dict[str, Any],
    attributes: dict[str, Any],
    given: dict[str, Any],
    attr_spec: dict[str, Any],
    given_spec: dict[str, Any],
) -> bool:
    if "predicate" in node:
        predicate = node["predicate"]
        resolved_args: dict[str, Any] = {}
        operand_types: dict[str, str] = {}
        for arg_name, operand in node["args"].items():
            value, type_name = _resolve_operand_value(
                operand, attributes, given, attr_spec, given_spec
            )
            resolved_args[arg_name] = value
            operand_types[arg_name] = type_name
        return evaluate_predicate(predicate, resolved_args, operand_types)
    if "all" in node:
        return all(
            _evaluate_where_node(child, attributes, given, attr_spec, given_spec)
            for child in node["all"]
        )
    if "any" in node:
        return any(
            _evaluate_where_node(child, attributes, given, attr_spec, given_spec)
            for child in node["any"]
        )
    raise ClaimError("invalid where node")


def _resolve_operand_value(
    operand: dict[str, Any],
    attributes: dict[str, Any],
    given: dict[str, Any],
    attr_spec: dict[str, Any],
    given_spec: dict[str, Any],
) -> tuple[Any, str]:
    if "attribute" in operand:
        alias = operand["attribute"]
        return attributes[alias], attr_spec[alias]["type"]
    if "given" in operand:
        name = operand["given"]
        return given[name], given_spec[name]["type"]
    if "const" in operand:
        value = operand["const"]
        type_name = _const_operand_type(value)
        if type_name is None:
            raise ClaimError("invalid const operand")
        return validate_scalar(type_name, value), type_name
    raise ClaimError("invalid operand")

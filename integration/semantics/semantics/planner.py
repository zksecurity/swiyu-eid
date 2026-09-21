"""Synthetic campaign case planner — claim-generic, no per-claim branches."""

from __future__ import annotations

import copy
import hashlib
import itertools
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Any

from semantics.assertions import evaluate_claim
from semantics.fixtures import make_fixture, reauthorize_fixture

MAX_SEARCH = 256
DEFAULT_MAX_CASES = 64

_AUTH = "credential.authentic@1"
_META = "credential.expected-metadata@1"
_VALID = "credential.valid-at@1"
_HOLDER = "holder.signature-valid@1"
_CONTEXT = "presentation.context-bound@1"
_STATUS = "status.zero-at-reference@1"


@dataclass
class PlanCase:
    id: str
    recipe: str
    expectation_basis: str
    expected_verdict: bool
    fixture: dict[str, Any] = field(repr=False, default_factory=dict)
    given: dict[str, Any] = field(repr=False, default_factory=dict)
    reference_outcome: dict[str, Any] = field(repr=False, default_factory=dict)


def _stable_id(*parts: str) -> str:
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:12]
    return f"case-{digest}"


def _date_next(day: str) -> str:
    return (date.fromisoformat(day) + timedelta(days=1)).isoformat()


def _given_type(spec: Any) -> str:
    if isinstance(spec, dict):
        return spec["type"]
    return spec


def _attr_type(document: dict[str, Any], alias: str) -> str:
    return document["attributes"][alias]["type"]


def _mismatch_scalar(type_name: str, match: Any) -> Any:
    if type_name == "swiyu.date@0":
        return _date_next(str(match))
    if type_name == "ascii-code2@1":
        return "XX" if match != "XX" else "QQ"
    if type_name.startswith("utf8"):
        return str(match) + "-x"
    return str(match) + "-x"


def _collect_leaves(where: dict[str, Any]) -> list[dict[str, Any]]:
    if "predicate" in where:
        return [where]
    if "all" in where:
        leaves: list[dict[str, Any]] = []
        for node in where["all"]:
            leaves.extend(_collect_leaves(node))
        return leaves
    if "any" in where:
        leaves = []
        for node in where["any"]:
            leaves.extend(_collect_leaves(node))
        return leaves
    return []


def _first_any(where: dict[str, Any]) -> list[dict[str, Any]] | None:
    if "any" in where:
        return list(where["any"])
    if "all" in where:
        for node in where["all"]:
            found = _first_any(node)
            if found is not None:
                return found
    return None


def _eval_node(node: dict[str, Any], attrs: dict[str, Any], given: dict[str, Any]) -> bool:
    if "predicate" in node:
        predicate = node["predicate"]
        args = node.get("args", {})

        def resolve(operand: dict[str, Any]) -> Any:
            if "attribute" in operand:
                return attrs[operand["attribute"]]
            return given[operand["given"]]

        if predicate == "value.equals@1":
            return resolve(args["left"]) == resolve(args["right"])
        if predicate == "value.in-set@1":
            members = resolve(args["set"])
            return resolve(args["value"]) in members
        if predicate == "date.on-or-before@1":
            return str(resolve(args["value"])) <= str(resolve(args["limit"]))
        return False
    if "all" in node:
        return all(_eval_node(child, attrs, given) for child in node["all"])
    if "any" in node:
        return any(_eval_node(child, attrs, given) for child in node["any"])
    return False


def _or_label(where: dict[str, Any], attrs: dict[str, Any], given: dict[str, Any]) -> str | None:
    branches = _first_any(where)
    if not branches or len(branches) < 2:
        return None
    bits = "".join("t" if _eval_node(branch, attrs, given) else "f" for branch in branches[:2])
    return f"or_{bits}"


def _candidates_for_leaf(
    leaf: dict[str, Any],
    *,
    document: dict[str, Any],
    base_attrs: dict[str, Any],
    base_given: dict[str, Any],
) -> list[tuple[dict[str, Any], dict[str, Any], bool]]:
    predicate = leaf["predicate"]
    args = leaf.get("args", {})
    variants: list[tuple[dict[str, Any], dict[str, Any], bool]] = []

    if predicate == "value.equals@1":
        left = args["left"]
        right = args["right"]
        if "attribute" in left and "given" in right:
            alias = left["attribute"]
            given_name = right["given"]
            match = base_given.get(given_name, base_attrs.get(alias))
            variants.append(({alias: match}, {given_name: match}, True))
            variants.append(
                ({alias: _mismatch_scalar(_attr_type(document, alias), match)}, {given_name: match}, False)
            )
    elif predicate == "value.in-set@1":
        value = args["value"]
        set_arg = args["set"]
        if "attribute" in value and "given" in set_arg:
            alias = value["attribute"]
            set_name = set_arg["given"]
            members = list(base_given.get(set_name, ["CH", "DE"]))
            member = members[0] if members else base_attrs.get(alias)
            variants.append(({alias: member}, {set_name: members}, True))
            variants.append(
                (
                    {alias: _mismatch_scalar(_attr_type(document, alias), member)},
                    {set_name: members},
                    False,
                )
            )
    elif predicate == "date.on-or-before@1":
        value = args["value"]
        limit = args["limit"]
        if "attribute" in value and "given" in limit:
            alias = value["attribute"]
            limit_name = limit["given"]
            cutoff = base_given.get(limit_name, "2008-01-01")
            variants.append(({alias: cutoff}, {limit_name: cutoff}, True))
            variants.append(({alias: _date_next(cutoff)}, {limit_name: cutoff}, False))
    if not variants:
        variants.append(({}, {}, True))
    return variants


def _merge_assignment(
    where: dict[str, Any],
    assignment: dict[int, tuple[dict[str, Any], dict[str, Any], bool]],
    *,
    base_attrs: dict[str, Any],
    base_given: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    attrs = dict(base_attrs)
    given = copy.deepcopy(base_given)
    for leaf in _collect_leaves(where):
        variant = assignment.get(id(leaf))
        if variant is None:
            continue
        a, g, _verdict = variant
        attrs.update(a)
        for key, value in g.items():
            given[key] = copy.deepcopy(value)
    return attrs, given


def _given_overrides_only(full_given: dict[str, Any], base_given: dict[str, Any]) -> dict[str, Any]:
    overrides: dict[str, Any] = {}
    for key, value in full_given.items():
        if key not in base_given or value != base_given[key]:
            overrides[key] = copy.deepcopy(value)
    return overrides


def _case_from_bundle(
    claim: Any,
    *,
    recipe: str,
    basis: str,
    bundle: dict[str, Any],
    expected: bool,
    seed: int,
) -> PlanCase | None:
    ref = evaluate_claim(claim, bundle["fixture"], bundle["given"])
    if ref.get("status") != "ok":
        return None
    if bool(ref.get("value")) is not bool(expected):
        return None
    case_id = _stable_id(recipe, basis, str(expected), str(seed))
    return PlanCase(
        id=case_id,
        recipe=recipe,
        expectation_basis=basis,
        expected_verdict=expected,
        fixture=bundle["fixture"],
        given=bundle["given"],
        reference_outcome=ref,
    )


def _not_run_case(recipe: str, reason: str) -> PlanCase:
    return PlanCase(
        id=_stable_id("not_run", recipe, reason),
        recipe=recipe,
        expectation_basis="not_run",
        expected_verdict=False,
        reference_outcome={"status": "not_run", "reason": reason},
    )


def _require_by_operation(document: dict[str, Any], operation: str) -> dict[str, Any] | None:
    for entry in document.get("require", []):
        if entry.get("assert") == operation:
            return entry
    return None


def _given_name(entry: dict[str, Any], arg: str) -> str | None:
    operand = entry.get("args", {}).get(arg, {})
    if isinstance(operand, dict) and "given" in operand:
        return operand["given"]
    return None


def _append_unique(cases: list[PlanCase], case: PlanCase | None) -> None:
    if case is None:
        return
    if any(existing.id == case.id or existing.recipe == case.recipe for existing in cases):
        return
    cases.append(case)


def _assertion_failure_cases(claim: Any, *, seed: int) -> list[PlanCase]:
    document = claim.document
    positive = make_fixture(claim, seed=seed)
    cases: list[PlanCase] = []

    auth = _require_by_operation(document, _AUTH)
    if auth is not None:
        issuer_name = _given_name(auth, "issuer")
        other = make_fixture(claim, seed=seed + 17)
        given = copy.deepcopy(positive["given"])
        if issuer_name:
            given[issuer_name] = copy.deepcopy(other["given"][issuer_name])
        bundle = {"fixture": copy.deepcopy(positive["fixture"]), "given": given}
        _append_unique(
            cases,
            _case_from_bundle(
                claim,
                recipe=f"assertion_failure:{auth['id']}:issuer_key",
                basis="assertion_failure",
                bundle=bundle,
                expected=False,
                seed=seed,
            ),
        )

    meta = _require_by_operation(document, _META)
    if meta is not None:
        issuer_name = _given_name(meta, "issuer")
        given = copy.deepcopy(positive["given"])
        if issuer_name:
            given[issuer_name]["allowed_vcts"] = ["urn:swiyu:excluded-type"]
        refreshed = reauthorize_fixture(claim, positive["fixture"], given, seed=seed)
        _append_unique(
            cases,
            _case_from_bundle(
                claim,
                recipe=f"assertion_failure:{meta['id']}:allowed_vct",
                basis="assertion_failure",
                bundle=refreshed,
                expected=False,
                seed=seed,
            ),
        )

    valid = _require_by_operation(document, _VALID)
    if valid is not None:
        expired = make_fixture(claim, seed=seed, nbf=1_800_000_001)
        _append_unique(
            cases,
            _case_from_bundle(
                claim,
                recipe=f"assertion_failure:{valid['id']}:nbf_boundary",
                basis="assertion_failure",
                bundle=expired,
                expected=False,
                seed=seed,
            ),
        )

    holder = _require_by_operation(document, _HOLDER)
    if holder is not None:
        fixture = copy.deepcopy(positive["fixture"])
        fixture["holder_signature"] = "A" * 86
        bundle = {"fixture": fixture, "given": copy.deepcopy(positive["given"])}
        _append_unique(
            cases,
            _case_from_bundle(
                claim,
                recipe=f"assertion_failure:{holder['id']}:holder_signature",
                basis="assertion_failure",
                bundle=bundle,
                expected=False,
                seed=seed,
            ),
        )

    context = _require_by_operation(document, _CONTEXT)
    if context is not None:
        fixture = copy.deepcopy(positive["fixture"])
        fixture["presentation_context"] = "0" * 64
        bundle = {"fixture": fixture, "given": copy.deepcopy(positive["given"])}
        _append_unique(
            cases,
            _case_from_bundle(
                claim,
                recipe=f"assertion_failure:{context['id']}:presentation_context",
                basis="assertion_failure",
                bundle=bundle,
                expected=False,
                seed=seed,
            ),
        )

    status = _require_by_operation(document, _STATUS)
    if status is None:
        cases.append(
            _not_run_case(
                "assertion_failure:status",
                "status guard absent from claim require roster",
            )
        )
    else:
        status_name = _given_name(status, "reference")
        given = copy.deepcopy(positive["given"])
        if status_name:
            given[status_name]["commitment"] = "f" * 64
        refreshed = reauthorize_fixture(claim, positive["fixture"], given, seed=seed)
        _append_unique(
            cases,
            _case_from_bundle(
                claim,
                recipe=f"assertion_failure:{status['id']}:commitment",
                basis="assertion_failure",
                bundle=refreshed,
                expected=False,
                seed=seed,
            ),
        )
    return cases


def _or_explicit_cases(
    claim: Any,
    *,
    seed: int,
    base_attrs: dict[str, Any],
    base_given: dict[str, Any],
) -> list[PlanCase]:
    document = claim.document
    branches = _first_any(document["where"])
    if not branches or len(branches) < 2:
        return []
    left_leaves = _collect_leaves(branches[0])
    right_leaves = _collect_leaves(branches[1])
    other_leaves = [
        leaf
        for leaf in _collect_leaves(document["where"])
        if leaf not in left_leaves and leaf not in right_leaves
    ]
    left_vars = [
        _candidates_for_leaf(leaf, document=document, base_attrs=base_attrs, base_given=base_given)
        for leaf in left_leaves
    ]
    right_vars = [
        _candidates_for_leaf(leaf, document=document, base_attrs=base_attrs, base_given=base_given)
        for leaf in right_leaves
    ]
    other_true = []
    for leaf in other_leaves:
        options = _candidates_for_leaf(leaf, document=document, base_attrs=base_attrs, base_given=base_given)
        true_opts = [item for item in options if item[2]]
        other_true.append(true_opts[0] if true_opts else options[0])

    labels = ("or_tt", "or_tf", "or_ft", "or_ff")
    want = ((True, True), (True, False), (False, True), (False, False))
    cases: list[PlanCase] = []
    for label, (want_l, want_r) in zip(labels, want):
        found = None
        left_space = itertools.product(*left_vars) if left_vars else [()]
        right_space = itertools.product(*right_vars) if right_vars else [()]
        for left_combo, right_combo in itertools.islice(itertools.product(left_space, right_space), MAX_SEARCH):
            attrs = dict(base_attrs)
            given = copy.deepcopy(base_given)
            for a, g, _v in other_true:
                attrs.update(a)
                given.update(copy.deepcopy(g))
            for a, g, _v in left_combo:
                attrs.update(a)
                given.update(copy.deepcopy(g))
            for a, g, _v in right_combo:
                attrs.update(a)
                given.update(copy.deepcopy(g))
            if _eval_node(branches[0], attrs, given) is not want_l:
                continue
            if _eval_node(branches[1], attrs, given) is not want_r:
                continue
            overrides = _given_overrides_only(given, base_given)
            bundle = make_fixture(claim, attributes=attrs, given_overrides=overrides, seed=seed)
            expected = _eval_node(document["where"], attrs, bundle["given"])
            recipe = f"or_branch:{label}"
            found = _case_from_bundle(
                claim,
                recipe=recipe,
                basis="where_true" if expected else "where_false",
                bundle=bundle,
                expected=expected,
                seed=seed,
            )
            if found is not None:
                break
        if found is None:
            cases.append(_not_run_case(f"or_branch:{label}", "OR branch not constructible under typed candidates"))
        else:
            cases.append(found)
    return cases


def plan_campaign_cases(
    claim: Any,
    *,
    seed: int = 1,
    max_cases: int = DEFAULT_MAX_CASES,
) -> list[PlanCase]:
    document = claim.document if hasattr(claim, "document") else claim
    where = document["where"]
    intended: list[PlanCase] = []

    base_bundle = make_fixture(claim, seed=seed)
    base_given = base_bundle["given"]
    attr_defaults = {
        alias: _default_attr_from_bundle(base_bundle, document, alias)
        for alias in document.get("attributes", {})
    }

    positive = _case_from_bundle(
        claim,
        recipe="positive_control",
        basis="positive_control",
        bundle=base_bundle,
        expected=True,
        seed=seed,
    )
    _append_unique(intended, positive)

    leaves = _collect_leaves(where)
    leaf_variants = [
        _candidates_for_leaf(
            leaf, document=document, base_attrs=attr_defaults, base_given=base_given
        )
        for leaf in leaves
    ]
    search = itertools.product(*leaf_variants) if leaf_variants else [()]
    for combo in itertools.islice(search, MAX_SEARCH):
        assignment = {id(leaf): variant for leaf, variant in zip(leaves, combo)}
        attrs, given = _merge_assignment(
            where, assignment, base_attrs=attr_defaults, base_given=base_given
        )
        verdict = _eval_node(where, attrs, given)
        if verdict and positive:
            continue
        overrides = _given_overrides_only(given, base_given)
        bundle = make_fixture(claim, attributes=attrs, given_overrides=overrides, seed=seed)
        recipe = "predicate:where_false" if not verdict else "predicate:where_true"
        case = _case_from_bundle(
            claim,
            recipe=recipe,
            basis="where_true" if verdict else "where_false",
            bundle=bundle,
            expected=verdict,
            seed=seed,
        )
        _append_unique(intended, case)

    for case in _or_explicit_cases(
        claim, seed=seed, base_attrs=attr_defaults, base_given=base_given
    ):
        _append_unique(intended, case)

    for case in _assertion_failure_cases(claim, seed=seed):
        _append_unique(intended, case)

    if max_cases <= 0:
        return []
    if len(intended) <= max_cases:
        return intended
    omitted = intended[max_cases - 1 :]
    kept = intended[: max_cases - 1]
    kept.append(
        _not_run_case(
            "unrun_recipes:" + ",".join(case.recipe for case in omitted),
            "max_cases omitted remaining cryptographic recipes",
        )
    )
    return kept


def _default_attr_from_bundle(
    bundle: dict[str, Any], document: dict[str, Any], alias: str
) -> Any:
    # Attribute values live in the signed credential, not given. Use type defaults
    # matching make_fixture when the alias is absent from overrides.
    type_name = document["attributes"][alias]["type"]
    if type_name == "swiyu.date@0":
        return "2000-01-01"
    if type_name == "ascii-code2@1":
        return "CH"
    return "synthetic"

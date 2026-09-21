"""Campaign-only provider support manifest validation and artifact pin checks."""

from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any

SUPPORT_SCHEMA = "swiyu.claim-support.v0"
ENFORCEMENT_STAGES = frozenset({"proof", "verifier", "both"})
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class SupportError(ValueError):
    pass


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _confine(target: Path, roots: list[Path]) -> bool:
    resolved = target.resolve()
    for root in roots:
        root_resolved = root.resolve()
        try:
            resolved.relative_to(root_resolved)
            return True
        except ValueError:
            continue
    return False


def _reject_nonfinite(value: Any) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise SupportError("nonfinite JSON number")
    if isinstance(value, dict):
        for item in value.values():
            _reject_nonfinite(item)
    elif isinstance(value, list):
        for item in value:
            _reject_nonfinite(item)


def _parse_support_json(text: str) -> Any:
    def check_duplicates(pairs: list[tuple[Any, Any]]) -> dict[str, Any]:
        seen: set[str] = set()
        obj: dict[str, Any] = {}
        for key, val in pairs:
            if not isinstance(key, str):
                raise SupportError("non-string JSON object key")
            if key in seen:
                raise SupportError("duplicate JSON object key")
            seen.add(key)
            obj[key] = val
        return obj

    def parse_constant(name: str) -> None:
        raise SupportError(f"nonfinite JSON: {name}")

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=check_duplicates,
            parse_constant=parse_constant,
        )
    except SupportError:
        raise
    except json.JSONDecodeError as exc:
        raise SupportError("invalid support JSON") from exc
    except ValueError as exc:
        raise SupportError("invalid support JSON") from exc
    _reject_nonfinite(parsed)
    return parsed


def _hex_digest(value: Any, *, what: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise SupportError(f"invalid {what}")
    return value


def _validate_enforcement_map(enforcement: Any) -> dict[str, Any]:
    if not isinstance(enforcement, dict):
        raise SupportError("enforcement map required")
    for assertion_id, stage in enforcement.items():
        if not isinstance(assertion_id, str) or not assertion_id:
            raise SupportError("invalid enforcement id")
        if stage not in ENFORCEMENT_STAGES:
            raise SupportError("invalid enforcement stage")
    return enforcement


def load_support(path: str | Path) -> dict[str, Any]:
    support_path = Path(path).resolve()
    if not support_path.is_file():
        raise SupportError("support manifest not found")
    document = _parse_support_json(support_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise SupportError("support must be object")
    validate_support(document, support_path.parent)
    document["_support_dir"] = str(support_path.parent)
    document["_support_path"] = str(support_path)
    return document


def validate_support(document: dict[str, Any], base_dir: Path) -> None:
    if document.get("schema") != SUPPORT_SCHEMA:
        raise SupportError("unsupported support schema")
    claims = document.get("supported_claims")
    if not isinstance(claims, list) or not claims:
        raise SupportError("supported_claims required")
    seen: set[str] = set()
    seen_digests: set[str] = set()
    for entry in claims:
        if not isinstance(entry, dict):
            raise SupportError("invalid supported claim entry")
        claim_id = entry.get("id")
        digest = entry.get("statement_digest")
        if not isinstance(claim_id, str) or not claim_id:
            raise SupportError("invalid supported claim id")
        if claim_id in seen:
            raise SupportError("duplicate supported claim id")
        seen.add(claim_id)
        _hex_digest(digest, what="statement digest")
        if digest in seen_digests:
            raise SupportError("duplicate supported claim digest")
        seen_digests.add(digest)
        profile = entry.get("implementation_profile")
        circuit = entry.get("circuit")
        if (profile is None) != (circuit is None):
            raise SupportError("implementation profile and circuit must be declared together")
        if profile is not None:
            if not isinstance(profile, str) or not profile:
                raise SupportError("invalid implementation profile")
            if not isinstance(circuit, str) or not circuit:
                raise SupportError("invalid circuit")
        if "enforcement" in entry:
            _validate_enforcement_map(entry.get("enforcement"))
    _validate_enforcement_map(document.get("enforcement"))
    artifacts = document.get("artifact_pins")
    if not isinstance(artifacts, list) or not artifacts:
        raise SupportError("artifact_pins required")
    approved = [base_dir.resolve()]
    for rel_root in document.get("approved_roots", []):
        if not isinstance(rel_root, str):
            raise SupportError("invalid approved root")
        approved.append((base_dir / rel_root).resolve())
    seen_paths: set[str] = set()
    for pin in artifacts:
        if not isinstance(pin, dict):
            raise SupportError("invalid artifact pin")
        rel = pin.get("path")
        digest = pin.get("sha256")
        if not isinstance(rel, str) or not rel:
            raise SupportError("invalid artifact path")
        if rel in seen_paths:
            raise SupportError("duplicate artifact path")
        seen_paths.add(rel)
        _hex_digest(digest, what="artifact digest")
        target = (base_dir / rel).resolve()
        if not _confine(target, approved):
            raise SupportError("artifact path escapes approved roots")
        if not target.is_file():
            raise SupportError(f"missing artifact: {rel}")
        if _file_digest(target) != digest:
            raise SupportError(f"stale artifact pin: {rel}")


def _required_ids(claim: Any) -> set[str]:
    document = claim.document if hasattr(claim, "document") else claim
    required = {entry["id"] for entry in document.get("require", [])}
    required.add("where")
    return required


def _selected_enforcement(support: dict[str, Any], matched: dict[str, Any], required: set[str]) -> dict[str, Any]:
    if isinstance(matched.get("enforcement"), dict):
        return matched["enforcement"]
    global_map = support.get("enforcement") or {}
    if set(global_map) != required:
        return global_map
    return global_map


def verify_claim_supported(
    support: dict[str, Any],
    *,
    claim_id: str,
    statement_digest: str,
    claim: Any | None = None,
    implementation_profile: str | None = None,
    circuit: str | None = None,
) -> None:
    if (implementation_profile is None) != (circuit is None):
        raise SupportError("implementation profile and circuit must be selected together")
    matched = None
    for entry in support.get("supported_claims", []):
        identity_matches = (
            entry.get("id") == claim_id
            and entry.get("statement_digest") == statement_digest
        )
        implementation_matches = implementation_profile is None or (
            entry.get("implementation_profile") == implementation_profile
            and entry.get("circuit") == circuit
        )
        if identity_matches and implementation_matches:
            matched = entry
            break
    if matched is None:
        raise SupportError("claim not registered in support manifest")
    if claim is None:
        return
    actual_digest = getattr(claim, "statement_digest", None)
    if actual_digest is not None and actual_digest != statement_digest:
        raise SupportError("claim digest does not match semantic claim document")
    required = _required_ids(claim)
    enforcement = set(_selected_enforcement(support, matched, required))
    missing = required - enforcement
    extra = enforcement - required
    if missing:
        raise SupportError(f"missing enforcement obligations: {sorted(missing)}")
    if extra:
        raise SupportError(f"extra enforcement obligations: {sorted(extra)}")


def implementation_digest(support: dict[str, Any], manifest_path: str | Path) -> str:
    hasher = hashlib.sha256()
    hasher.update(Path(manifest_path).read_bytes())
    support_path = support.get("_support_path")
    if support_path:
        hasher.update(Path(support_path).read_bytes())
    for pin in support.get("artifact_pins", []):
        hasher.update(pin["path"].encode("utf-8"))
        hasher.update(bytes.fromhex(pin["sha256"]))
    return hasher.hexdigest()


def refresh_support_digests(support_path: str | Path) -> dict[str, Any]:
    """Development-only helper: rewrite artifact pin digests from disk. Never called at load."""
    path = Path(support_path).resolve()
    document = json.loads(path.read_text(encoding="utf-8"))
    base_dir = path.parent
    updated: list[dict[str, str]] = []
    for pin in document.get("artifact_pins", []):
        rel = pin["path"]
        target = (base_dir / rel).resolve()
        updated.append({"path": rel, "sha256": _file_digest(target)})
    document["artifact_pins"] = updated
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return document

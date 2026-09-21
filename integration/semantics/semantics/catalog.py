"""Pinned semantic catalog loader."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from semantics.canonical import canonical_digest, parse_json_strict
from semantics.claim_types import KNOWN_TYPES, ClaimError

SEMANTICS_ROOT = Path(__file__).resolve().parents[1]
CATALOG_LOCK_PATH = SEMANTICS_ROOT / "catalog.lock.json"
LOCK_SCHEMA = "swiyu.semantic-catalog-lock.v0"

CORE_SOURCE_SPECS = {
    "claims": "semantics/claims.py",
    "catalog": "semantics/catalog.py",
    "claim_types": "semantics/claim_types.py",
    "predicates": "semantics/predicates.py",
    "canonical": "semantics/canonical.py",
    "credentials": "semantics/credentials.py",
    "assertions": "semantics/assertions.py",
}

PACKAGE_SCHEMAS = {
    "swiyu.semantic-format-package.v0",
    "swiyu.semantic-assertion-package.v0",
    "swiyu.semantic-predicate-package.v0",
}

KNOWN_PREDICATE_IDS = frozenset(
    {
        "value.equals@1",
        "value.in-set@1",
        "date.on-or-before@1",
        "date.yyyymmdd-age-at-least@1",
    }
)


@dataclass(frozen=True)
class PackageEntry:
    package_id: str
    path: Path
    digest: str
    document: dict[str, Any]


@dataclass(frozen=True)
class Catalog:
    lock_path: Path
    packages: dict[str, PackageEntry]
    types: frozenset[str]
    sources: dict[str, str]

    def package(self, package_id: str) -> PackageEntry:
        entry = self.packages.get(package_id)
        if entry is None:
            raise ClaimError("unknown catalog package")
        return entry


def _resolve_under_root(lock_root: Path, rel: str) -> Path:
    if not isinstance(rel, str) or rel.startswith("/") or ".." in Path(rel).parts:
        raise ClaimError("invalid catalog package path")
    path = (lock_root / rel).resolve()
    root = lock_root.resolve()
    if path != root and root not in path.parents:
        raise ClaimError("catalog path escape")
    return path


def _load_source_pins(lock_root: Path, sources_spec: Any) -> dict[str, str]:
    if not isinstance(sources_spec, dict):
        raise ClaimError("invalid catalog sources")
    sources: dict[str, str] = {}
    for name, spec in sources_spec.items():
        if name in sources:
            raise ClaimError("duplicate catalog source id")
        if not isinstance(spec, dict):
            raise ClaimError("invalid catalog source pin")
        rel = spec.get("path")
        pinned = spec.get("digest")
        if not isinstance(rel, str) or not isinstance(pinned, str):
            raise ClaimError("invalid catalog source pin")
        path = _resolve_under_root(lock_root, rel)
        if not path.is_file():
            raise ClaimError("missing catalog source file")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != pinned:
            raise ClaimError("catalog source digest mismatch")
        sources[name] = digest
    expected_names = set(CORE_SOURCE_SPECS.keys())
    if set(sources.keys()) != expected_names:
        raise ClaimError("incomplete catalog source pins")
    return sources


def _load_package(lock_root: Path, package_id: str, spec: dict[str, Any]) -> PackageEntry:
    rel = spec.get("path")
    pinned = spec.get("digest")
    if not isinstance(rel, str) or not isinstance(pinned, str):
        raise ClaimError("invalid catalog package pin")
    path = _resolve_under_root(lock_root, rel)
    if not path.is_file():
        raise ClaimError("missing catalog package file")
    text = path.read_text(encoding="utf-8")
    document = parse_json_strict(text)
    if not isinstance(document, dict):
        raise ClaimError("invalid catalog package document")
    digest = canonical_digest(document)
    if digest != pinned:
        raise ClaimError("catalog package digest mismatch")
    doc_id = document.get("id")
    if doc_id != package_id:
        raise ClaimError("catalog package id mismatch")
    schema = document.get("schema")
    if schema not in PACKAGE_SCHEMAS:
        raise ClaimError("unknown catalog package schema")
    if schema == "swiyu.semantic-predicate-package.v0":
        predicates = document.get("predicates")
        if not isinstance(predicates, dict) or set(predicates.keys()) != KNOWN_PREDICATE_IDS:
            raise ClaimError("catalog predicate mismatch")
    return PackageEntry(
        package_id=package_id,
        path=path,
        digest=digest,
        document=document,
    )


def load_catalog(path: Path | None = None) -> Catalog:
    lock_path = path or CATALOG_LOCK_PATH
    text = lock_path.read_text(encoding="utf-8")
    lock = parse_json_strict(text)
    if not isinstance(lock, dict):
        raise ClaimError("invalid catalog lock")
    if lock.get("schema") != LOCK_SCHEMA:
        raise ClaimError("unknown catalog lock schema")
    packages_spec = lock.get("packages")
    if not isinstance(packages_spec, dict):
        raise ClaimError("invalid catalog packages")
    lock_root = lock_path.parent
    packages: dict[str, PackageEntry] = {}
    for package_id, spec in packages_spec.items():
        if package_id in packages:
            raise ClaimError("duplicate catalog package id")
        if not isinstance(spec, dict):
            raise ClaimError("invalid catalog package pin")
        packages[package_id] = _load_package(lock_root, package_id, spec)
    types_spec = lock.get("types")
    if not isinstance(types_spec, dict):
        raise ClaimError("invalid catalog types")
    if set(types_spec.keys()) != set(KNOWN_TYPES):
        raise ClaimError("catalog type mismatch")
    sources = _load_source_pins(lock_root, lock.get("sources"))
    return Catalog(
        lock_path=lock_path,
        packages=packages,
        types=frozenset(types_spec.keys()),
        sources=sources,
    )


def load_catalog_lock_document(path: Path | None = None) -> dict[str, Any]:
    lock_path = path or CATALOG_LOCK_PATH
    return json.loads(lock_path.read_text(encoding="utf-8"))

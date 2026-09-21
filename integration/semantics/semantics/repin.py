"""Explicit catalog source-pin maintenance (--check / --write only)."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from semantics.catalog import CATALOG_LOCK_PATH, CORE_SOURCE_SPECS, SEMANTICS_ROOT

LOCK_SCHEMA = "swiyu.semantic-catalog-lock.v0"


def _source_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _build_sources() -> dict[str, dict[str, str]]:
    sources: dict[str, dict[str, str]] = {}
    for name, rel in CORE_SOURCE_SPECS.items():
        path = SEMANTICS_ROOT / rel
        if not path.is_file():
            raise SystemExit(f"missing source file: {rel}")
        sources[name] = {"path": rel, "digest": _source_digest(path)}
    return sources


def _load_lock() -> dict[str, Any]:
    return json.loads(CATALOG_LOCK_PATH.read_text(encoding="utf-8"))


def cmd_check() -> int:
    lock = _load_lock()
    expected = _build_sources()
    actual = lock.get("sources")
    if actual != expected:
        print("catalog source pins are stale", file=sys.stderr)
        return 1
    print(json.dumps({"status": "ok", "sources": sorted(expected.keys())}))
    return 0


def cmd_write() -> int:
    lock = _load_lock()
    lock["sources"] = _build_sources()
    CATALOG_LOCK_PATH.write_text(
        json.dumps(lock, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"status": "ok", "wrote": str(CATALOG_LOCK_PATH)}))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="semantics.repin")
    parser.add_argument("--check", action="store_true", help="verify source pins")
    parser.add_argument("--write", action="store_true", help="rewrite source pins")
    args = parser.parse_args(argv)
    if args.check and args.write:
        print("specify only one of --check or --write", file=sys.stderr)
        return 2
    if args.check:
        return cmd_check()
    if args.write:
        return cmd_write()
    print("specify --check or --write", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

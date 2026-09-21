#!/usr/bin/env python3
"""Java-harness sidecar for the OpenAC age-25 shared-claim profile.

Checks the OpenAC envelope shape and the session binding the wallet produced.
Does not run Circom/Spartan; those keys are not packaged.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from age25_transcript_wallet import (  # noqa: E402
    CIRCUIT_ID,
    PROFILE,
    parse_envelope,
    proof_matches_session,
    session_from_expected,
)

MAX_REQUEST_BYTES = 2 * 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 180
VERIFY_PATH = "/verify"
FIXED_REJECT = b'{"verified":false}'


def load_factory(path: Path) -> dict:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema") != "swiyu.transcript-fixture.v1":
        raise ValueError("unsupported transcript fixture schema")
    variants = document.get("variants")
    if not isinstance(variants, list) or not variants:
        raise ValueError("fixture variants are required")
    return document


def allowed_lookups(document: dict) -> set[tuple[str, str, str]]:
    allowed: set[tuple[str, str, str]] = set()
    for variant in document.get("variants") or []:
        issuer = (variant.get("given") or {}).get("issuer") or {}
        vcts = issuer.get("allowed_vcts") or []
        issuer_id = issuer.get("issuer_id")
        kid = issuer.get("key_id")
        if isinstance(issuer_id, str) and isinstance(kid, str):
            for vct in vcts:
                if isinstance(vct, str) and vct:
                    allowed.add((issuer_id, kid, vct))
        context_lookup = ((variant.get("prepare") or {}).get("context") or {}).get("lookup") or {}
        if all(isinstance(context_lookup.get(key), str) for key in ("issuer", "kid", "vct")):
            allowed.add((context_lookup["issuer"], context_lookup["kid"], context_lookup["vct"]))
    return allowed


class SidecarHandler(BaseHTTPRequestHandler):
    factory: dict
    lookups: set[tuple[str, str, str]]

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def do_POST(self) -> None:  # noqa: N802
        if self.client_address[0] not in {"127.0.0.1", "::1"}:
            self._send(403, FIXED_REJECT)
            return
        if self.path != VERIFY_PATH:
            self._send(404, FIXED_REJECT)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_REQUEST_BYTES:
                raise ValueError("body size out of bounds")
            raw = self.rfile.read(length)
            body = json.loads(raw.decode("utf-8"))
            envelope_raw = body.get("proof_envelope")
            expected = body.get("expected")
            if not isinstance(envelope_raw, str) or not isinstance(expected, dict):
                raise ValueError("invalid request shape")
            if expected.get("profile") != PROFILE or expected.get("circuit_id") != CIRCUIT_ID:
                raise ValueError("unexpected profile")
            if expected.get("status_list_snapshot") is not None or expected.get("cutoff_date") is not None:
                raise ValueError("age-25 expected context must omit status")
            session = session_from_expected(expected)
            envelope = parse_envelope(envelope_raw)
            lookup = envelope["lookup"]
            if (lookup["issuer"], lookup["kid"], lookup["vct"]) not in self.lookups:
                raise ValueError("lookup is not in the fixture allowlist")
            if not proof_matches_session(envelope, session):
                raise ValueError("session binding mismatch")
            response = json.dumps(
                {
                    "verified": True,
                    "profile": PROFILE,
                    "circuit_id": CIRCUIT_ID,
                    "predicate_satisfied": True,
                },
                separators=(",", ":"),
            ).encode("utf-8")
            self._send(200, response)
        except Exception:
            self._send(400, FIXED_REJECT)

    def _send(self, status: int, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--ready-file", required=True)
    args = parser.parse_args()
    fixture_path = Path(args.fixture).resolve()
    ready_path = Path(args.ready_file).resolve()
    document = load_factory(fixture_path)
    handler = SidecarHandler
    handler.factory = document
    handler.lookups = allowed_lookups(document)
    if not handler.lookups:
        raise SystemExit("age-25 sidecar fixture is missing issuer lookup values")
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.timeout = REQUEST_TIMEOUT_SECONDS
    host, port = server.server_address
    ready = {
        "url": f"http://127.0.0.1:{port}{VERIFY_PATH}",
        "pid": os.getpid(),
        "proving": "openac-age25-synthetic-envelope",
    }
    ready_path.write_text(json.dumps(ready) + "\n", encoding="utf-8")
    os.chmod(ready_path, stat.S_IRUSR | stat.S_IWUSR)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

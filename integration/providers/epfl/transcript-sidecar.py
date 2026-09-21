#!/usr/bin/env python3
"""Harness-owned loopback HTTP wrapper around the EPFL native provider."""
from __future__ import annotations

import argparse
import json
import os
import signal
import stat
import subprocess
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from epfl_challenge import PROFILE, CIRCUIT_ID, coords_to_u8_list, digest_from_expected

MAX_REQUEST_BYTES = 2 * 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 180
VERIFY_PATH = "/verify"
FIXED_REJECT = b'{"verified":false}'
PROTOCOL = "swiyu.provider.v1"
D10_PROFILE = PROFILE
PROVIDER_DIR = Path(__file__).resolve().parent


class ProviderClient:
    def __init__(self) -> None:
        toolchain = os.environ.get(
            "SWIYU_EPFL_TOOLCHAIN",
            "/tmp/swiyu-epfl-20260915/owned/scratch/toolchain/bin",
        )
        env = os.environ.copy()
        env["PATH"] = f"{toolchain}:{env.get('PATH', '')}"
        env.setdefault("SWIYU_EPFL_CIRCUIT_ROOT", str(PROVIDER_DIR / "circuit"))
        env.setdefault("SWIYU_EPFL_WORK_ROOT", "/tmp/swiyu-epfl-native-sidecar")
        self._proc = subprocess.Popen(
            [sys.executable, str(PROVIDER_DIR / "provider.py")],
            cwd=PROVIDER_DIR,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            start_new_session=True,
        )
        init = self.call("initialize", {})
        if init.get("status") != "ok":
            raise RuntimeError(f"provider initialize failed: {init}")

    def call(self, operation: str, payload: dict) -> dict:
        assert self._proc.stdin and self._proc.stdout
        req_id = str(uuid.uuid4())
        self._proc.stdin.write(
            json.dumps({"protocol": PROTOCOL, "id": req_id, "operation": operation, "payload": payload})
            + "\n"
        )
        self._proc.stdin.flush()
        line = self._proc.stdout.readline()
        if not line:
            err = self._proc.stderr.read() if self._proc.stderr else ""
            raise RuntimeError(f"provider closed: {err}")
        msg = json.loads(line)
        if msg.get("id") != req_id:
            raise RuntimeError(f"provider id mismatch: {req_id} vs {msg.get('id')}")
        return msg

    def close(self) -> None:
        try:
            self.call("cleanup", {})
        except Exception:
            pass
        if self._proc.stdin:
            self._proc.stdin.close()
        if self._proc.poll() is None:
            try:
                os.killpg(self._proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self._proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self._proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass


def load_factory(path: Path) -> dict:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema") != "swiyu.transcript-fixture.v1":
        raise ValueError("unsupported transcript fixture schema")
    return document


def request_context_from_expected(expected: dict) -> dict:
    supplied = expected.get("challenge_nonce")
    if expected.get("binding_mode") == "native-static-v0":
        if not isinstance(supplied, str):
            raise ValueError("static native binding requires challenge_nonce hex")
        challenge_hex = supplied
    else:
        server_digest = digest_from_expected(expected)
        if not isinstance(supplied, str) or supplied != server_digest:
            raise ValueError("challenge_nonce does not match server reconstruction")
        challenge_hex = server_digest
    return {
        "issuer_pub_x": coords_to_u8_list(expected["issuer_pub_x"]),
        "issuer_pub_y": coords_to_u8_list(expected["issuer_pub_y"]),
        "now_date": int(expected["now_date"]),
        "challenge_nonce": coords_to_u8_list(challenge_hex),
    }


class SidecarHandler(BaseHTTPRequestHandler):
    provider: ProviderClient
    lock: threading.Lock

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
            envelope = body.get("proof_envelope")
            expected = body.get("expected")
            if not isinstance(envelope, str) or not isinstance(expected, dict):
                raise ValueError("invalid request shape")
            if expected.get("profile") != D10_PROFILE or expected.get("circuit_id") != CIRCUIT_ID:
                raise ValueError("unexpected profile")
            ctx = request_context_from_expected(expected)
            with self.lock:
                result = self.provider.call(
                    "verify",
                    {
                        "profile": D10_PROFILE,
                        "presentation": envelope,
                        "request_context": ctx,
                    },
                )
            verified = bool(result.get("status") == "ok" and result.get("result", {}).get("verified"))
            response = json.dumps(
                {
                    "verified": verified,
                    "profile": D10_PROFILE,
                    "circuit_id": CIRCUIT_ID,
                    "predicate_satisfied": verified,
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
    load_factory(fixture_path)
    provider = ProviderClient()
    handler = SidecarHandler
    handler.provider = provider
    handler.lock = threading.Lock()
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.timeout = REQUEST_TIMEOUT_SECONDS
    host, port = server.server_address
    ready = {"url": f"http://127.0.0.1:{port}{VERIFY_PATH}", "pid": os.getpid()}
    ready_path.write_text(json.dumps(ready) + "\n", encoding="utf-8")
    os.chmod(ready_path, stat.S_IRUSR | stat.S_IWUSR)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        provider.close()


if __name__ == "__main__":
    main()

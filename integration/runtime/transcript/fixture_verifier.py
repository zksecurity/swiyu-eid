"""Fixture-only mock verifier. Not production evidence."""

from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from uuid import uuid4


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _jwt(payload: dict) -> str:
    header = _b64(json.dumps({"alg": "ES256", "typ": "JWT", "profile_version": "swiss-profile-vc:1.0.0"}).encode())
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64(b"fixture-signature-opaque")
    return f"{header}.{body}.{sig}"


class _State:
    def __init__(self) -> None:
        self.sessions: dict[str, dict] = {}


def make_handler(state: _State, host: str):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args) -> None:
            return

        def _write(self, status: int, body: str, content_type: str) -> None:
            raw = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8")
            parsed = urlparse(self.path)
            if parsed.path == "/management/api/verifications":
                request_id = str(uuid4())
                payload = json.loads(raw or "{}")
                state.sessions[request_id] = {
                    "state": "PENDING",
                    "oauth": request_id,
                    "nonce": payload.get("nonce") or "fixture-nonce-aaaaaaaa",
                }
                body = json.dumps({"id": request_id, "state": "PENDING"})
                self._write(200, body, "application/json")
                return
            if parsed.path.endswith("/response-data"):
                request_id = parsed.path.split("/")[-2]
                form = parse_qs(raw, keep_blank_values=True)
                session = state.sessions.get(request_id)
                if session is None:
                    self._write(404, json.dumps({"error": "not_found"}), "application/json")
                    return
                posted_state = (form.get("state") or [""])[0]
                if posted_state != session["oauth"]:
                    self._write(400, json.dumps({"error": "state_mismatch"}), "application/json")
                    return
                if not (form.get("vp_token") or [""])[0]:
                    self._write(400, json.dumps({"error": "missing_vp_token"}), "application/json")
                    return
                session["state"] = "SUCCESS"
                self._write(200, "{}", "application/json")
                return
            self._write(404, "{}", "application/json")

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            parts = parsed.path.strip("/").split("/")
            if len(parts) == 4 and parts[0] == "oid4vp" and parts[2] == "request-object":
                request_id = parts[3]
                session = state.sessions.get(request_id)
                if session is None:
                    self._write(404, json.dumps({"error": "not_found"}), "application/json")
                    return
                response_uri = f"http://{host}/oid4vp/api/request-object/{request_id}/response-data"
                token = _jwt(
                    {
                        "response_uri": response_uri,
                        "response_mode": "direct_post",
                        "nonce": session["nonce"],
                        "state": session["oauth"],
                        "client_id": "x509_san_dns:verifier.example.ch",
                    }
                )
                self._write(200, token, "application/oauth-authz-req+jwt")
                return
            if len(parts) == 4 and parts[0] == "management" and parts[2] == "verifications":
                request_id = parts[3]
                session = state.sessions.get(request_id)
                if session is None:
                    self._write(404, json.dumps({"error": "not_found"}), "application/json")
                    return
                self._write(200, json.dumps({"id": request_id, "state": session["state"]}), "application/json")
                return
            self._write(404, "{}", "application/json")

    return Handler


class FixtureVerifier:
    """In-process mock of selected OID4VP HTTP. Never campaign evidence."""

    def __init__(self) -> None:
        self._state = _State()
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self._state, "pending"))
        host, port = self._httpd.server_address[:2]
        self.base = f"http://{host}:{port}"
        self._httpd.RequestHandlerClass = make_handler(self._state, f"{host}:{port}")
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def start(self) -> str:
        self._thread.start()
        return self.base

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

"""JSONL stdin/stdout provider process client (T06)."""
import errno
import fcntl
import json
import math
import os
import select
import signal
import subprocess
import threading
import time
import uuid
from typing import Any, Optional

from manifest import load_manifest

PROTOCOL = "swiyu.provider.v1"
DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_INPUT = 1048576
DEFAULT_MAX_OUTPUT = 65536
DEFAULT_MAX_STDERR = 8192
VALID_STATUSES = frozenset({"ok", "unsupported", "error"})
SHUTDOWN_CLEANUP_CAP = 1.0


class ProviderError(Exception):
    def __init__(self, code: str, message: str, status: str = "error"):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    seen: set[str] = set()
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"duplicate JSON key: {key}")
        seen.add(key)
        obj[key] = value
    return obj


def _reject_non_finite(value: Any) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite number in JSON")
    if isinstance(value, dict):
        for item in value.values():
            _reject_non_finite(item)
    elif isinstance(value, list):
        for item in value:
            _reject_non_finite(item)


def _parse_json_strict(raw: str) -> Any:
    try:
        parsed = json.loads(raw, object_pairs_hook=_reject_duplicate_keys, parse_constant=_nan_inf)
    except json.JSONDecodeError as exc:
        raise ProviderError("malformed", f"invalid JSON response: {exc}") from exc
    except ValueError as exc:
        raise ProviderError("malformed", str(exc)) from exc
    try:
        _reject_non_finite(parsed)
    except ValueError as exc:
        raise ProviderError("malformed", str(exc)) from exc
    return parsed


def _nan_inf(_name: str) -> None:
    raise ValueError("non-finite number in JSON")


def _set_nonblocking(fd: int) -> None:
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)


class ProviderClient:
    def __init__(
        self,
        manifest_path: str,
        timeout: float = DEFAULT_TIMEOUT,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT,
        max_input_bytes: int = DEFAULT_MAX_INPUT,
    ):
        self._manifest = load_manifest(manifest_path)
        self._timeout = timeout
        self._max_output = max_output_bytes
        self._max_input = max_input_bytes
        self._proc: Optional[subprocess.Popen] = None
        self._pgid: Optional[int] = None
        self._stderr_chunks: list[bytes] = []
        self._stderr_bytes = 0
        self._stderr_thread: Optional[threading.Thread] = None
        self._invalid = False

    def __enter__(self) -> "ProviderClient":
        self._start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._shutdown()

    @property
    def manifest(self) -> dict:
        return self._manifest

    def _protocol_fail(self, code: str, message: str) -> None:
        self._invalid = True
        raise ProviderError(code, message)

    def _start(self) -> None:
        cwd = self._manifest["_manifest_dir"]
        cmd = list(self._manifest["command"])
        if not cmd:
            raise ProviderError("launch", "empty command in manifest")
        for part in cmd:
            if not isinstance(part, str) or not part:
                raise ProviderError("launch", "invalid argv entry")
        try:
            self._proc = subprocess.Popen(
                cmd,
                cwd=cwd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError as exc:
            raise ProviderError("launch", str(exc)) from exc
        assert self._proc.stdin and self._proc.stdout and self._proc.stderr
        try:
            self._pgid = os.getpgid(self._proc.pid)
        except OSError:
            self._pgid = self._proc.pid
        _set_nonblocking(self._proc.stdin.fileno())
        _set_nonblocking(self._proc.stdout.fileno())
        _set_nonblocking(self._proc.stderr.fileno())
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr, daemon=True
        )
        self._stderr_thread.start()

    def _drain_stderr(self) -> None:
        proc = self._proc
        if proc is None or proc.stderr is None:
            return
        fd = proc.stderr.fileno()
        while True:
            if proc.poll() is not None:
                try:
                    chunk = os.read(fd, 4096)
                except OSError as exc:
                    if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                        break
                    break
                if not chunk:
                    break
            else:
                r, _, _ = select.select([fd], [], [], 0.2)
                if not r:
                    continue
                try:
                    chunk = os.read(fd, 4096)
                except OSError as exc:
                    if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                        continue
                    break
                if not chunk:
                    break
            if self._stderr_bytes < DEFAULT_MAX_STDERR:
                take = DEFAULT_MAX_STDERR - self._stderr_bytes
                self._stderr_chunks.append(chunk[:take])
                self._stderr_bytes += min(len(chunk), take)

    def _terminate_group(self) -> None:
        proc = self._proc
        pgid = self._pgid
        if pgid is not None:
            try:
                os.killpg(pgid, signal.SIGTERM)
            except OSError:
                pass
            deadline = time.monotonic() + 0.4
            while time.monotonic() < deadline:
                alive = False
                if proc is not None and proc.poll() is None:
                    alive = True
                else:
                    try:
                        os.killpg(pgid, 0)
                        alive = True
                    except OSError:
                        alive = False
                if not alive:
                    break
                time.sleep(0.05)
            try:
                os.killpg(pgid, signal.SIGKILL)
            except OSError:
                pass
        if proc is not None:
            if proc.poll() is None:
                try:
                    proc.kill()
                except OSError:
                    pass
            try:
                proc.wait(timeout=0.4)
            except subprocess.TimeoutExpired:
                pass

    def _shutdown(self) -> None:
        proc = self._proc
        if proc is None:
            return
        try:
            if proc.poll() is None and not self._invalid:
                try:
                    cap = min(self._timeout, SHUTDOWN_CLEANUP_CAP)
                    self.call("cleanup", {}, timeout=cap)
                except ProviderError:
                    self._invalid = True
        finally:
            self._terminate_group()
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
            if self._stderr_thread is not None:
                self._stderr_thread.join(timeout=0.4)
            self._proc = None

    def call(
        self,
        operation: str,
        payload: dict,
        timeout: Optional[float] = None,
    ) -> dict:
        if self._invalid:
            raise ProviderError("state", "provider client invalidated")
        if self._proc is None:
            raise ProviderError("state", "provider not started")
        if self._proc.poll() is not None:
            self._invalid = True
            raise ProviderError("crashed", "provider process exited prematurely")
        req_id = str(uuid.uuid4())
        request = {
            "protocol": PROTOCOL,
            "id": req_id,
            "operation": operation,
            "payload": payload,
        }
        line = json.dumps(request, separators=(",", ":"), allow_nan=False) + "\n"
        encoded = line.encode("utf-8")
        if len(encoded) > self._max_input:
            raise ProviderError("limit", "request exceeds input limit")
        budget = self._timeout if timeout is None else timeout
        deadline = time.monotonic() + budget
        try:
            self._write_all(encoded, deadline)
        except ProviderError:
            self._invalid = True
            raise
        try:
            raw = self._read_line(deadline)
        except ProviderError:
            self._invalid = True
            raise
        if raw is None:
            self._invalid = True
            raise ProviderError("timeout", f"no response within {budget}s")
        try:
            response = _parse_json_strict(raw.decode("utf-8"))
        except ProviderError:
            self._invalid = True
            raise
        except UnicodeDecodeError as exc:
            self._invalid = True
            raise ProviderError("malformed", f"invalid UTF-8: {exc}") from exc
        return self._validate_response(response, req_id, operation)

    def _write_all(self, data: bytes, deadline: float) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None:
            raise ProviderError("state", "provider not started")
        fd = proc.stdin.fileno()
        offset = 0
        while offset < len(data):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._terminate_group()
                raise ProviderError("timeout", "write timed out")
            if proc.poll() is not None:
                raise ProviderError("crashed", "provider process exited during write")
            _, writable, _ = select.select([], [fd], [], remaining)
            if not writable:
                self._terminate_group()
                raise ProviderError("timeout", "write timed out")
            try:
                written = os.write(fd, data[offset:])
            except BlockingIOError:
                continue
            except OSError as exc:
                raise ProviderError("io", f"write failed: {exc}") from exc
            if written == 0:
                raise ProviderError("io", "stdin closed")
            offset += written

    def _read_line(self, deadline: float) -> Optional[bytes]:
        proc = self._proc
        if proc is None or proc.stdout is None:
            return None
        fd = proc.stdout.fileno()
        buf = bytearray()
        while True:
            if len(buf) > self._max_output:
                self._terminate_group()
                raise ProviderError("limit", "response exceeds output limit")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._terminate_group()
                return None
            readable, _, _ = select.select([fd], [], [], remaining)
            if readable:
                try:
                    chunk = os.read(fd, min(4096, max(1, self._max_output - len(buf) + 1)))
                except BlockingIOError:
                    continue
                except OSError as exc:
                    raise ProviderError("io", f"read failed: {exc}") from exc
                if chunk == b"":
                    if not buf:
                        raise ProviderError("crashed", "provider process exited prematurely")
                    raise ProviderError("malformed", "incomplete response before EOF")
                buf.extend(chunk)
                if b"\n" in buf:
                    line, _rest = buf.split(b"\n", 1)
                    if len(line) > self._max_output:
                        self._terminate_group()
                        raise ProviderError("limit", "response exceeds output limit")
                    return bytes(line)
                continue
            if proc.poll() is not None:
                if not buf:
                    raise ProviderError("crashed", "provider process exited prematurely")
                raise ProviderError("malformed", "incomplete response before EOF")

    def _validate_response(self, response: Any, req_id: str, operation: str) -> dict:
        if not isinstance(response, dict):
            self._protocol_fail("malformed", "response must be object")
        if response.get("protocol") != PROTOCOL:
            self._protocol_fail("protocol", f"unexpected protocol: {response.get('protocol')}")
        if "id" not in response:
            self._protocol_fail("malformed", "response missing id")
        if response.get("id") != req_id:
            self._protocol_fail("id_mismatch", "response id does not match request")
        status = response.get("status")
        if status not in VALID_STATUSES:
            self._protocol_fail("malformed", f"unknown status: {status!r}")
        if status == "ok":
            result = response.get("result")
            if not isinstance(result, dict):
                self._protocol_fail("malformed", "ok response missing result object")
            self._validate_operation_result(operation, result)
            return result
        err = response.get("error")
        if not isinstance(err, dict):
            self._protocol_fail("malformed", "error response missing error object")
        code = err.get("code")
        message = err.get("message")
        if not isinstance(code, str) or not code:
            self._protocol_fail("malformed", "error.code must be non-empty string")
        if not isinstance(message, str):
            self._protocol_fail("malformed", "error.message must be string")
        if status == "unsupported":
            raise ProviderError(code, message, status="unsupported")
        raise ProviderError(code, message, status=status)

    def _validate_operation_result(self, operation: str, result: dict) -> None:
        if operation == "prepare":
            handle = result.get("handle")
            if not isinstance(handle, str) or not handle:
                self._protocol_fail("malformed", "prepare handle must be nonempty string")
        elif operation == "present":
            presentation = result.get("presentation")
            if not isinstance(presentation, str):
                self._protocol_fail("malformed", "present presentation must be string")
        elif operation == "verify":
            if type(result.get("verified")) is not bool:
                self._protocol_fail("malformed", "verified must be boolean")

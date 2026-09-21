#!/usr/bin/env python3
"""EPFL zkp-pocs native JSONL provider: d10_swiyu_jwt + c05_age_verification (nargo/bb, not OpenAC)."""
from __future__ import annotations

import base64
import binascii
import json
import re
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path

try:
    from fixtures import VARIANTS, write_prover_toml
except ImportError:
    VARIANTS = None
    write_prover_toml = None

PROTOCOL = "swiyu.provider.v1"
C05_PROFILE = "epfl-c05-age18-fixedcred-v0"
D10_PROFILE = "epfl-d10-swiyu-jwt-age25-v0"
C05_CIRCUIT = "c05_age_verification"
D10_CIRCUIT = "d10_swiyu_jwt"
SCHEME = "ultra_honk"
CREDENTIAL_LEN = 218
OPERATIONS = ["initialize", "prepare", "present", "verify", "cleanup"]
PUBLIC_FIELD_COUNT = 97

HANDLES: dict[str, dict] = {}
READY: dict[str, bool] = {}
LOCK = threading.Lock()
PROVIDER_DIR = Path(__file__).resolve().parent
OWNED_SCRATCH: set[Path] = set()
PRIVATE_SCRATCH_PREFIXES = ("present-c05-", "present-d10-", "verify-c05-", "verify-d10-")
NATIVE_DIAGNOSTICS = Path("/tmp/swiyu-epfl-20260915/owned/scratch/native-diagnostics")


PROOF_B64URL_RE = re.compile(r"\A[A-Za-z0-9_-]+\Z")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _proof_b64url_decode(data: str) -> bytes:
    if not isinstance(data, str) or not data or PROOF_B64URL_RE.fullmatch(data) is None:
        raise ValueError("invalid proof_b64")
    padded = data + "=" * (-len(data) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid proof_b64") from exc
    if _b64url(raw) != data:
        raise ValueError("noncanonical proof_b64")
    return raw


def _decode_b64(data: str) -> bytes:
    try:
        return _proof_b64url_decode(data)
    except ValueError:
        padded = data + "=" * (-len(data) % 4)
        return base64.b64decode(padded, validate=True)


def toolchain_bin() -> Path:
    override = os.environ.get("SWIYU_EPFL_TOOLCHAIN")
    if override:
        return Path(override)
    return Path("/tmp/swiyu-epfl-20260915/owned/scratch/toolchain/bin")


def circuit_root() -> Path:
    override = os.environ.get("SWIYU_EPFL_CIRCUIT_ROOT")
    if override:
        return Path(override)
    return PROVIDER_DIR / "circuit"


def work_root() -> Path:
    override = os.environ.get("SWIYU_EPFL_WORK_ROOT")
    if override:
        path = Path(override)
    else:
        path = Path(tempfile.gettempdir()) / "swiyu-epfl-native"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _is_owned_private_scratch(path: Path) -> bool:
    try:
        if path.is_symlink() or not path.is_dir():
            return False
    except OSError:
        return False
    if not path.name.startswith(PRIVATE_SCRATCH_PREFIXES):
        return False
    try:
        st = path.stat()
    except OSError:
        return False
    return stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid()


def harden_private_scratch(root: Path) -> None:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        try:
            os.chmod(dirpath, 0o700)
        except OSError:
            pass
        for name in filenames:
            file_path = Path(dirpath) / name
            if file_path.is_symlink():
                continue
            try:
                os.chmod(file_path, 0o600)
            except OSError:
                pass


def make_private_scratch(prefix: str) -> Path:
    if not prefix.startswith(PRIVATE_SCRATCH_PREFIXES):
        raise ValueError(f"refusing non-private prefix: {prefix}")
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=work_root()))
    path.chmod(0o700)
    harden_private_scratch(path)
    OWNED_SCRATCH.add(path)
    return path


def remove_owned_scratch(path: Path | None) -> None:
    if path is None:
        return
    if path in OWNED_SCRATCH or _is_owned_private_scratch(path):
        for dirpath, _dirnames, filenames in os.walk(path, topdown=False, followlinks=False):
            try:
                os.chmod(dirpath, 0o700)
            except OSError:
                pass
            for name in filenames:
                try:
                    os.chmod(Path(dirpath) / name, 0o700)
                except OSError:
                    pass
        shutil.rmtree(path, ignore_errors=True)
    OWNED_SCRATCH.discard(path)


def reclaim_abandoned_private_scratch(root: Path | None = None) -> list[str]:
    target = root or work_root()
    removed: list[str] = []
    try:
        children = list(target.iterdir())
    except OSError:
        return removed
    for child in children:
        if not _is_owned_private_scratch(child):
            continue
        shutil.rmtree(child, ignore_errors=True)
        OWNED_SCRATCH.discard(child)
        removed.append(child.name)
    return removed


@contextmanager
def private_run_dir(prefix: str):
    path = make_private_scratch(prefix)
    try:
        yield path
    finally:
        remove_owned_scratch(path)


def crs_dir() -> Path:
    override = os.environ.get("SWIYU_EPFL_CRS") or os.environ.get("BB_CRS")
    if override:
        return Path(override)
    return Path.home() / ".bb-crs"


def nargo_bin() -> Path:
    return toolchain_bin() / "nargo"


def bb_bin() -> Path:
    return toolchain_bin() / "bb"


def artifacts_available(circuit: str) -> bool:
    return (
        nargo_bin().is_file()
        and bb_bin().is_file()
        and (circuit_root() / circuit / "Nargo.toml").is_file()
    )


def reply(req_id: str, status: str, result=None, error=None) -> None:
    msg = {"protocol": PROTOCOL, "id": req_id, "status": status}
    if status == "ok":
        msg["result"] = result or {}
    else:
        msg["error"] = error or {"code": status, "message": status}
    sys.stdout.write(json.dumps(msg, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def preserve_nargo_diagnostics(prefix: str, executed: subprocess.CompletedProcess) -> str | None:
    diag = (executed.stderr or executed.stdout or "").strip()
    if not diag:
        return None
    NATIVE_DIAGNOSTICS.mkdir(parents=True, exist_ok=True)
    path = NATIVE_DIAGNOSTICS / f"{prefix}-{uuid.uuid4().hex}.stderr"
    path.write_text(diag[-8000:])
    path.chmod(0o600)
    for line in reversed(diag.splitlines()):
        if "Assertion failed" in line or "error:" in line:
            return line.strip()
    return diag.splitlines()[-1].strip() if diag.splitlines() else None


def run_cmd(argv: list[str], cwd: Path, timeout: float) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PATH"] = f"{toolchain_bin()}:{env.get('PATH', '')}"
    # bb 1.2.1 has no --threads flag; it still spawned 8 workers under RAYON=2 in d10 probe.
    env["HARDWARE_CONCURRENCY"] = env.get("HARDWARE_CONCURRENCY", "2")
    env["RAYON_NUM_THREADS"] = env.get("RAYON_NUM_THREADS", "2")
    env["OMP_NUM_THREADS"] = env.get("OMP_NUM_THREADS", "2")
    env["BB_NUM_CPUS"] = env.get("BB_NUM_CPUS", "2")
    return subprocess.run(
        argv,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        check=False,
    )


def compiled_dir(circuit: str) -> Path:
    return work_root() / "compiled" / circuit


def vk_path(circuit: str) -> Path:
    return work_root() / "vk" / circuit / "vk"


def bb_scheme_args() -> list[str]:
    args = ["--scheme", SCHEME]
    crs = crs_dir()
    if crs.is_dir():
        args.extend(["-c", str(crs)])
    return args


def ensure_compiled(circuit: str) -> None:
    if READY.get(circuit):
        return
    if not artifacts_available(circuit):
        raise RuntimeError("nargo/bb or circuit sources missing")
    dest = compiled_dir(circuit)
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(circuit_root(), dest.parent, dirs_exist_ok=True)
    circuit_dir = dest
    compile_result = run_cmd([str(nargo_bin()), "compile"], cwd=circuit_dir, timeout=180)
    if compile_result.returncode != 0:
        raise RuntimeError(compile_result.stderr or compile_result.stdout or "nargo compile failed")
    vk_dir = vk_path(circuit).parent
    vk_dir.mkdir(parents=True, exist_ok=True)
    bytecode = circuit_dir / "target" / f"{circuit}.json"
    vk_cmd = [str(bb_bin()), "write_vk", *bb_scheme_args(), "-b", str(bytecode), "-o", str(vk_dir)]
    vk = run_cmd(vk_cmd, cwd=circuit_dir, timeout=180)
    if vk.returncode != 0:
        raise RuntimeError(vk.stderr or vk.stdout or "bb write_vk failed")
    READY[circuit] = True


def native_status(circuit: str) -> dict:
    available = artifacts_available(circuit)
    status = "implemented" if available else "unavailable"
    reason = None if available else "TOOLCHAIN_OR_CIRCUIT_MISSING"
    return status, reason


def operation_readiness() -> dict:
    d10_status, d10_reason = native_status(D10_CIRCUIT)
    return {
        "initialize": {"status": "implemented"},
        "prepare": {
            "status": "implemented",
            "coverage": "d10-prover-toml-path-or-c05-fixed-credential",
        },
        "present": {
            "status": d10_status,
            "reason": d10_reason,
            "detail": "nargo execute + bb prove ultra_honk; d10 uses caller Prover.toml without nonce rotation",
        },
        "verify": {
            "status": d10_status,
            "reason": d10_reason,
            "detail": "bb verify with independently encoded public inputs and pinned VK",
        },
        "cleanup": {"status": "implemented"},
    }


def handle_initialize(req_id: str, _payload: dict) -> None:
    try:
        reclaim_abandoned_private_scratch()
        if artifacts_available(D10_CIRCUIT):
            ensure_compiled(D10_CIRCUIT)
        reply(req_id, "ok", {
            "profiles": [D10_PROFILE, C05_PROFILE],
            "operations": OPERATIONS,
            "operationReadiness": operation_readiness(),
            "artifacts": {
                "available": artifacts_available(D10_CIRCUIT) and READY.get(D10_CIRCUIT, False),
                "nargo": str(nargo_bin()) if nargo_bin().is_file() else None,
                "bb": str(bb_bin()) if bb_bin().is_file() else None,
                "circuit": D10_CIRCUIT,
                "scheme": SCHEME,
                "public_field_count": PUBLIC_FIELD_COUNT,
            },
            "limitations": [
                "d10_swiyu_jwt: issuer ES256 over JWT signing input, birth_date SD-JWT disclosure binding, age>=25 by YYYYMMDD (now_date >= birth + 250000), holder ECDSA over challenge_nonce",
                "d10 static Prover.toml path: challenge_nonce is not a fresh OID4VP nonce; present does not rotate holder signatures there",
                "dc+sd-jwt prepare/present rotates challenge_nonce and holder device_signature per request_context for transcript campaigns",
                "proof_b64 wire encoding is canonical unpadded base64url; verify accepts that form and legacy standard base64 envelopes",
                "verify uses caller issuer_pub_x/y, now_date, challenge_nonce; envelope public_inputs/VK are ignored",
                "bounded semantic claim swiyu.epfl.d10-age25-jwt.v0 is supported; not OpenAC and not swiyu-age18-status-2k",
                "Java JDK HTTP adapter + EPFL sidecar route OID4VP transcript campaigns; not full Spring dispatch, Android, or TLS",
                "c05_age_verification remains profile epfl-c05-age18-fixedcred-v0: hidden 218-byte credential_string, public unix current_date, age>=18, no issuer/session/nonce binding",
                "Android is out of scope / not run: no device or emulator measurement",
            ],
        })
    except Exception as exc:
        reply(req_id, "error", error={"code": "initialize_failed", "message": str(exc)})


def unsupported_profile(req_id: str, payload: dict) -> bool:
    profile = payload.get("profile")
    if profile in {D10_PROFILE, C05_PROFILE}:
        return False
    reply(req_id, "unsupported", error={
        "code": "unsupported_profile",
        "message": f"profile not supported: {profile}",
    })
    return True


def resolve_d10_prover_toml(payload: dict) -> Path:
    cred = payload.get("credential") or {}
    fmt = cred.get("format")
    if fmt not in {None, "epfl-d10-prover-toml"}:
        raise ValueError("expected format epfl-d10-prover-toml (local Prover.toml path; not a shipped JWT)")
    path_value = cred.get("path") or cred.get("data") or (payload.get("context") or {}).get("prover_toml")
    if not isinstance(path_value, str) or not path_value:
        raise ValueError("credential.path must be a local Prover.toml file")
    path = Path(path_value).expanduser().resolve()
    if not path.is_file() or path.name != "Prover.toml":
        raise ValueError("Prover.toml path not found")
    return path


def resolve_d10_variant(payload: dict):
    cred = payload.get("credential") or {}
    fmt = cred.get("format")
    if fmt == "dc+sd-jwt":
        data = cred.get("data")
        if not isinstance(data, str) or not data:
            raise ValueError("credential.data required for dc+sd-jwt")
        if VARIANTS is None:
            raise ValueError("fixtures module unavailable")
        for variant in VARIANTS.values():
            if variant.compact_sd_jwt == data:
                return variant
        raise ValueError("unknown dc+sd-jwt credential (not a registered EPFL test fixture)")
    variant_id = cred.get("variant")
    if isinstance(variant_id, str) and VARIANTS and variant_id in VARIANTS:
        return VARIANTS[variant_id]
    raise ValueError("expected dc+sd-jwt test fixture or variant id")


def handle_prepare(req_id: str, payload: dict) -> None:
    if unsupported_profile(req_id, payload):
        return
    profile = payload.get("profile")
    if profile == D10_PROFILE:
        cred = payload.get("credential") or {}
        fmt = cred.get("format")
        if fmt in {None, "epfl-d10-prover-toml"}:
            try:
                prover = resolve_d10_prover_toml(payload)
            except ValueError as exc:
                reply(req_id, "error", error={"code": "bad_credential", "message": str(exc)})
                return
            handle = str(uuid.uuid4())
            HANDLES[handle] = {"profile": D10_PROFILE, "prover_toml": str(prover), "mode": "static-prover"}
            reply(req_id, "ok", {"handle": handle})
            return
        if fmt in {"dc+sd-jwt", "epfl-variant"} or cred.get("variant"):
            try:
                variant = resolve_d10_variant(payload)
            except ValueError as exc:
                reply(req_id, "error", error={"code": "bad_credential", "message": str(exc)})
                return
            handle = str(uuid.uuid4())
            HANDLES[handle] = {"profile": D10_PROFILE, "variant_id": variant.variant_id, "mode": "synthetic-sd-jwt"}
            reply(req_id, "ok", {"handle": handle})
            return
        reply(req_id, "error", error={"code": "bad_credential", "message": "expected epfl-d10-prover-toml or dc+sd-jwt test fixture"})
        return
    cred = payload.get("credential") or {}
    if cred.get("format") != "epfl-fixed-credential":
        reply(req_id, "error", error={
            "code": "bad_credential",
            "message": "expected format epfl-fixed-credential (not dc+sd-jwt / OpenAC)",
        })
        return
    data = cred.get("data")
    if not isinstance(data, str) or len(data) != CREDENTIAL_LEN:
        reply(req_id, "error", error={
            "code": "bad_credential",
            "message": f"credential_string must be length {CREDENTIAL_LEN}",
        })
        return
    handle = str(uuid.uuid4())
    HANDLES[handle] = {"credential_string": data, "profile": C05_PROFILE}
    reply(req_id, "ok", {"handle": handle})


def parse_current_date(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("current_date must be a JSON integer unix timestamp")
    if value < 0:
        raise ValueError("current_date must be non-negative")
    return value


def parse_u8_32(value, name: str) -> list[int]:
    if isinstance(value, str):
        raw = bytes.fromhex(value) if len(value) == 64 else base64.b64decode(value)
        value = list(raw)
    if not isinstance(value, list) or len(value) != 32:
        raise ValueError(f"{name} must be 32 bytes")
    out = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int) or item < 0 or item > 255:
            raise ValueError(f"{name} must be u8 values")
        out.append(item)
    return out


def parse_now_date(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("now_date must be a JSON integer YYYYMMDD")
    if value < 0:
        raise ValueError("now_date must be non-negative")
    return value


def encode_c05_public_inputs(current_date: int) -> bytes:
    return current_date.to_bytes(32, "big")


def encode_d10_public_inputs(
    issuer_x: list[int], issuer_y: list[int], now_date: int, nonce: list[int]
) -> bytes:
    parts = [bytes(31) + bytes([b]) for b in issuer_x]
    parts += [bytes(31) + bytes([b]) for b in issuer_y]
    parts.append(now_date.to_bytes(32, "big"))
    parts += [bytes(31) + bytes([b]) for b in nonce]
    blob = b"".join(parts)
    if len(blob) != PUBLIC_FIELD_COUNT * 32:
        raise ValueError("public input encoding size mismatch")
    return blob


def d10_request_context(payload: dict) -> tuple[list[int], list[int], int, list[int]]:
    ctx = payload.get("request_context") or {}
    return (
        parse_u8_32(ctx.get("issuer_pub_x"), "issuer_pub_x"),
        parse_u8_32(ctx.get("issuer_pub_y"), "issuer_pub_y"),
        parse_now_date(ctx.get("now_date")),
        parse_u8_32(ctx.get("challenge_nonce"), "challenge_nonce"),
    )


def handle_present(req_id: str, payload: dict) -> None:
    if unsupported_profile(req_id, payload):
        return
    state = HANDLES.get(payload.get("handle"))
    if not state or state.get("profile") != payload.get("profile"):
        reply(req_id, "error", error={"code": "bad_handle", "message": "unknown handle"})
        return
    if payload.get("profile") == D10_PROFILE:
        present_d10(req_id, payload, state)
        return
    present_c05(req_id, payload, state)


def present_c05(req_id: str, payload: dict, state: dict) -> None:
    status, result, error = "error", None, {"code": "present_failed", "message": "present failed"}
    try:
        current_date = parse_current_date((payload.get("request_context") or {}).get("current_date"))
        with LOCK:
            ensure_compiled(C05_CIRCUIT)
            with private_run_dir("present-c05-") as run_dir:
                shutil.copytree(compiled_dir(C05_CIRCUIT).parent, run_dir, dirs_exist_ok=True)
                circuit_dir = run_dir / C05_CIRCUIT
                prover = circuit_dir / "Prover.toml"
                cred = state["credential_string"].replace("\\", "\\\\").replace('"', '\\"')
                prover.write_text(f'credential_string = "{cred}"\ncurrent_date = {current_date}\n')
                harden_private_scratch(run_dir)
                executed = run_cmd(
                    [str(nargo_bin()), "execute", "-p", "Prover.toml"],
                    cwd=circuit_dir,
                    timeout=120,
                )
                if executed.returncode != 0:
                    status = "error"
                    error = {
                        "code": "predicate_unsatisfied",
                        "message": "circuit witness failed (underage or malformed DOB)",
                    }
                else:
                    witness = circuit_dir / "target" / f"{C05_CIRCUIT}.gz"
                    bytecode = circuit_dir / "target" / f"{C05_CIRCUIT}.json"
                    proof_dir = run_dir / "proof"
                    proof_dir.mkdir()
                    vk = vk_path(C05_CIRCUIT)
                    proved = run_cmd(
                        [
                            str(bb_bin()), "prove", *bb_scheme_args(),
                            "-b", str(bytecode), "-w", str(witness), "-k", str(vk), "-o", str(proof_dir),
                        ],
                        cwd=circuit_dir,
                        timeout=180,
                    )
                    if proved.returncode != 0:
                        status = "error"
                        error = {
                            "code": "prove_failed",
                            "message": (proved.stderr or proved.stdout)[-500:],
                        }
                    else:
                        proof = (proof_dir / "proof").read_bytes()
                        public_inputs = (proof_dir / "public_inputs").read_bytes()
                        expected = encode_c05_public_inputs(current_date)
                        if public_inputs != expected:
                            status = "error"
                            error = {
                                "code": "public_input_mismatch",
                                "message": "prover public inputs did not match current_date encoding",
                            }
                        else:
                            witness_bytes = witness.stat().st_size
                            presentation = json.dumps({
                                "profile": C05_PROFILE,
                                "circuit": C05_CIRCUIT,
                                "scheme": SCHEME,
                                "current_date": current_date,
                                "proof_b64": _b64url(proof),
                                "public_inputs_b64": base64.b64encode(public_inputs).decode("ascii"),
                            }, separators=(",", ":"))
                            status = "ok"
                            result = {
                                "presentation": presentation,
                                "artifact_sizes": {
                                    "proof": len(proof),
                                    "witness": witness_bytes,
                                    "witness_encoding": "gzip",
                                },
                                "public_outputs": {"current_date": current_date, "min_age_years": 18},
                            }
    except ValueError as exc:
        status, error = "error", {"code": "bad_request", "message": str(exc)}
    except Exception as exc:
        status, error = "error", {"code": "present_failed", "message": str(exc)}
    if status == "ok":
        reply(req_id, "ok", result)
    else:
        reply(req_id, "error", error=error)


def present_d10(req_id: str, payload: dict, state: dict) -> None:
    status, result, error = "error", None, {"code": "present_failed", "message": "present failed"}
    try:
        issuer_x, issuer_y, now_date, nonce = d10_request_context(payload)
        with LOCK:
            ensure_compiled(D10_CIRCUIT)
            with private_run_dir("present-d10-") as run_dir:
                shutil.copytree(compiled_dir(D10_CIRCUIT).parent, run_dir, dirs_exist_ok=True)
                circuit_dir = run_dir / D10_CIRCUIT
                prover_path = circuit_dir / "Prover.toml"
                if state.get("mode") == "synthetic-sd-jwt":
                    if write_prover_toml is None or VARIANTS is None:
                        raise RuntimeError("fixtures module unavailable")
                    variant = VARIANTS[state["variant_id"]]
                    write_prover_toml(variant, nonce, prover_path)
                else:
                    shutil.copy2(state["prover_toml"], prover_path)
                harden_private_scratch(run_dir)
                executed = run_cmd(
                    [str(nargo_bin()), "execute", "-p", "Prover.toml"],
                    cwd=circuit_dir,
                    timeout=120,
                )
                if executed.returncode != 0:
                    detail = preserve_nargo_diagnostics("present-d10", executed)
                    status = "error"
                    error = {
                        "code": "predicate_unsatisfied",
                        "message": detail or "circuit witness failed (age, signatures, or Prover.toml)",
                    }
                else:
                    witness = circuit_dir / "target" / f"{D10_CIRCUIT}.gz"
                    bytecode = circuit_dir / "target" / f"{D10_CIRCUIT}.json"
                    proof_dir = run_dir / "proof"
                    proof_dir.mkdir()
                    vk = vk_path(D10_CIRCUIT)
                    proved = run_cmd(
                        [
                            str(bb_bin()), "prove", *bb_scheme_args(),
                            "-b", str(bytecode), "-w", str(witness), "-k", str(vk), "-o", str(proof_dir),
                        ],
                        cwd=circuit_dir,
                        timeout=180,
                    )
                    if proved.returncode != 0:
                        status = "error"
                        error = {
                            "code": "prove_failed",
                            "message": (proved.stderr or proved.stdout)[-500:],
                        }
                    else:
                        proof = (proof_dir / "proof").read_bytes()
                        public_inputs = (proof_dir / "public_inputs").read_bytes()
                        expected = encode_d10_public_inputs(issuer_x, issuer_y, now_date, nonce)
                        if public_inputs != expected:
                            status = "error"
                            error = {
                                "code": "public_input_mismatch",
                                "message": "prover public inputs did not match caller-encoded d10 fields; nonce was not rotated",
                            }
                        else:
                            witness_bytes = witness.stat().st_size
                            presentation_obj = {
                                "profile": D10_PROFILE,
                                "circuit": D10_CIRCUIT,
                                "scheme": SCHEME,
                                "proof_b64": _b64url(proof),
                            }
                            if state.get("mode") != "synthetic-sd-jwt":
                                presentation_obj["public_inputs_b64"] = base64.b64encode(public_inputs).decode("ascii")
                                presentation_obj["vk_b64"] = "untrusted-do-not-use"
                            presentation = json.dumps(presentation_obj, separators=(",", ":"))
                            status = "ok"
                            result = {
                                "presentation": presentation,
                                "artifact_sizes": {
                                    "proof": len(proof),
                                    "witness": witness_bytes,
                                    "witness_encoding": "gzip",
                                },
                                "public_outputs": {
                                    "now_date": now_date,
                                    "min_age_years": 25,
                                    "challenge_binding": (
                                        "fresh-request-context-nonce"
                                        if state.get("mode") == "synthetic-sd-jwt"
                                        else "static-prover-toml-nonce-not-oid4vp"
                                    ),
                                },
                            }
    except ValueError as exc:
        status, error = "error", {"code": "bad_request", "message": str(exc)}
    except Exception as exc:
        status, error = "error", {"code": "present_failed", "message": str(exc)}
    if status == "ok":
        reply(req_id, "ok", result)
    else:
        reply(req_id, "error", error=error)


def handle_verify(req_id: str, payload: dict) -> None:
    if unsupported_profile(req_id, payload):
        return
    if payload.get("profile") == D10_PROFILE:
        verify_d10(req_id, payload)
        return
    verify_c05(req_id, payload)


def verify_c05(req_id: str, payload: dict) -> None:
    try:
        current_date = parse_current_date((payload.get("request_context") or {}).get("current_date"))
        envelope = json.loads(payload.get("presentation") or "")
        proof = _decode_b64(envelope["proof_b64"])
        ensure_compiled(C05_CIRCUIT)
        ok = False
        with private_run_dir("verify-c05-") as verify_dir:
            proof_path = verify_dir / "proof"
            pi_path = verify_dir / "public_inputs"
            proof_path.write_bytes(proof)
            pi_path.write_bytes(encode_c05_public_inputs(current_date))
            harden_private_scratch(verify_dir)
            vk = vk_path(C05_CIRCUIT)
            verified_run = run_cmd(
                [str(bb_bin()), "verify", *bb_scheme_args(), "-p", str(proof_path), "-k", str(vk), "-i", str(pi_path)],
                cwd=verify_dir,
                timeout=60,
            )
            ok = verified_run.returncode == 0
        reply(req_id, "ok", {
            "verified": ok,
            "reason": None if ok else "proof_or_public_input_rejected",
        })
    except Exception as exc:
        reply(req_id, "error", error={"code": "bad_presentation", "message": str(exc)})


def verify_d10(req_id: str, payload: dict) -> None:
    try:
        issuer_x, issuer_y, now_date, nonce = d10_request_context(payload)
        envelope = json.loads(payload.get("presentation") or "")
        proof = _decode_b64(envelope["proof_b64"])
        ensure_compiled(D10_CIRCUIT)
        ok = False
        vk = vk_path(D10_CIRCUIT)
        with private_run_dir("verify-d10-") as verify_dir:
            proof_path = verify_dir / "proof"
            pi_path = verify_dir / "public_inputs"
            proof_path.write_bytes(proof)
            pi_path.write_bytes(encode_d10_public_inputs(issuer_x, issuer_y, now_date, nonce))
            harden_private_scratch(verify_dir)
            if not vk.is_file():
                raise RuntimeError("trusted verification key missing")
            verified_run = run_cmd(
                [str(bb_bin()), "verify", *bb_scheme_args(), "-p", str(proof_path), "-k", str(vk), "-i", str(pi_path)],
                cwd=verify_dir,
                timeout=60,
            )
            ok = verified_run.returncode == 0
        reply(req_id, "ok", {
            "verified": ok,
            "reason": None if ok else "proof_or_public_input_rejected",
            "trusted_vk": str(vk),
            "ignored_envelope_fields": ["public_inputs_b64", "vk_b64"],
        })
    except Exception as exc:
        reply(req_id, "error", error={"code": "bad_presentation", "message": str(exc)})


def handle_cleanup(req_id: str, _payload: dict) -> None:
    HANDLES.clear()
    for path in list(OWNED_SCRATCH):
        remove_owned_scratch(path)
    reclaim_abandoned_private_scratch()
    reply(req_id, "ok", {})


def main() -> None:
    handlers = {
        "initialize": handle_initialize,
        "prepare": handle_prepare,
        "present": handle_present,
        "verify": handle_verify,
        "cleanup": handle_cleanup,
    }
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        if req.get("protocol") != PROTOCOL:
            continue
        op = req.get("operation")
        fn = handlers.get(op)
        rid = req.get("id", "")
        if fn is None:
            reply(rid, "unsupported", error={"code": "unknown_operation", "message": op})
        else:
            fn(rid, req.get("payload") or {})


if __name__ == "__main__":
    main()

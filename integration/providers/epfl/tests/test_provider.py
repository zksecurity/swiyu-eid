"""EPFL native provider tests: c05 + d10 UltraHonk (not OpenAC, not OID4VP)."""
from __future__ import annotations

import base64
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

PROVIDER_DIR = Path(__file__).resolve().parents[1]
PYTHON = PROVIDER_DIR.parents[1] / "semantics" / ".venv" / "bin" / "python"
PROTOCOL = "swiyu.provider.v1"
C05_PROFILE = "epfl-c05-age18-fixedcred-v0"
D10_PROFILE = "epfl-d10-swiyu-jwt-age25-v0"
SYNTHETIC = Path("/tmp/swiyu-epfl-20260915/owned/scratch/c05-work/synthetic.json")
TOOLCHAIN = Path("/tmp/swiyu-epfl-20260915/owned/scratch/toolchain/bin")
SCRATCH_PROVER = Path("/tmp/swiyu-epfl-20260915/d10/circuit/Prover.toml")


def _scratch_leftovers(root: str) -> list[str]:
    return sorted(
        p.name
        for p in Path(root).iterdir()
        if p.is_dir() and (p.name.startswith("present-") or p.name.startswith("verify-"))
    )


def _load_provider():
    spec = importlib.util.spec_from_file_location("epfl_native_provider", PROVIDER_DIR / "provider.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class ProofCodecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_provider()

    def test_proof_b64url_roundtrip_and_rejects_malformed(self) -> None:
        raw = b"ultrahonk-proof-bytes-sample"
        encoded = self.mod._b64url(raw)
        self.assertEqual(self.mod._proof_b64url_decode(encoded), raw)
        self.assertNotIn("=", encoded)
        self.assertNotRegex(encoded, r"[+/]")
        with self.assertRaises(ValueError):
            self.mod._proof_b64url_decode(base64.b64encode(raw).decode("ascii"))
        with self.assertRaises(ValueError):
            self.mod._proof_b64url_decode(encoded + "=")
        with self.assertRaises(ValueError):
            self.mod._proof_b64url_decode("")

    def test_decode_b64_accepts_legacy_standard_base64(self) -> None:
        raw = b"legacy-envelope-proof"
        legacy = base64.b64encode(raw).decode("ascii")
        self.assertEqual(self.mod._decode_b64(legacy), raw)


def _have_toolchain() -> bool:
    return (TOOLCHAIN / "nargo").is_file() and (TOOLCHAIN / "bb").is_file()


def _d10_prover() -> Path | None:
    env = os.environ.get("SWIYU_EPFL_D10_PROVER_TOML")
    if env and Path(env).is_file():
        return Path(env)
    root = os.environ.get("SWIYU_EPFL_SOURCE_ROOT")
    if root:
        candidate = Path(root) / "noir/d10_swiyu_jwt/Prover.toml"
        if candidate.is_file():
            return candidate
    if SCRATCH_PROVER.is_file():
        return SCRATCH_PROVER
    return None


def _parse_u8_array(src: str, key: str) -> list[int]:
    match = re.search(rf"^{key} = \[([^\]]+)\]", src, re.M)
    if not match:
        raise ValueError(key)
    vals = [int(part.strip()) for part in match.group(1).split(",")]
    if len(vals) != 32:
        raise ValueError(key)
    return vals


def _d10_public(prover: Path) -> dict:
    src = prover.read_text()
    now = re.search(r"^now_date = (\d+)", src, re.M)
    if not now:
        raise ValueError("now_date")
    return {
        "issuer_pub_x": _parse_u8_array(src, "issuer_pub_x"),
        "issuer_pub_y": _parse_u8_array(src, "issuer_pub_y"),
        "now_date": int(now.group(1)),
        "challenge_nonce": _parse_u8_array(src, "challenge_nonce"),
    }


class ProviderProcess:
    def __init__(self) -> None:
        env = os.environ.copy()
        env["PATH"] = f"{TOOLCHAIN}:{env.get('PATH', '')}"
        env["HARDWARE_CONCURRENCY"] = "2"
        env["RAYON_NUM_THREADS"] = "2"
        env["OMP_NUM_THREADS"] = "2"
        env["BB_NUM_CPUS"] = "2"
        env["SWIYU_EPFL_TOOLCHAIN"] = str(TOOLCHAIN)
        env["SWIYU_EPFL_CIRCUIT_ROOT"] = str(PROVIDER_DIR / "circuit")
        env["SWIYU_EPFL_WORK_ROOT"] = tempfile.mkdtemp(prefix="epfl-provider-work-")
        self.work_root = env["SWIYU_EPFL_WORK_ROOT"]
        self.proc = subprocess.Popen(
            [str(PYTHON), "provider.py"],
            cwd=PROVIDER_DIR,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )

    def call(self, operation: str, payload: dict, req_id: str | None = None) -> dict:
        assert self.proc.stdin and self.proc.stdout
        rid = req_id or str(uuid.uuid4())
        self.proc.stdin.write(
            json.dumps({"protocol": PROTOCOL, "id": rid, "operation": operation, "payload": payload})
            + "\n"
        )
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            err = self.proc.stderr.read() if self.proc.stderr else ""
            raise RuntimeError(f"provider closed: {err}")
        msg = json.loads(line)
        if msg.get("id") != rid:
            raise RuntimeError(f"id mismatch {rid} vs {msg.get('id')}")
        return msg

    def close(self) -> None:
        try:
            self.call("cleanup", {})
        except Exception:
            pass
        if self.proc.stdin:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        shutil.rmtree(self.work_root, ignore_errors=True)


@unittest.skipUnless(_have_toolchain() and SYNTHETIC.is_file(), "native nargo/bb and synthetic fixture required")
class EpflC05ProviderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.synth = json.loads(SYNTHETIC.read_text())
        cls.client = ProviderProcess()
        init = cls.client.call("initialize", {})
        if init.get("status") != "ok":
            raise RuntimeError(f"initialize failed: {init}")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()

    def test_initialize_advertises_native_c05_without_session_binding(self) -> None:
        msg = self.client.call("initialize", {})
        self.assertEqual(msg["status"], "ok")
        result = msg["result"]
        self.assertIn(C05_PROFILE, result["profiles"])
        self.assertEqual(result["operations"], ["initialize", "prepare", "present", "verify", "cleanup"])
        self.assertEqual(result["operationReadiness"]["present"]["status"], "implemented")
        limitations = " ".join(result.get("limitations", [])).lower()
        self.assertIn("session", limitations)
        self.assertIn("android", limitations)
        self.assertIn("not run", limitations)
        self.assertNotIn("oid4vp", [p.lower() for p in result["profiles"]])

    def test_native_roundtrip_accepts_adult_fixed_credential(self) -> None:
        prep = self.client.call("prepare", {
            "profile": C05_PROFILE,
            "credential": {"format": "epfl-fixed-credential", "data": self.synth["adult_credential_string"]},
            "context": {},
        })
        self.assertEqual(prep["status"], "ok", prep)
        handle = prep["result"]["handle"]
        present = self.client.call("present", {
            "profile": C05_PROFILE,
            "handle": handle,
            "request_context": {"current_date": self.synth["current_date"]},
            "inputs": {},
        })
        self.assertEqual(present["status"], "ok", present)
        sizes = present["result"]["artifact_sizes"]
        self.assertGreater(sizes["proof"], 1000)
        self.assertGreater(sizes["witness"], 100)
        verify = self.client.call("verify", {
            "profile": C05_PROFILE,
            "presentation": present["result"]["presentation"],
            "request_context": {"current_date": self.synth["current_date"]},
            "inputs": {},
        })
        self.assertEqual(verify["status"], "ok", verify)
        self.assertIs(verify["result"]["verified"], True)
        leftovers = _scratch_leftovers(self.client.work_root)
        self.assertEqual(leftovers, [])
        self.assertTrue((Path(self.client.work_root) / "compiled").exists())
        self.assertTrue((Path(self.client.work_root) / "vk").exists())

    def test_tampered_proof_is_rejected(self) -> None:
        prep = self.client.call("prepare", {
            "profile": C05_PROFILE,
            "credential": {"format": "epfl-fixed-credential", "data": self.synth["adult_credential_string"]},
        })
        present = self.client.call("present", {
            "profile": C05_PROFILE,
            "handle": prep["result"]["handle"],
            "request_context": {"current_date": self.synth["current_date"]},
        })
        envelope = json.loads(present["result"]["presentation"])
        proof = bytearray(_load_provider()._proof_b64url_decode(envelope["proof_b64"]))
        proof[80] ^= 0x01
        envelope["proof_b64"] = _b64url(bytes(proof))
        verify = self.client.call("verify", {
            "profile": C05_PROFILE,
            "presentation": json.dumps(envelope, separators=(",", ":")),
            "request_context": {"current_date": self.synth["current_date"]},
        })
        self.assertEqual(verify["status"], "ok", verify)
        self.assertIs(verify["result"]["verified"], False)

    def test_wrong_public_current_date_is_rejected(self) -> None:
        prep = self.client.call("prepare", {
            "profile": C05_PROFILE,
            "credential": {"format": "epfl-fixed-credential", "data": self.synth["adult_credential_string"]},
        })
        present = self.client.call("present", {
            "profile": C05_PROFILE,
            "handle": prep["result"]["handle"],
            "request_context": {"current_date": self.synth["current_date"]},
        })
        verify = self.client.call("verify", {
            "profile": C05_PROFILE,
            "presentation": present["result"]["presentation"],
            "request_context": {"current_date": int(self.synth["current_date"]) + 1},
        })
        self.assertEqual(verify["status"], "ok", verify)
        self.assertIs(verify["result"]["verified"], False)

    def test_underage_credential_cannot_present(self) -> None:
        prep = self.client.call("prepare", {
            "profile": C05_PROFILE,
            "credential": {"format": "epfl-fixed-credential", "data": self.synth["underage_credential_string"]},
        })
        present = self.client.call("present", {
            "profile": C05_PROFILE,
            "handle": prep["result"]["handle"],
            "request_context": {"current_date": self.synth["current_date"]},
        })
        self.assertEqual(present["status"], "error")
        self.assertEqual(present["error"]["code"], "predicate_unsatisfied")
        self.assertEqual(_scratch_leftovers(self.client.work_root), [])

    def test_unsupported_profile_and_bad_handle(self) -> None:
        prep = self.client.call("prepare", {"profile": "swiyu-age18-status-2k-v0", "credential": {}})
        self.assertEqual(prep["status"], "unsupported")
        present = self.client.call("present", {
            "profile": C05_PROFILE,
            "handle": "missing",
            "request_context": {"current_date": self.synth["current_date"]},
        })
        self.assertEqual(present["status"], "error")
        self.assertEqual(present["error"]["code"], "bad_handle")

    def test_sd_jwt_credential_is_rejected_not_relabeled(self) -> None:
        prep = self.client.call("prepare", {
            "profile": C05_PROFILE,
            "credential": {"format": "dc+sd-jwt", "data": "e30"},
        })
        self.assertEqual(prep["status"], "error")
        self.assertEqual(prep["error"]["code"], "bad_credential")


@unittest.skipUnless(_have_toolchain() and _d10_prover() is not None, "native nargo/bb and local d10 Prover.toml required")
class EpflD10ProviderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.prover = _d10_prover()
        cls.ctx = _d10_public(cls.prover)
        cls.client = ProviderProcess()
        init = cls.client.call("initialize", {})
        if init.get("status") != "ok":
            raise RuntimeError(f"initialize failed: {init}")
        prep = cls.client.call("prepare", {
            "profile": D10_PROFILE,
            "credential": {"format": "epfl-d10-prover-toml", "path": str(cls.prover)},
        })
        if prep.get("status") != "ok":
            raise RuntimeError(prep)
        present = cls.client.call("present", {
            "profile": D10_PROFILE,
            "handle": prep["result"]["handle"],
            "request_context": cls.ctx,
        })
        if present.get("status") != "ok":
            raise RuntimeError(present)
        cls.present = present
        cls.presentation = present["result"]["presentation"]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()

    def test_initialize_advertises_d10_and_does_not_claim_oid4vp(self) -> None:
        msg = self.client.call("initialize", {})
        self.assertEqual(msg["status"], "ok")
        result = msg["result"]
        self.assertEqual(result["profiles"][0], D10_PROFILE)
        self.assertIn(C05_PROFILE, result["profiles"])
        text = " ".join(result.get("limitations", [])).lower()
        self.assertIn("not a fresh oid4vp", text)
        self.assertIn("swiyu.epfl.d10-age25-jwt.v0", text)
        self.assertIn("base64url", text)
        self.assertIn("android", text)
        self.assertIn("not run", text)

    def test_native_roundtrip_accepts_local_prover_toml(self) -> None:
        sizes = self.present["result"]["artifact_sizes"]
        envelope = json.loads(self.presentation)
        encoded = envelope["proof_b64"]
        self.assertNotIn("=", encoded)
        self.assertNotRegex(encoded, r"[+/]")
        self.assertEqual(len(_load_provider()._proof_b64url_decode(encoded)), sizes["proof"])
        self.assertEqual(sizes["proof"], 16224)
        self.assertGreater(sizes["witness"], 300000)
        self.assertEqual(sizes.get("witness_encoding"), "gzip")
        verify = self.client.call("verify", {
            "profile": D10_PROFILE,
            "presentation": self.presentation,
            "request_context": self.ctx,
        })
        self.assertEqual(verify["status"], "ok", verify)
        self.assertIs(verify["result"]["verified"], True)
        self.assertEqual(_scratch_leftovers(self.client.work_root), [])
        self.assertTrue(self.prover.is_file())
        self.assertTrue((Path(self.client.work_root) / "compiled" / "d10_swiyu_jwt").exists())
        self.assertTrue((Path(self.client.work_root) / "vk" / "d10_swiyu_jwt" / "vk").is_file())

    def test_tampered_proof_is_rejected(self) -> None:
        envelope = json.loads(self.presentation)
        proof = bytearray(_load_provider()._proof_b64url_decode(envelope["proof_b64"]))
        proof[80] ^= 0x01
        envelope["proof_b64"] = _b64url(bytes(proof))
        verify = self.client.call("verify", {
            "profile": D10_PROFILE,
            "presentation": json.dumps(envelope, separators=(",", ":")),
            "request_context": self.ctx,
        })
        self.assertEqual(verify["status"], "ok", verify)
        self.assertIs(verify["result"]["verified"], False)

    def test_wrong_nonce_issuer_and_date_are_rejected(self) -> None:
        nonce = list(self.ctx["challenge_nonce"])
        nonce[0] = (nonce[0] + 1) % 256
        issuer = list(self.ctx["issuer_pub_x"])
        issuer[0] = (issuer[0] + 1) % 256
        cases = [
            {**self.ctx, "challenge_nonce": nonce},
            {**self.ctx, "issuer_pub_x": issuer},
            {**self.ctx, "now_date": self.ctx["now_date"] + 1},
        ]
        for ctx in cases:
            verify = self.client.call("verify", {
                "profile": D10_PROFILE,
                "presentation": self.presentation,
                "request_context": ctx,
            })
            self.assertEqual(verify["status"], "ok", verify)
            self.assertIs(verify["result"]["verified"], False, ctx)

    def test_envelope_public_input_and_vk_substitution_is_ignored(self) -> None:
        envelope = json.loads(self.presentation)
        envelope["public_inputs_b64"] = base64.b64encode(b"\x00" * 3104).decode()
        envelope["vk_b64"] = base64.b64encode(b"not-a-real-vk").decode()
        honest = self.client.call("verify", {
            "profile": D10_PROFILE,
            "presentation": json.dumps(envelope, separators=(",", ":")),
            "request_context": self.ctx,
        })
        self.assertEqual(honest["status"], "ok", honest)
        self.assertIs(honest["result"]["verified"], True)
        proof = bytearray(_load_provider()._proof_b64url_decode(envelope["proof_b64"]))
        proof[90] ^= 0xFF
        envelope["proof_b64"] = _b64url(bytes(proof))
        malicious = self.client.call("verify", {
            "profile": D10_PROFILE,
            "presentation": json.dumps(envelope, separators=(",", ":")),
            "request_context": self.ctx,
        })
        self.assertEqual(malicious["status"], "ok", malicious)
        self.assertIs(malicious["result"]["verified"], False)

    def test_lifecycle_and_unsupported_inputs(self) -> None:
        bad_sdjwt = self.client.call("prepare", {
            "profile": D10_PROFILE,
            "credential": {"format": "dc+sd-jwt", "data": "e30"},
        })
        self.assertEqual(bad_sdjwt["status"], "error")
        self.assertEqual(bad_sdjwt["error"]["code"], "bad_credential")
        missing = self.client.call("present", {
            "profile": D10_PROFILE,
            "handle": "missing",
            "request_context": self.ctx,
        })
        self.assertEqual(missing["status"], "error")
        self.assertEqual(missing["error"]["code"], "bad_handle")
        c05_on_d10 = self.client.call("prepare", {
            "profile": D10_PROFILE,
            "credential": {"format": "epfl-fixed-credential", "data": "x" * 218},
        })
        self.assertEqual(c05_on_d10["status"], "error")
        unknown = self.client.call("verify", {"profile": "swiyu-age18-status-2k-v0", "presentation": "{}"})
        self.assertEqual(unknown["status"], "unsupported")
        cleanup = self.client.call("cleanup", {})
        self.assertEqual(cleanup["status"], "ok")
        after = self.client.call("present", {
            "profile": D10_PROFILE,
            "handle": "gone",
            "request_context": self.ctx,
        })
        self.assertEqual(after["status"], "error")
        self.assertEqual(_scratch_leftovers(self.client.work_root), [])
        self.assertTrue((Path(self.client.work_root) / "compiled").exists())
        self.assertTrue((Path(self.client.work_root) / "vk").exists())


class EpflOwnedScratchCleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.prev = os.environ.get("SWIYU_EPFL_WORK_ROOT")
        self.root = Path(tempfile.mkdtemp(prefix="epfl-cleanup-unit-"))
        os.environ["SWIYU_EPFL_WORK_ROOT"] = str(self.root)
        self.provider = _load_provider()

    def tearDown(self) -> None:
        if self.prev is None:
            os.environ.pop("SWIYU_EPFL_WORK_ROOT", None)
        else:
            os.environ["SWIYU_EPFL_WORK_ROOT"] = self.prev
        shutil.rmtree(self.root, ignore_errors=True)

    def test_private_scratch_is_0700_files_0600_and_removed_on_success(self) -> None:
        compiled = self.root / "compiled"
        compiled.mkdir()
        (compiled / "keep").write_text("public-cache")
        caller = Path(tempfile.mkdtemp(prefix="epfl-caller-")) / "Prover.toml"
        caller.write_text("secret-not-for-workroot")
        with self.provider.private_run_dir("present-d10-") as run_dir:
            shutil.copy2(caller, run_dir / "Prover.toml")
            self.provider.harden_private_scratch(run_dir)
            st_dir = run_dir.stat()
            self.assertEqual(stat.S_IMODE(st_dir.st_mode), 0o700)
            st_file = (run_dir / "Prover.toml").stat()
            self.assertEqual(stat.S_IMODE(st_file.st_mode), 0o600)
            marker = run_dir
        self.assertFalse(marker.exists())
        self.assertTrue(caller.is_file())
        self.assertTrue((compiled / "keep").is_file())
        shutil.rmtree(caller.parent, ignore_errors=True)

    def test_cleanup_reclaims_owned_present_verify_scratch_only(self) -> None:
        abandoned = self.root / "present-d10-abandoned"
        abandoned.mkdir()
        (abandoned / "Prover.toml").write_text("private-copy")
        foreign = self.root / "unrelated-keep"
        foreign.mkdir()
        (foreign / "file").write_text("stay")
        cache = self.root / "vk"
        cache.mkdir()
        (cache / "vk").write_text("public")
        removed = self.provider.reclaim_abandoned_private_scratch(self.root)
        self.assertIn("present-d10-abandoned", removed)
        self.assertFalse(abandoned.exists())
        self.assertTrue((foreign / "file").is_file())
        self.assertTrue((cache / "vk").is_file())


if __name__ == "__main__":
    unittest.main()

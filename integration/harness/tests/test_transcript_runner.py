"""Behavioral tests for the reusable OID4VP transcript campaign driver."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from urllib.parse import parse_qs, unquote_plus

HARNESS = Path(__file__).resolve().parents[1]
SEMANTICS = Path(__file__).resolve().parents[2] / "semantics"
PROVIDERS = Path(__file__).resolve().parents[2] / "providers"
RUNTIME = Path(__file__).resolve().parents[2] / "runtime"
for path in (str(HARNESS), str(SEMANTICS), str(RUNTIME)):
    if path not in sys.path:
        sys.path.insert(0, path)

from semantics.support import SupportError

from transcript.fixture_verifier import FixtureVerifier
from transcript_runner import run_transcript_campaign

CLEARANCE = SEMANTICS / "claims" / "clearance-status.json"
REFERENCE_SUPPORT = PROVIDERS / "semantic-reference" / "support.json"
OPENAC_CLAIM = SEMANTICS / "claims" / "openac-age18-status-2k.json"
OPENAC_SUPPORT = PROVIDERS / "openac" / "support.json"
OPENAC_MANIFEST = PROVIDERS / "openac" / "manifest.json"
OPENAC_FIXTURE = PROVIDERS / "openac" / "transcript-fixture.mjs"

FACTORY = r'''
import json, sys
from copy import deepcopy
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from semantics.claims import load_claim
from semantics.fixtures import make_fixture

claim = load_claim(sys.argv[2])
a = make_fixture(claim, seed=1)
b = make_fixture(claim, seed=1, attributes={"clearance": "synthetic-other"})
b["given"]["issuer"] = deepcopy(a["given"]["issuer"])
qid = a["given"]["session"]["query_id"]
doc = {
  "schema": "swiyu.transcript-fixture.v1",
  "equivalence": "not_claimed",
  "mapping": {
    "credential_path": ["credential", "data"],
    "query_id": qid,
    "challenge_fields": {"nonce": "nonce", "clientId": "client_id", "responseUri": "response_uri", "state": "state"},
    "vp_token_format": "application/x-www-form-urlencoded",
  },
  "proof_path": "/proof",
  "dcql_query": {"credentials": [{"id": qid, "format": "dc+sd-jwt"}]},
  "variants": [
    {
      "id": "hidden-a",
      "credential": {"format": "dc+sd-jwt", "data": a["fixture"]["credential"]},
      "given": a["given"],
      "prepare": {"profile": "test", "credential": {"format": "dc+sd-jwt", "data": a["fixture"]["credential"]}, "context": {}},
      "present": {"profile": "test", "request_context": {"profile": "test", "queryId": qid, "cutoffDate": "2000-01-01", "currentTime": "1", "statusListSnapshot": "snap"}, "inputs": {}},
      "verify": {"inputs": {}},
    },
    {
      "id": "hidden-b",
      "credential": {"format": "dc+sd-jwt", "data": b["fixture"]["credential"]},
      "given": b["given"],
      "prepare": {"profile": "test", "credential": {"format": "dc+sd-jwt", "data": b["fixture"]["credential"]}, "context": {}},
      "present": {"profile": "test", "request_context": {"profile": "test", "queryId": qid, "cutoffDate": "2000-01-01", "currentTime": "1", "statusListSnapshot": "snap"}, "inputs": {}},
      "verify": {"inputs": {}},
    },
  ],
}
print(json.dumps(doc))
'''


def _write_manifest(directory: Path) -> Path:
    factory = directory / "transcript-fixture.py"
    factory.write_text(FACTORY, encoding="utf-8")
    stub = directory / "provider.py"
    stub.write_text(
        "import json,sys\n"
        "for line in sys.stdin:\n"
        " r=json.loads(line)\n"
        " print(json.dumps({'protocol':r['protocol'],'id':r['id'],'status':'ok','result':{}}),flush=True)\n",
        encoding="utf-8",
    )
    manifest = directory / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "swiyu.provider-manifest.v1",
                "id": "transcript-test",
                "title": "Transcript test provider",
                "kind": "test-only",
                "profiles": ["swiyu.semantic-reference.v0"],
                "command": [sys.executable, "provider.py"],
                "source": {"transcript_fixture": "transcript-fixture.py"},
            }
        ),
        encoding="utf-8",
    )
    return manifest


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class FakeProviderClient:
    """Test double at the ProviderClient boundary. Does not stub the engine."""

    def __init__(self, _manifest_path: str, **_kwargs):
        self.challenges: list[dict] = []
        self.prepares: list[dict] = []
        self._n = 0

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return None

    def call(self, operation: str, payload: dict):
        if operation == "initialize":
            return {"profiles": ["test"]}
        if operation == "prepare":
            self.prepares.append(deepcopy(payload))
            self._n += 1
            return {"handle": f"handle-{self._n}"}
        if operation == "present":
            self.challenges.append(deepcopy(payload.get("request_context") or {}))
            proof = _b64url(os.urandom(315_967))
            envelope = json.dumps({"proof": proof, "lookup": {"issuer": "did:example:issuer"}}, separators=(",", ":"))
            return {
                "presentation": _b64url(envelope.encode("utf-8")),
                "artifact_sizes": {"witness": 208_666_624, "proof": 315_967},
            }
        if operation == "cleanup":
            return {}
        raise AssertionError(f"unexpected operation {operation}")


class TranscriptRunnerTests(unittest.TestCase):
    def test_proof_size_is_measured_and_false_claimed_size_is_rejected(self):
        from transcript_runner import _artifact_sizes
        presentation = json.dumps({'proof': _b64url(b'actual-proof')})
        self.assertEqual(_artifact_sizes({'presentation': presentation}), (12, None))
        with self.assertRaises(RuntimeError):
            _artifact_sizes({'presentation': presentation, 'artifact_sizes': {'proof': 123, 'witness': 200}})

    def test_proof_b64_standard_base64_is_rejected(self):
        import base64
        from transcript_runner import _artifact_sizes

        proof = b"epfl-ultrahonk-proof-bytes"
        presentation = json.dumps({"proof_b64": base64.b64encode(proof).decode("ascii")})
        with self.assertRaises(RuntimeError):
            _artifact_sizes({"presentation": presentation}, proof_path="/proof_b64")

    def test_proof_b64_canonical_base64url_roundtrip_and_rejects_malformed(self):
        from transcript_equivalence import _b64url_decode_canonical
        from transcript_runner import _artifact_sizes, _decode_proof_leaf

        proof = b"epfl-ultrahonk-proof-bytes"
        encoded = _b64url(proof)
        presentation = json.dumps({"proof_b64": encoded})
        self.assertEqual(
            _artifact_sizes({"presentation": presentation}, proof_path="/proof_b64"),
            (len(proof), None),
        )
        self.assertEqual(_decode_proof_leaf(encoded), proof)
        self.assertIsNone(_decode_proof_leaf(base64.b64encode(proof).decode("ascii")))
        self.assertIsNone(_decode_proof_leaf(encoded + "="))
        self.assertIsNone(_decode_proof_leaf(""))
        self.assertIsNone(_b64url_decode_canonical("bad+chars"))

    def test_real_engine_fixture_mode_clean_pair_and_injected_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "out"
            code, bundle = run_transcript_campaign(
                str(OPENAC_MANIFEST),
                str(OPENAC_CLAIM),
                str(output),
                support_path=str(OPENAC_SUPPORT),
                fixture_only=True,
                injections=["hidden_field", "hash_header"],
            )
            self.assertEqual(code, 0, bundle["campaigns"])
            self.assertFalse(bundle["evidence_usable"])
            self.assertEqual(bundle["mode"], "fixture-only")
            self.assertIn("never used as evidence", bundle["qualification"].lower())
            kinds = {c["kind"]: c["report"] for c in bundle["campaigns"]}
            self.assertEqual(kinds["baseline"]["status"], "clean", kinds["baseline"])
            self.assertEqual(kinds["injected regression"]["status"], "findings", kinds["injected regression"])
            compared = [p for p in kinds["baseline"]["pairs"] if p.get("eligibility") == "compared"]
            self.assertGreaterEqual(len(compared), 1)
            self.assertTrue(all(p.get("status") == "equivalent" for p in compared), compared)
            sessions = bundle["sessions"]
            self.assertGreaterEqual(len(sessions), 4)
            for session in sessions:
                self.assertEqual(
                    [event["boundary"] for event in session["events"]],
                    [
                        "verifier:management_create",
                        "verifier:request_object",
                        "wallet->verifier:direct_post",
                        "verifier:management_result",
                    ],
                )
                self.assertIs(session["accepted"], True)
                self.assertEqual(set(session["fresh"]), {"nonce", "state"})
                session["given"]["session"]
                self.assertNotIn("{request_id}", session["given"]["session"].get("response_uri", ""))
                self.assertIsNone(session.get("proof_reuse"))
                create = json.loads(session["events"][0]["request"]["body"])
                self.assertIn("dcql_query", create)
                post = session["events"][2]
                form = parse_qs(post["request"]["body"], keep_blank_values=True)
                self.assertIn("vp_token", form)
                self.assertIn("state", form)
            injected = [s for s in sessions if s["campaign"] == "injected"]
            cred = injected[0]["credential"]
            form = parse_qs(injected[0]["events"][2]["request"]["body"], keep_blank_values=True)
            self.assertEqual(form["x_swiyu_wallet_tag"][0], cred)
            header_vals = [v for k, v in injected[0]["events"][2]["request"]["headers"] if k.lower() == "x-swiyu-wallet-correlation"]
            self.assertEqual(header_vals[0], hashlib.sha256(cred.encode("utf-8")).hexdigest())
            public = json.loads((output / "report.json").read_text(encoding="utf-8"))
            dumped = json.dumps(public)
            self.assertNotIn(cred, dumped)
            self.assertNotIn("credential_hash", dumped)
            self.assertNotIn(cred.split("~")[0], dumped)
            for session in public["sessions"]:
                self.assertNotIn("events", session)
                self.assertNotIn("credential", session)
                self.assertNotIn("given", session)

    def test_fake_provider_present_uses_fetched_request_challenge_and_is_fresh(self):
        fake = FakeProviderClient("unused")
        mock = FixtureVerifier()
        base = mock.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp) / "out"
                code, bundle = run_transcript_campaign(
                    str(OPENAC_MANIFEST),
                    str(OPENAC_CLAIM),
                    str(output),
                    support_path=str(OPENAC_SUPPORT),
                    fixture_only=False,
                    verifier_base=base,
                    provider_client_factory=lambda path: fake,
                )
                self.assertEqual(code, 0, [c["report"] for c in bundle["campaigns"]])
                self.assertFalse(bundle["evidence_usable"])
                self.assertEqual(len(fake.challenges), 2)
                self.assertEqual(len(fake.prepares), 2)
                seen = []
                for session, challenge in zip(
                    [s for s in bundle["sessions"] if s["campaign"] == "clean"],
                    fake.challenges,
                ):
                    jwt = session["events"][1]["response"]["body"].strip()
                    payload = json.loads(
                        base64.urlsafe_b64decode(jwt.split(".")[1] + "=" * (-len(jwt.split(".")[1]) % 4))
                    )
                    self.assertEqual(challenge["nonce"], payload["nonce"])
                    self.assertEqual(challenge["clientId"], payload["client_id"])
                    self.assertEqual(challenge["responseUri"], payload["response_uri"])
                    self.assertEqual(challenge["state"], payload["state"])
                    self.assertEqual(session["fresh"]["nonce"], payload["nonce"])
                    self.assertEqual(session["fresh"]["state"], payload["state"])
                    seen.append((challenge["nonce"], challenge["state"]))
                self.assertEqual(len(set(seen)), 2)
                for session in bundle["sessions"]:
                    self.assertEqual(session.get("proof_bytes"), 315_967)
                    self.assertEqual(session.get("witness_bytes"), 208_666_624)
                    token = unquote_plus(parse_qs(session["events"][2]["request"]["body"])["vp_token"][0])
                    self.assertNotEqual(session.get("proof_bytes"), len(token.encode("utf-8")))
        finally:
            mock.stop()

    def test_public_json_omits_raw_marker_even_when_injected_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "out"
            _, bundle = run_transcript_campaign(
                str(OPENAC_MANIFEST),
                str(OPENAC_CLAIM),
                str(output),
                support_path=str(OPENAC_SUPPORT),
                fixture_only=True,
                injections=["hidden_field"],
            )
            marker = bundle["sessions"][0]["credential"]
            self.assertTrue(marker)
            public = (output / "report.json").read_text(encoding="utf-8")
            self.assertNotIn(marker, public)
            self.assertNotIn(marker.split("~")[0], public)
            html = (output / "report.html").read_text(encoding="utf-8")
            self.assertNotIn(marker[:40], html)
            injected = [c for c in bundle["campaigns"] if c["kind"] == "injected regression"][0]
            self.assertEqual(injected["report"]["status"], "findings")
            self.assertNotEqual(injected["report"]["status"], "clean")

    def test_unsupported_claim_is_rejected_before_http(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = _write_manifest(root)
            with self.assertRaises(SupportError):
                run_transcript_campaign(
                    str(manifest),
                    str(OPENAC_CLAIM),
                    str(root / "out"),
                    support_path=str(REFERENCE_SUPPORT),
                    fixture_only=True,
                )

    def test_retain_private_writes_mode_600_artifacts_with_raw_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "out"
            run_transcript_campaign(
                str(OPENAC_MANIFEST),
                str(OPENAC_CLAIM),
                str(output),
                support_path=str(OPENAC_SUPPORT),
                fixture_only=True,
                retain_private=True,
            )
            private = output / "private" / "sessions.json"
            self.assertTrue(private.is_file())
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o600)
            payload = json.loads(private.read_text(encoding="utf-8"))
            self.assertIn("events", payload["sessions"][0])
            self.assertIn("credential", payload["sessions"][0])

    def test_openac_factory_emits_independent_variants_without_equivalence_claim(self):
        import subprocess

        completed = subprocess.run(
            ["node", str(OPENAC_FIXTURE)],
            cwd=str(OPENAC_FIXTURE.parent),
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        document = json.loads(completed.stdout)
        self.assertEqual(document["schema"], "swiyu.transcript-fixture.v1")
        self.assertNotEqual(document.get("equivalence"), "equivalent")
        variants = document["variants"]
        self.assertGreaterEqual(len(variants), 2)
        creds = [v["credential"]["data"] for v in variants]
        self.assertNotEqual(creds[0], creds[1])
        self.assertIn("current_time", variants[0]["given"])
        self.assertEqual(document["mapping"]["challenge_fields"]["nonce"], "nonce")
        dumped = json.dumps(document)
        self.assertNotIn("equivalent_inputs", dumped)

    def test_fixture_document_arg_reuses_loaded_factory(self):
        import subprocess

        completed = subprocess.run(
            ["node", str(OPENAC_FIXTURE)],
            cwd=str(OPENAC_FIXTURE.parent),
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "factory.json"
            path.write_text(completed.stdout, encoding="utf-8")
            os.chmod(path, 0o600)
            output = Path(tmp) / "out"
            code, bundle = run_transcript_campaign(
                str(OPENAC_MANIFEST),
                str(OPENAC_CLAIM),
                str(output),
                support_path=str(OPENAC_SUPPORT),
                fixture_only=True,
                fixture_document_path=str(path),
            )
            self.assertEqual(code, 0, bundle["campaigns"])
            self.assertEqual(bundle["campaigns"][0]["report"]["status"], "clean")


if __name__ == "__main__":
    unittest.main()

"""Behavioral tests for claim-derived transcript differential engine."""

from __future__ import annotations

import base64
import copy
import json
import sys
import unittest
from pathlib import Path
from urllib.parse import urlencode

SEMANTICS = Path(__file__).resolve().parents[2] / "semantics"
HARNESS = Path(__file__).resolve().parents[1]
PROVIDERS = Path(__file__).resolve().parents[2] / "providers"
for path in (str(HARNESS), str(SEMANTICS)):
    if path not in sys.path:
        sys.path.insert(0, path)

from semantics.claims import load_claim
from semantics.credentials import authenticate
from semantics.fixtures import make_fixture

from transcript_equivalence import (
    ClassifyError,
    analyze_transcripts,
    classify_fixture,
    decode_body,
)

CLEARANCE = SEMANTICS / "claims" / "clearance-status.json"
COMPOSED = SEMANTICS / "claims" / "composed-status.json"
OPENAC = SEMANTICS / "claims" / "openac-age18-status-2k.json"

SECRET_CLEARANCE = "TOP-SECRET-CLEARANCE-VALUE"
NONCE_A = "fresh-nonce-aaaa-12"
NONCE_B = "fresh-nonce-bbbb-12"
STATE_A = "fresh-state-aaaa-12"
STATE_B = "fresh-state-bbbb-12"
PROOF_A = base64.urlsafe_b64encode(b"proof-bytes-alpha-xx").rstrip(b"=").decode("ascii")
PROOF_B = base64.urlsafe_b64encode(b"proof-bytes-beta-yyy").rstrip(b"=").decode("ascii")


def _b64url_json(obj) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jwt(payload: dict) -> str:
    header = _b64url_json({"alg": "ES256", "typ": "JWT"})
    body = _b64url_json(payload)
    sig = base64.urlsafe_b64encode(b"sig-bytes-not-secret").rstrip(b"=").decode("ascii")
    return f"{header}.{body}.{sig}"


def _headers(*pairs, body: str = "") -> list:
    items = [["content-type", "application/json"]]
    items.extend([list(p) for p in pairs])
    items.append(["content-length", str(len(body))])
    return items


def _event(boundary: str, *, url: str, body: str, status: int = 200, extra_headers=None):
    headers = _headers(*(extra_headers or ()), body=body)
    return {
        "boundary": boundary,
        "request": {
            "method": "POST",
            "url": url,
            "headers": headers,
            "body": body,
        },
        "response": {
            "status": status,
            "headers": [["content-type", "application/json"], ["content-length", "2"]],
            "body": "{}",
        },
    }


def _session(sid, bundle, *, nonce, state, proof, accepted=True, extra_body=None, url=None, events=None):
    given = copy.deepcopy(bundle["given"])
    given["session"] = {
        **given["session"],
        "nonce": nonce,
        "state": state,
    }
    body_obj = {
        "audience": given["session"]["client_id"],
        "nonce": nonce,
        "proof": proof,
        "issuer": given["issuer"]["issuer_id"],
    }
    if extra_body:
        body_obj.update(extra_body)
    body = json.dumps(body_obj, separators=(",", ":"))
    default_url = url or (
        f"https://verifier.example/response?nonce={nonce}&state={state}"
    )
    return {
        "id": sid,
        "variant": "accept",
        "credential": bundle["fixture"]["credential"],
        "given": given,
        "accepted": accepted,
        "fresh": {"nonce": nonce, "state": state},
        "events": events
        if events is not None
        else [_event("wallet->verifier", url=default_url, body=body)],
    }


def _policy(**overrides):
    policy = {
        "id": "oid4vp-http",
        "observer": "network",
        "opaque_fields": [
            {
                "event": 0,
                "side": "request",
                "path": "/proof",
                "channel": "proof",
            }
        ],
        "public_fields": [
            {
                "event": 0,
                "side": "request",
                "path": "/nonce",
                "expected_key": "nonce",
            }
        ],
        "ignored_headers": [],
    }
    policy.update(overrides)
    return policy


class ClassifyFixtureTests(unittest.TestCase):
    def setUp(self):
        self.claim_path = CLEARANCE
        self.claim = load_claim(CLEARANCE)
        self.bundle = make_fixture(self.claim, attributes={"clearance": "synthetic"})

    def test_accepts_authentic_fixture_and_omits_session_nonce_state_only(self):
        classification = classify_fixture(
            self.claim_path,
            self.bundle["fixture"]["credential"],
            self.bundle["given"],
        )
        self.assertEqual(classification["statement_digest"], self.claim.statement_digest)
        self.assertTrue(classification["acceptance"])
        self.assertEqual(
            classification["release"],
            {
                "acceptance": True,
                "eid.issuer": "synthetic-issuer-1",
                "eid.key_id": "synthetic-key-1",
                "eid.credential_type": "swiyu.synthetic-eid@0",
            },
        )
        session = classification["public_context"]["session"]
        self.assertNotIn("nonce", session)
        self.assertNotIn("state", session)
        self.assertEqual(session["client_id"], "client-1")
        self.assertEqual(session["response_uri"], "https://verifier.example/response")
        self.assertEqual(session["query_id"], "query-1")
        self.assertIn("issuer", classification["public_context"])
        self.assertIn("now", classification["public_context"])
        kinds = {m["kind"] for m in classification["hidden_markers"]}
        self.assertIn("holder_key", kinds)
        dumped = json.dumps(classification)
        self.assertNotIn(self.bundle["fixture"]["credential"][:40], dumped)
        for marker in classification["hidden_markers"]:
            self.assertNotIn("value", marker)
            self.assertIn("id", marker)
            self.assertIn("kind", marker)
        self.assertIn("verifier_evaluated", classification["oracle_scope"])
        self.assertIn(
            "holder.signature-valid@1",
            classification["oracle_scope"]["verifier_evaluated"],
        )
        self.assertIn(
            "status.zero-at-reference@1",
            classification["oracle_scope"]["verifier_evaluated"],
        )
        note = json.dumps(classification["oracle_scope"]).lower()
        self.assertIn("verifier_evaluated", note)
        self.assertIn("not", note)

    def test_resolves_time_given_from_require_ast_not_age_field(self):
        claim = load_claim(OPENAC)
        bundle = make_fixture(claim)
        classification = classify_fixture(
            OPENAC, bundle["fixture"]["credential"], bundle["given"]
        )
        self.assertIn("acceptance", classification["release"])
        self.assertTrue(isinstance(classification["acceptance"], bool))
        self.assertEqual(
            classification["public_context"]["current_time"],
            bundle["given"]["current_time"],
        )

    def test_where_false_is_rejected_without_claiming_status_oracle(self):
        bundle = make_fixture(
            self.claim,
            attributes={"clearance": "nope"},
            given_overrides={"required_clearance": "secret"},
        )
        classification = classify_fixture(
            self.claim_path, bundle["fixture"]["credential"], bundle["given"]
        )
        self.assertFalse(classification["acceptance"])
        self.assertFalse(classification["release"]["acceptance"])

    def test_invalid_credential_raises(self):
        with self.assertRaises(ClassifyError):
            classify_fixture(self.claim_path, "not-a-jwt", self.bundle["given"])


class DecodeBodyTests(unittest.TestCase):
    def test_json_form_jwt_and_repeated_form_params(self):
        jwt = _jwt({"nonce": "abc"})
        decoded = decode_body(json.dumps({"token": jwt}))
        self.assertFalse(decoded["truncated"])
        token = decoded["value"]["token"]
        self.assertEqual(token["payload"]["nonce"], "abc")
        self.assertEqual(token["signature"]["encoding"], "compact-jws")
        self.assertIsInstance(token["signature"]["length"], int)

        form = urlencode([("k", "1"), ("k", "2"), ("vp", jwt)], doseq=True)
        form_decoded = decode_body(form)
        self.assertEqual(form_decoded["value"]["k"], ["1", "2"])
        self.assertEqual(form_decoded["value"]["vp"]["payload"]["nonce"], "abc")

        wrapped = _b64url_json({"inner": True})
        nested = decode_body(json.dumps({"blob": wrapped}))
        self.assertEqual(nested["value"]["blob"]["inner"], True)


def _holder_canary(bundle) -> str:
    claim = load_claim(CLEARANCE)
    defs = {
        alias: spec["path"][0]
        for alias, spec in claim.document["attributes"].items()
    }
    auth = authenticate(
        bundle["fixture"]["credential"], bundle["given"]["issuer"], defs
    )
    return auth.holder_key["x"]


class AnalyzeTranscriptTests(unittest.TestCase):
    def setUp(self):
        self.claim = load_claim(CLEARANCE)
        self.accept = make_fixture(self.claim, seed=1)
        self.accept_same_issuer = make_fixture(self.claim, seed=1)
        self.canary = _holder_canary(self.accept)

    def test_equivalent_sessions_with_distinct_proofs_and_fresh_rename(self):
        sessions = [
            _session("s1", self.accept, nonce=NONCE_A, state=STATE_A, proof=PROOF_A),
            _session(
                "s2",
                self.accept_same_issuer,
                nonce=NONCE_B,
                state=STATE_B,
                proof=PROOF_B,
            ),
        ]
        report = analyze_transcripts(CLEARANCE, sessions, _policy())
        self.assertEqual(report["schema"], "swiyu.transcript-campaign.v1")
        self.assertEqual(report["status"], "clean")
        compared = [p for p in report["pairs"] if p["eligibility"] == "compared"]
        self.assertEqual(len(compared), 1)
        self.assertEqual(compared[0]["status"], "equivalent")
        blob = json.dumps(report)
        self.assertNotIn(self.canary, blob)
        self.assertNotIn("statistical unlinkability", blob.lower())

    def test_secret_in_header_url_form_jwt_and_base64_before_opaque(self):
        leak = self.canary
        jwt = _jwt({"leak": leak})
        form = urlencode({"error": leak, "proof": PROOF_A})
        blob = _b64url_json({"hidden": leak})
        body = json.dumps(
            {"nonce": NONCE_A, "proof": PROOF_A, "wrapped": blob, "token": jwt},
            separators=(",", ":"),
        )
        sessions = [
            {
                **_session(
                    "s1",
                    self.accept,
                    nonce=NONCE_A,
                    state=STATE_A,
                    proof=PROOF_A,
                    extra_body={"wrapped": blob, "token": jwt},
                ),
                "events": [
                    _event(
                        "wallet->verifier",
                        url=f"https://verifier.example/response?canary={leak}&nonce={NONCE_A}",
                        body=body,
                        extra_headers=[("x-debug", leak)],
                    ),
                    {
                        "boundary": "error",
                        "request": {
                            "method": "POST",
                            "url": "https://verifier.example/error",
                            "headers": [
                                ["content-type", "application/x-www-form-urlencoded"],
                                ["content-length", str(len(form))],
                            ],
                            "body": form,
                        },
                        "response": {
                            "status": 400,
                            "headers": [["content-length", "0"]],
                            "body": "",
                        },
                    },
                ],
            }
        ]
        report = analyze_transcripts(CLEARANCE, sessions, _policy())
        self.assertEqual(report["status"], "findings")
        kinds = {f["kind"] for f in report["findings"]}
        self.assertIn("secret_disclosure", kinds)
        self.assertNotIn(leak, json.dumps(report))

    def test_freshness_mismatch_and_sibling_not_masked(self):
        body = json.dumps(
            {"nonce": "wrong-fresh-value-xx", "proof": PROOF_A, "extra": "keep"},
            separators=(",", ":"),
        )
        sess = _session(
            "s1", self.accept, nonce=NONCE_A, state=STATE_A, proof=PROOF_A
        )
        sess["events"] = [
            _event(
                "wallet->verifier",
                url=f"https://verifier.example/response?nonce={NONCE_A}",
                body=body,
            )
        ]
        report = analyze_transcripts(CLEARANCE, [sess], _policy())
        kinds = {f["kind"] for f in report["findings"]}
        self.assertIn("freshness_binding_mismatch", kinds)

    def test_predicate_outcome_change_is_input_non_equivalent(self):
        reject = make_fixture(
            self.claim,
            attributes={"clearance": "nope"},
            given_overrides={"required_clearance": SECRET_CLEARANCE},
            seed=1,
        )
        sessions = [
            _session("ok", self.accept, nonce=NONCE_A, state=STATE_A, proof=PROOF_A),
            _session(
                "no",
                reject,
                nonce=NONCE_B,
                state=STATE_B,
                proof=PROOF_B,
                accepted=False,
            ),
        ]
        report = analyze_transcripts(CLEARANCE, sessions, _policy())
        elig = {p["eligibility"] for p in report["pairs"]}
        self.assertIn("input_non_equivalent", elig)
        self.assertNotIn("compared", elig)

    def test_unexpected_reject_is_finding(self):
        sess = _session(
            "s1",
            self.accept,
            nonce=NONCE_A,
            state=STATE_A,
            proof=PROOF_A,
            accepted=False,
        )
        report = analyze_transcripts(CLEARANCE, [sess], _policy())
        kinds = {f["kind"] for f in report["findings"]}
        self.assertIn("unexpected_reject", kinds)
        self.assertNotEqual(report["status"], "clean")

    def test_empty_trace_is_inconclusive(self):
        sess = _session(
            "s1", self.accept, nonce=NONCE_A, state=STATE_A, proof=PROOF_A, events=[]
        )
        report = analyze_transcripts(CLEARANCE, [sess], _policy())
        self.assertEqual(report["status"], "inconclusive")

    def test_and_or_claim_pairs_matching_acceptance(self):
        claim = load_claim(COMPOSED)
        a = make_fixture(claim, seed=3)
        b = make_fixture(
            claim,
            attributes={"nationality": "DE", "residence": "FR"},
            seed=3,
        )
        sessions = [
            _session("and", a, nonce=NONCE_A, state=STATE_A, proof=PROOF_A),
            _session("or", b, nonce=NONCE_B, state=STATE_B, proof=PROOF_B),
        ]
        report = analyze_transcripts(COMPOSED, sessions, _policy())
        compared = [p for p in report["pairs"] if p["eligibility"] == "compared"]
        self.assertEqual(len(compared), 1)

    def test_unknown_hash_differential_without_marker(self):
        h1 = "a" * 64
        h2 = "b" * 64
        s1 = _session(
            "s1",
            self.accept,
            nonce=NONCE_A,
            state=STATE_A,
            proof=PROOF_A,
            extra_body={"cred_id": h1},
        )
        s2 = _session(
            "s2",
            self.accept_same_issuer,
            nonce=NONCE_B,
            state=STATE_B,
            proof=PROOF_B,
            extra_body={"cred_id": h2},
        )
        report = analyze_transcripts(CLEARANCE, [s1, s2], _policy())
        kinds = {f["kind"] for f in report["findings"]}
        self.assertIn("unknown_identifier_differential", kinds)
        diffs = report["pairs"][0]["diffs"]
        self.assertTrue(any(d["pointer"].endswith("cred_id") for d in diffs))
        self.assertNotIn(h1, json.dumps(report))

    def test_proof_length_mismatch_is_finding_same_bytes_allowed_to_differ(self):
        short = base64.urlsafe_b64encode(b"short-proof-xx").rstrip(b"=").decode()
        longp = base64.urlsafe_b64encode(b"longer-proof-bytes!!").rstrip(b"=").decode()
        s1 = _session(
            "s1", self.accept, nonce=NONCE_A, state=STATE_A, proof=short
        )
        s2 = _session(
            "s2",
            self.accept_same_issuer,
            nonce=NONCE_B,
            state=STATE_B,
            proof=longp,
        )
        report = analyze_transcripts(CLEARANCE, [s1, s2], _policy())
        kinds = {f["kind"] for f in report["findings"]}
        self.assertIn("opaque_length_mismatch", kinds)

    def test_invalid_auth_session_is_error_or_inconclusive(self):
        sess = _session(
            "s1", self.accept, nonce=NONCE_A, state=STATE_A, proof=PROOF_A
        )
        sess["credential"] = "totally-invalid"
        report = analyze_transcripts(CLEARANCE, [sess], _policy())
        self.assertIn(report["status"], {"error", "inconclusive"})


class AdversarialEngineReviewTests(unittest.TestCase):
    def setUp(self):
        self.claim = load_claim(CLEARANCE)
        self.accept = make_fixture(self.claim, seed=1)
        self.accept_b = make_fixture(self.claim, seed=1)
        self.canary = _holder_canary(self.accept)

    def test_native_status_list_length_65536_classifies_without_dummy_root(self):
        claim = load_claim(OPENAC)
        bundle = make_fixture(claim, seed=2)
        snapshot = copy.deepcopy(bundle["given"]["status_snapshot"])
        self.assertEqual(set(snapshot), {
            "id",
            "issuer_id",
            "key_id",
            "subject",
            "commitment",
            "epoch",
            "list_length",
            "valid_before",
        })
        original_root = snapshot["commitment"]
        snapshot["list_length"] = 65536
        bundle["given"]["status_snapshot"] = snapshot
        classification = classify_fixture(
            OPENAC, bundle["fixture"]["credential"], bundle["given"]
        )
        self.assertTrue(classification["acceptance"])
        self.assertEqual(
            classification["public_context"]["status_snapshot"]["list_length"],
            65536,
        )
        self.assertEqual(
            classification["public_context"]["status_snapshot"]["commitment"],
            original_root,
        )
        self.assertEqual(
            classification["public_context"]["status_snapshot"]["epoch"],
            snapshot["epoch"],
        )
        self.assertIn(
            "status.zero-at-reference@1",
            classification["oracle_scope"]["verifier_evaluated"],
        )
        with self.assertRaises(ClassifyError):
            bad = copy.deepcopy(bundle["given"])
            bad["status_snapshot"]["list_length"] = 65537
            classify_fixture(OPENAC, bundle["fixture"]["credential"], bad)
        with self.assertRaises(ClassifyError):
            bad = copy.deepcopy(bundle["given"])
            bad["status_snapshot"]["list_length"] = 131072
            classify_fixture(OPENAC, bundle["fixture"]["credential"], bad)
        with self.assertRaises(ClassifyError):
            bad = copy.deepcopy(bundle["given"])
            bad["status_snapshot"]["list_length"] = True
            classify_fixture(OPENAC, bundle["fixture"]["credential"], bad)

    def test_public_context_alpha_renames_response_uri_uuid_preserving_origin(self):
        uuid_a = "11111111-1111-4111-8111-111111111111"
        uuid_b = "22222222-2222-4222-8222-222222222222"
        origin = "https://verifier.example"
        path = "/oid4vp/api/request-object/{id}/response-data?query=age"
        s1 = _session("s1", self.accept, nonce=NONCE_A, state=STATE_A, proof=PROOF_A)
        s2 = _session("s2", self.accept_b, nonce=NONCE_B, state=STATE_B, proof=PROOF_B)
        s1["given"]["session"]["response_uri"] = path.replace("{id}", uuid_a).replace(
            "/oid4vp", origin + "/oid4vp"
        )
        s2["given"]["session"]["response_uri"] = (
            origin + "/oid4vp/api/request-object/" + uuid_b + "/response-data?query=age"
        )
        s1["fresh"]["request_id"] = uuid_a
        s2["fresh"]["request_id"] = uuid_b
        report = analyze_transcripts(CLEARANCE, [s1, s2], _policy())
        compared = [p for p in report["pairs"] if p["eligibility"] == "compared"]
        self.assertEqual(len(compared), 1)
        ctx = report["classifications"][0]["public_context"]["session"]["response_uri"]
        self.assertIn("{request_id}", ctx)
        self.assertIn(origin, ctx)
        self.assertIn("/oid4vp/api/request-object/", ctx)
        self.assertIn("/response-data", ctx)
        self.assertIn("query=age", ctx)
        blob = json.dumps(report)
        self.assertNotIn(uuid_a, blob)
        self.assertNotIn(uuid_b, blob)

    def test_url_rename_preserves_symbolic_names_when_positions_swap(self):
        s1 = _session(
            "s1",
            self.accept,
            nonce=NONCE_A,
            state=STATE_A,
            proof=PROOF_A,
            url=f"https://verifier.example/callback/{NONCE_A}/{STATE_A}?keep=1",
        )
        s2 = _session(
            "s2",
            self.accept_b,
            nonce=NONCE_B,
            state=STATE_B,
            proof=PROOF_B,
            url=f"https://verifier.example/callback/{STATE_B}/{NONCE_B}?keep=1",
        )
        report = analyze_transcripts(CLEARANCE, [s1, s2], _policy())
        self.assertEqual(report["pairs"][0]["eligibility"], "compared")
        self.assertEqual(report["pairs"][0]["status"], "mismatch")
        pointers = " ".join(d["pointer"] for d in report["pairs"][0]["diffs"])
        self.assertTrue("url" in pointers or report["findings"])
        kinds = {f["kind"] for f in report["findings"]}
        self.assertTrue(kinds & {"transcript_mismatch", "unknown_identifier_differential"})

    def test_accepted_must_be_strict_bool(self):
        sess = _session("s1", self.accept, nonce=NONCE_A, state=STATE_A, proof=PROOF_A)
        sess["accepted"] = "false"
        report = analyze_transcripts(CLEARANCE, [sess], _policy())
        self.assertIn(report["status"], {"error", "inconclusive"})
        kinds = {f["kind"] for f in report["findings"]}
        self.assertTrue(kinds & {"invalid_accepted", "policy_error", "invalid_auth"})

    def test_missing_accepted_is_not_clean(self):
        sess = _session("s1", self.accept, nonce=NONCE_A, state=STATE_A, proof=PROOF_A)
        del sess["accepted"]
        report = analyze_transcripts(CLEARANCE, [sess], _policy())
        self.assertNotEqual(report["status"], "clean")

    def test_zero_eligible_pairs_is_inconclusive(self):
        reject = make_fixture(
            self.claim,
            attributes={"clearance": "nope"},
            given_overrides={"required_clearance": SECRET_CLEARANCE},
            seed=1,
        )
        sessions = [
            _session("ok", self.accept, nonce=NONCE_A, state=STATE_A, proof=PROOF_A),
            _session(
                "no",
                reject,
                nonce=NONCE_B,
                state=STATE_B,
                proof=PROOF_B,
                accepted=False,
            ),
        ]
        report = analyze_transcripts(CLEARANCE, sessions, _policy())
        self.assertEqual(report["status"], "inconclusive")
        self.assertEqual(report["coverage"]["compared_pairs"], 0)

    def test_unexpected_reject_still_scans_secrets(self):
        sess = _session(
            "s1",
            self.accept,
            nonce=NONCE_A,
            state=STATE_A,
            proof=PROOF_A,
            accepted=False,
        )
        sess["events"][0]["request"]["url"] = (
            f"https://verifier.example/response?leak={self.canary}"
        )
        report = analyze_transcripts(CLEARANCE, [sess], _policy())
        kinds = {f["kind"] for f in report["findings"]}
        self.assertIn("unexpected_reject", kinds)
        self.assertIn("secret_disclosure", kinds)
        self.assertNotIn(self.canary, json.dumps(report))

    def test_malformed_headers_are_inconclusive(self):
        sess = _session("s1", self.accept, nonce=NONCE_A, state=STATE_A, proof=PROOF_A)
        sess["events"][0]["request"]["headers"] = ["broken"]
        report = analyze_transcripts(CLEARANCE, [sess], _policy())
        self.assertEqual(report["status"], "inconclusive")
        kinds = {f["kind"] for f in report["findings"]}
        self.assertIn("malformed_event", kinds)

    def test_ignored_headers_escape_hatch_rejected(self):
        sess = _session("s1", self.accept, nonce=NONCE_A, state=STATE_A, proof=PROOF_A)
        report = analyze_transcripts(
            CLEARANCE, [sess], _policy(ignored_headers=["x-hash", "date"])
        )
        self.assertEqual(report["status"], "error")
        self.assertIn("ignored", json.dumps(report["findings"]).lower())

    def test_content_length_uses_utf8_byte_size(self):
        body = json.dumps(
            {"nonce": NONCE_A, "proof": PROOF_A, "note": "é"},
            separators=(",", ":"),
            ensure_ascii=False,
        )
        sess = _session("s1", self.accept, nonce=NONCE_A, state=STATE_A, proof=PROOF_A)
        sess["events"] = [
            _event(
                "wallet->verifier",
                url=f"https://verifier.example/response?nonce={NONCE_A}",
                body=body,
            )
        ]
        sess["events"][0]["request"]["headers"] = [
            ["content-type", "application/json"],
            ["content-length", str(len(body))],
        ]
        report = analyze_transcripts(CLEARANCE, [sess], _policy())
        kinds = {f["kind"] for f in report["findings"]}
        self.assertIn("content_length_mismatch", kinds)

    def test_decoded_scan_finds_canary_in_large_base64_envelope(self):
        leak = self.canary
        envelope = _b64url_json({"hidden": leak, "pad": "Q" * 300000})
        self.assertGreater(len(envelope), 400_000)
        body = json.dumps(
            {"nonce": NONCE_A, "proof": PROOF_A, "envelope": envelope},
            separators=(",", ":"),
        )
        sess = _session("s1", self.accept, nonce=NONCE_A, state=STATE_A, proof=PROOF_A)
        sess["events"] = [
            _event(
                "wallet->verifier",
                url=f"https://verifier.example/response?nonce={NONCE_A}",
                body=body,
            )
        ]
        report = analyze_transcripts(CLEARANCE, [sess], _policy())
        kinds = {f["kind"] for f in report["findings"]}
        self.assertIn("secret_disclosure", kinds)
        self.assertNotIn(leak, json.dumps(report))
        self.assertNotIn("attribute.", json.dumps(report["findings"]))

    def test_opaque_rejects_object_and_undeclared_channel(self):
        sess = _session("s1", self.accept, nonce=NONCE_A, state=STATE_A, proof=PROOF_A)
        policy = _policy(
            opaque_fields=[
                {
                    "event": 0,
                    "side": "request",
                    "path": "/audience",
                    "channel": "proof",
                }
            ]
        )
        body = json.dumps(
            {"nonce": NONCE_A, "proof": PROOF_A, "audience": {"nested": True}},
            separators=(",", ":"),
        )
        sess["events"] = [
            _event(
                "wallet->verifier",
                url=f"https://verifier.example/response?nonce={NONCE_A}",
                body=body,
            )
        ]
        report = analyze_transcripts(CLEARANCE, [sess], policy)
        kinds = {f["kind"] for f in report["findings"]}
        self.assertTrue(kinds & {"opaque_invalid", "policy_error"})
        self.assertNotEqual(report["status"], "clean")

    def test_opaque_unknown_channel_rejected(self):
        sess = _session("s1", self.accept, nonce=NONCE_A, state=STATE_A, proof=PROOF_A)
        report = analyze_transcripts(
            CLEARANCE,
            [sess],
            _policy(
                opaque_fields=[
                    {
                        "event": 0,
                        "side": "request",
                        "path": "/proof",
                        "channel": "ciphertext",
                    }
                ]
            ),
        )
        self.assertEqual(report["status"], "error")

    def test_truncated_decode_is_inconclusive(self):
        huge = json.dumps(["n"] * 5000)
        sess = _session("s1", self.accept, nonce=NONCE_A, state=STATE_A, proof=PROOF_A)
        sess["events"] = [
            _event(
                "wallet->verifier",
                url=f"https://verifier.example/response?nonce={NONCE_A}",
                body=huge,
            )
        ]
        report = analyze_transcripts(CLEARANCE, [sess], _policy())
        self.assertEqual(report["status"], "inconclusive")
        kinds = {f["kind"] for f in report["findings"]}
        self.assertIn("truncated_decode", kinds)

    def test_jwt_keeps_alg_and_does_not_use_noncanonical_payload(self):
        header = _b64url_json({"alg": "ES256", "typ": "JWT"})
        payload = base64.b64encode(json.dumps({"x": 1}).encode()).decode("ascii")
        sig = base64.urlsafe_b64encode(b"sig-bytes-not-secret").rstrip(b"=").decode()
        decoded = decode_body(f"{header}.{payload}.{sig}")
        self.assertIsInstance(decoded["value"], str)
        good = decode_body(_jwt({"nonce": "abc"}))
        self.assertEqual(good["value"]["header"]["alg"], "ES256")
        self.assertEqual(good["value"]["signature"]["alg"], "ES256")

    def test_encoded_sdjwt_disclosure_scanned_even_when_equally_leaked(self):
        disc = _b64url_json({"hidden": self.canary})
        leaked = _jwt({"_sd": ["x" * 32]}) + "~" + disc
        s1 = _session(
            "s1",
            self.accept,
            nonce=NONCE_A,
            state=STATE_A,
            proof=PROOF_A,
            extra_body={"sd_jwt": leaked},
        )
        s2 = _session(
            "s2",
            self.accept_b,
            nonce=NONCE_B,
            state=STATE_B,
            proof=PROOF_B,
            extra_body={"sd_jwt": leaked},
        )
        report = analyze_transcripts(CLEARANCE, [s1, s2], _policy())
        self.assertEqual(report["status"], "findings")
        kinds = {f["kind"] for f in report["findings"]}
        self.assertIn("secret_disclosure", kinds)
        self.assertNotIn(self.canary, json.dumps(report))

    def test_mismatch_pairs_emit_findings_and_omit_raw_unknown_values(self):
        h1 = "a" * 64
        h2 = "b" * 64
        s1 = _session(
            "s1",
            self.accept,
            nonce=NONCE_A,
            state=STATE_A,
            proof=PROOF_A,
            extra_body={"cred_id": h1},
        )
        s2 = _session(
            "s2",
            self.accept_b,
            nonce=NONCE_B,
            state=STATE_B,
            proof=PROOF_B,
            extra_body={"cred_id": h2},
        )
        report = analyze_transcripts(CLEARANCE, [s1, s2], _policy())
        self.assertEqual(report["status"], "findings")
        self.assertTrue(report["findings"])
        blob = json.dumps(report)
        self.assertNotIn(h1, blob)
        self.assertNotIn(h2, blob)
        self.assertNotIn(self.canary, blob)


class EpflTranscriptEngineTests(unittest.TestCase):
    EPFL = SEMANTICS / "claims" / "epfl-d10-age25-jwt.json"

    def test_challenge_nonce_stripped_from_public_context(self):
        sys.path.insert(0, str(PROVIDERS / "epfl"))
        from fixtures import VARIANT_A, fixture_bundle  # noqa: WPS433

        challenge = "71904c78267613800be90ce2b62f3ef571de0a94eb2f41d2053d8aa58f528f90"
        bundle = fixture_bundle(VARIANT_A.variant_id, challenge)
        classification = classify_fixture(
            self.EPFL,
            bundle["credential"],
            bundle["given"],
        )
        self.assertTrue(classification["acceptance"])
        self.assertNotIn("challenge_nonce", classification["public_context"])
        self.assertEqual(classification["public_context"]["now_date"], bundle["given"]["now_date"])

    def test_same_public_meaning_different_hidden_dob(self):
        sys.path.insert(0, str(PROVIDERS / "epfl"))
        from fixtures import VARIANT_A, VARIANT_B, fixture_bundle  # noqa: WPS433

        challenge = "71904c78267613800be90ce2b62f3ef571de0a94eb2f41d2053d8aa58f528f90"
        bundle_a = fixture_bundle(VARIANT_A.variant_id, challenge)
        bundle_b = fixture_bundle(VARIANT_B.variant_id, challenge)
        a = classify_fixture(self.EPFL, bundle_a["credential"], bundle_a["given"])
        b = classify_fixture(self.EPFL, bundle_b["credential"], bundle_b["given"])
        self.assertTrue(a["acceptance"] and b["acceptance"])
        self.assertEqual(a["public_context"], b["public_context"])


if __name__ == "__main__":
    unittest.main()

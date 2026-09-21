"""Cross-implementation transcript differential for the shared age-25 claim."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path
from urllib.parse import urlencode

HARNESS = Path(__file__).resolve().parents[1]
SEMANTICS = Path(__file__).resolve().parents[2] / "semantics"
PROVIDERS = Path(__file__).resolve().parents[2] / "providers"
for path in (str(HARNESS), str(SEMANTICS), str(PROVIDERS / "epfl")):
    if path not in sys.path:
        sys.path.insert(0, path)

from fixtures import VARIANT_A, VARIANT_B, fixture_bundle
from transcript_cross import analyze_cross_implementation
from transcript_policy import build_cross_flow_policy, build_flow_policy

CLAIM = SEMANTICS / "claims" / "age25-holder-challenge.json"
CHALLENGE = "71904c78267613800be90ce2b62f3ef571de0a94eb2f41d2053d8aa58f528f90"
BOUNDARIES = [
    "verifier:management_create",
    "verifier:request_object",
    "wallet->verifier:direct_post",
    "verifier:management_result",
]


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _token(value) -> str:
    return _b64(json.dumps(value, separators=(",", ":")).encode())


def _jwt(payload: dict, sig: bytes) -> str:
    return _token({"alg": "ES256"}) + "." + _token(payload) + "." + _b64(sig)


def _zkp(implementation: str) -> dict:
    if implementation.startswith("epfl-"):
        return {
            "profile": "epfl-d10-swiyu-jwt-age25-v0",
            "circuit_id": "d10_swiyu_jwt",
            "now_date": 20240101,
            "issuer_pub_x": "e14492964d758e7de59e3adade4b3337cdc112e8bd37933c3769a2feb2d44de8",
            "issuer_pub_y": "abb82c578d7685444f97c9e59070e65a1810b4a5d82135f8a3c5994dbf39d884",
        }
    return {
        "profile": "openac-age25-jwt-v0",
        "circuit_id": "swiyu_age25_jwt",
        "now_date": 20240101,
    }


def _documents():
    return [
        {
            "mapping": {"query_id": "birth_date"},
            "proof_path": "/proof_b64",
        },
        {
            "mapping": {"query_id": "birth_date"},
            "proof_path": "/proof",
        },
    ]


def _realistic_envelope(implementation, encoded):
    if implementation.startswith("epfl-"):
        return {
            "profile": "epfl-d10-swiyu-jwt-age25-v0",
            "circuit": "d10_swiyu_jwt",
            "scheme": "ultra_honk",
            "proof_b64": encoded,
        }
    return {
        "version": "swiyu-zkp-proof-v0",
        "profile": "openac-age25-jwt-v0",
        "circuitId": "swiyu_age25_jwt",
        "proof": encoded,
        "lookup": {
            "issuer": "did:example:epfl-test-issuer",
            "kid": "epfl-test-key-1",
            "vct": "https://example.ch/vct/epfl-d10-test",
        },
    }


def _session(sid, variant, implementation, *, extra_headers=None, extra_fields=None, zkp=None, proof=None, envelope=None):
    bundle = fixture_bundle(variant.variant_id, CHALLENGE)
    state = f"{sid}-state-identifier"
    nonce = f"{sid}-nonce-identifier"
    callback = f"http://127.0.0.1:9999/oid4vp/api/request-object/{state}/response-data"
    given = copy.deepcopy(bundle["given"])
    policy = zkp or _zkp(implementation)
    create = json.dumps(
        {
            "jwt_secured_authorization_request": True,
            "response_mode": "direct_post",
            "accepted_issuer_dids": [given["issuer"]["issuer_id"]],
            "dcql_query": {
                "credentials": [{
                    "id": "birth_date",
                    "format": "dc+sd-jwt",
                    "x_swiyu_zkp": policy,
                }]
            },
        },
        separators=(",", ":"),
    )
    proof_bytes = proof or (b"E" * 64 if implementation.startswith("epfl-") else b"O" * 96)
    encoded = _b64(proof_bytes)
    envelope = json.dumps(
        envelope or {"proof": encoded, "proof_b64": encoded},
        separators=(",", ":"),
    )
    form = {"state": state, "vp_token": json.dumps({"birth_date": [envelope]}, separators=(",", ":"))}
    if extra_fields:
        form.update(extra_fields)
    post = urlencode(form)
    jwt = _jwt(
        {
            "nonce": nonce,
            "state": state,
            "response_uri": callback,
            "client_id": "did:example:epfl-verifier",
            "iat": 1789495000,
            "exp": 1789498600,
        },
        b"S" * 64,
    )
    result = json.dumps({"id": state, "state": "SUCCESS"}, separators=(",", ":"))
    bodies = [
        (create, json.dumps({"id": state})),
        ("", jwt),
        (post, "{}"),
        ("", result),
    ]
    events = []
    for index, (request, response) in enumerate(bodies):
        headers = [["Content-Length", str(len(request.encode()))]]
        if extra_headers and index == 2:
            headers.extend(extra_headers)
        events.append(
            {
                "boundary": BOUNDARIES[index],
                "request": {
                    "method": "POST" if index in (0, 2) else "GET",
                    "url": callback,
                    "headers": headers,
                    "body": request,
                },
                "response": {
                    "status": 200,
                    "headers": [
                        ["Date", "Tue, 15 Sep 2026 18:00:00 GMT"],
                        ["Content-Length", str(len(response.encode()))],
                    ],
                    "body": response,
                },
            }
        )
    return {
        "id": sid,
        "variant": variant.variant_id,
        "implementation": implementation,
        "credential": bundle["credential"],
        "given": given,
        "accepted": True,
        "fresh": {"nonce": nonce, "state": state},
        "session_meta": {
            "nonce": nonce,
            "state": state,
            "response_uri": callback,
            "client_id": "did:example:epfl-verifier",
        },
        "events": events,
    }


class CrossImplementationTests(unittest.TestCase):
    def setUp(self):
        self.policy = build_cross_flow_policy(_documents())

    def test_same_claim_different_circuits_are_equivalent_after_implementation_exemption(self):
        sessions = [
            _session("epfl-a", VARIANT_A, "epfl-d10-swiyu-jwt-age25-v0"),
            _session("openac-a", VARIANT_A, "openac-age25-jwt-v0"),
            _session("epfl-b", VARIANT_B, "epfl-d10-swiyu-jwt-age25-v0"),
            _session("openac-b", VARIANT_B, "openac-age25-jwt-v0"),
        ]
        report = analyze_cross_implementation(CLAIM, sessions, self.policy)
        self.assertEqual(report["status"], "clean", report)
        compared = [p for p in report["pairs"] if p["eligibility"] == "compared"]
        self.assertEqual(len(compared), 4)
        self.assertTrue(all(p["status"] == "equivalent" for p in compared), compared)
        self.assertEqual(
            set(report["coverage"]["implementations"]),
            {"epfl-d10-swiyu-jwt-age25-v0", "openac-age25-jwt-v0"},
        )

    def test_hidden_birth_date_in_form_field_is_a_finding(self):
        leaked = _session(
            "openac-a",
            VARIANT_A,
            "openac-age25-jwt-v0",
            extra_fields={"x_swiyu_wallet_tag": fixture_bundle(VARIANT_A.variant_id, CHALLENGE)["credential"]},
        )
        clean = _session("epfl-a", VARIANT_A, "epfl-d10-swiyu-jwt-age25-v0")
        report = analyze_cross_implementation(CLAIM, [clean, leaked], self.policy)
        self.assertEqual(report["status"], "findings", report)
        kinds = {f.get("kind") for f in report["findings"]}
        self.assertIn("secret_disclosure", kinds)
        blob = json.dumps(report)
        self.assertNotIn(VARIANT_A.birth_date, blob)
        self.assertNotIn(leaked["credential"][:40], blob)

    def test_unknown_hash_header_is_a_finding_even_without_markers(self):
        left = _session("epfl-a", VARIANT_A, "epfl-d10-swiyu-jwt-age25-v0")
        digest = hashlib.sha256(b"hidden-correlation").hexdigest()
        right = _session(
            "openac-a",
            VARIANT_A,
            "openac-age25-jwt-v0",
            extra_headers=[["X-Swiyu-Wallet-Correlation", digest]],
        )
        report = analyze_cross_implementation(CLAIM, [left, right], self.policy)
        self.assertEqual(report["status"], "findings", report)
        kinds = {f.get("kind") for f in report["findings"]}
        self.assertTrue(kinds & {"unknown_identifier_differential", "transcript_mismatch"})
        self.assertNotIn(digest, json.dumps(report))

    def test_status_field_on_one_backend_is_not_an_implementation_exemption(self):
        zkp = _zkp("openac-age25-jwt-v0")
        zkp["cutoff_date"] = "2007-06-15"
        left = _session("epfl-a", VARIANT_A, "epfl-d10-swiyu-jwt-age25-v0")
        right = _session("openac-a", VARIANT_A, "openac-age25-jwt-v0", zkp=zkp)
        report = analyze_cross_implementation(CLAIM, [left, right], self.policy)
        self.assertEqual(report["status"], "findings", report)
        self.assertTrue(
            any("cutoff_date" in pointer for finding in report["findings"] for pointer in finding.get("pointers", []))
        )

    def test_same_implementation_pairs_are_left_to_the_within_backend_engine(self):
        sessions = [
            _session("epfl-a", VARIANT_A, "epfl-d10-swiyu-jwt-age25-v0"),
            _session("epfl-b", VARIANT_B, "epfl-d10-swiyu-jwt-age25-v0"),
        ]
        report = analyze_cross_implementation(CLAIM, sessions, self.policy)
        self.assertEqual(report["status"], "inconclusive")
        self.assertEqual(report["coverage"]["compared_pairs"], 0)

    def test_loopback_ports_are_test_infrastructure(self):
        left = _session("epfl-a", VARIANT_A, "epfl-d10-swiyu-jwt-age25-v0")
        right = _session("openac-a", VARIANT_A, "openac-age25-jwt-v0")
        for session, port in ((left, "61014"), (right, "61058")):
            for event in session["events"]:
                event["request"]["url"] = event["request"]["url"].replace("127.0.0.1:9999", f"127.0.0.1:{port}")
                event["request"]["headers"] = [["Host", f"127.0.0.1:{port}"], *event["request"]["headers"]]
        report = analyze_cross_implementation(CLAIM, [left, right], self.policy)
        self.assertEqual(report["status"], "clean", report)

    def test_realistic_envelope_shapes_are_implementation_identity(self):
        sessions = [
            _session(
                "epfl-a",
                VARIANT_A,
                "epfl-d10-swiyu-jwt-age25-v0",
                envelope=_realistic_envelope("epfl", _b64(b"E" * 64)),
            ),
            _session(
                "openac-a",
                VARIANT_A,
                "openac-age25-jwt-v0",
                envelope=_realistic_envelope("openac", _b64(b"O" * 96)),
            ),
        ]
        report = analyze_cross_implementation(CLAIM, sessions, self.policy)
        self.assertEqual(report["status"], "clean", report)

    def test_extra_lookup_sibling_is_not_an_implementation_exemption(self):
        encoded = _b64(b"O" * 96)
        leaked = _realistic_envelope("openac", encoded)
        leaked["lookup"]["birth_date"] = "1988-06-19"
        left = _session(
            "epfl-a",
            VARIANT_A,
            "epfl-d10-swiyu-jwt-age25-v0",
            envelope=_realistic_envelope("epfl", _b64(b"E" * 64)),
        )
        right = _session(
            "openac-a",
            VARIANT_A,
            "openac-age25-jwt-v0",
            envelope=leaked,
        )
        report = analyze_cross_implementation(CLAIM, [left, right], self.policy)
        self.assertEqual(report["status"], "findings", report)
        self.assertTrue(
            any("lookup" in pointer for finding in report["findings"] for pointer in finding.get("pointers", [])),
            report["findings"],
        )
        self.assertNotIn("1988-06-19", json.dumps(report))

    def test_cross_policy_masks_both_proof_leaves(self):
        policy = build_cross_flow_policy(_documents())
        paths = {field["path"] for field in policy["opaque_fields"]}
        self.assertEqual(
            paths,
            {
                "/vp_token/birth_date/0/proof",
                "/vp_token/birth_date/0/proof_b64",
            },
        )
        single = build_flow_policy(_documents()[0])
        self.assertEqual(single["opaque_fields"][0]["path"], "/vp_token/birth_date/0/proof_b64")


if __name__ == "__main__":
    unittest.main()

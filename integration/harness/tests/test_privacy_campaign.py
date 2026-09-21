"""Behavioral tests for generic privacy campaign analysis."""

from __future__ import annotations

import json
import unittest
from copy import deepcopy

import base64
from urllib.parse import quote

from privacy_campaign import CampaignError, MAX_DECODE_BYTES, analyze_campaign
from privacy_controls import control_cases


SCHEMA = "swiyu.privacy-traces.v1"
PROVIDER = {"id": "fixture.provider", "title": "Fixture Provider"}
SECRET = "SYNTHETIC-SECRET-CANARY-9f3a"


def _bundle(cases):
    return {"schema": SCHEMA, "provider": PROVIDER, "cases": cases}


def _record(**overrides):
    rec = {
        "id": "r1",
        "subject": "subject-a",
        "session": "sess-1",
        "scope": "scope-x",
        "public_context": {"audience": "verifier-1"},
        "expected_outcome": "ok",
        "outcome": "ok",
        "view": {"ok": True},
        "allowed_public": {},
    }
    rec.update(overrides)
    return rec


def _case(**overrides):
    case = {
        "id": "c1",
        "family": "disclosure",
        "relation": "secret_scan",
        "observer": "network",
        "runtime": "local",
        "evidence_kind": "integration",
        "records": [_record()],
        "secrets": [],
        "opaque_paths": [],
        "compare_paths": [],
    }
    case.update(overrides)
    return case


class TestPrivacyCampaignSecretScan(unittest.TestCase):
    def test_secret_in_subject_or_path_metadata_is_not_secret_free(self):
        report = analyze_campaign(
            _bundle(
                [
                    _case(
                        secrets=[{"label": "canary", "value": SECRET}],
                        opaque_paths=[f"/field-{SECRET}"],
                        records=[_record(subject=f"sub-{SECRET}", view={"ok": True})],
                    )
                ]
            )
        )
        self.assertEqual(report["privacy"]["status"], "findings")
        self.assertTrue(any(f["kind"] == "secret_disclosure" for f in report["privacy"]["findings"]))
        self.assertNotIn(SECRET, json.dumps(report))

    def test_detects_secret_inside_nested_base64url_jwt_segment(self):
        payload = json.dumps({"inner": SECRET}, separators=(",", ":"))
        seg = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
        token = f"eyJhbGciOiJub25lIn0.{seg}."
        bundle = _bundle(
            [
                _case(
                    secrets=[{"label": "canary", "value": SECRET}],
                    records=[
                        _record(
                            view={
                                "wrapper": {
                                    "token": token,
                                    "nested": {"note": "clean"},
                                }
                            }
                        )
                    ],
                )
            ]
        )
        report = analyze_campaign(bundle)
        self.assertEqual(report["schema"], "swiyu.privacy-campaign.v1")
        self.assertEqual(report["privacy"]["status"], "findings")
        kinds = [f["kind"] for f in report["privacy"]["findings"]]
        self.assertIn("secret_disclosure", kinds)
        blob = json.dumps(report)
        self.assertNotIn(SECRET, blob)
        self.assertNotIn("view", report["privacy"]["cases"][0])
        self.assertNotIn("secrets", report["privacy"]["cases"][0])

    def test_opaque_and_allowed_public_do_not_hide_secret_canaries(self):
        bundle = _bundle(
            [
                _case(
                    secrets=[{"label": "canary", "value": SECRET}],
                    opaque_paths=["/hidden"],
                    records=[
                        _record(
                            view={"hidden": SECRET, "aud": "public"},
                            allowed_public={"/aud": "public"},
                        )
                    ],
                )
            ]
        )
        report = analyze_campaign(bundle)
        self.assertEqual(report["privacy"]["status"], "findings")
        self.assertTrue(any(f["kind"] == "secret_disclosure" for f in report["privacy"]["findings"]))
        self.assertNotIn(SECRET, json.dumps(report))

    def test_oversized_encoded_presentation_is_not_silently_clean(self):
        secret = SECRET
        inner = json.dumps({"canary": secret})
        encoded = base64.urlsafe_b64encode((inner + "x" * MAX_DECODE_BYTES).encode()).decode()
        self.assertGreater(len(encoded), MAX_DECODE_BYTES)
        report = analyze_campaign(
            _bundle(
                [
                    _case(
                        secrets=[{"label": "canary", "value": secret}],
                        records=[_record(view={"presentation": encoded})],
                    )
                ]
            )
        )
        case = report["privacy"]["cases"][0]
        self.assertNotEqual(report["privacy"]["status"], "clean")
        self.assertNotEqual(case["status"], "clean")
        self.assertTrue(
            case.get("reason")
            or report["privacy"]["coverage"]["gaps"]
            or any(f["kind"] in {"decode_truncated", "decoder_limit"} for f in report["privacy"]["findings"])
        )
        method = report["privacy"]["method"].lower()
        self.assertTrue("16" in method or "decoder" in method or "limit" in method)
        self.assertNotIn(secret, json.dumps(report))

    def test_detects_url_and_hex_wrapped_secrets(self):
        hexed = SECRET.encode().hex()
        urled = quote(SECRET)
        bundle = _bundle(
            [
                _case(
                    id="hex",
                    secrets=[{"label": "canary", "value": SECRET}],
                    records=[_record(view={"h": hexed})],
                ),
                _case(
                    id="url",
                    secrets=[{"label": "canary", "value": SECRET}],
                    records=[_record(id="r2", view={"u": urled})],
                ),
            ]
        )
        report = analyze_campaign(bundle)
        self.assertEqual(len(report["privacy"]["findings"]), 2)


class TestPrivacyCampaignRelations(unittest.TestCase):
    def test_equivalent_ignores_opaque_randomized_proof_bytes(self):
        bundle = _bundle(
            [
                _case(
                    family="hidden_branch",
                    relation="equivalent",
                    opaque_paths=["/proof"],
                    records=[
                        _record(view={"ok": True, "proof": "aaa", "aud": "v"}, allowed_public={"/aud": "v"}),
                        _record(
                            id="r2",
                            session="sess-2",
                            view={"ok": True, "proof": "zzz", "aud": "v"},
                            allowed_public={"/aud": "v"},
                        ),
                    ],
                )
            ]
        )
        report = analyze_campaign(bundle)
        self.assertEqual(report["privacy"]["status"], "clean")

    def test_equivalent_flags_public_difference_not_provider_outcome(self):
        bundle = _bundle(
            [
                _case(
                    family="hidden_branch",
                    relation="equivalent",
                    records=[
                        _record(view={"branch": "A"}, outcome="ok"),
                        _record(id="r2", session="sess-2", view={"branch": "B"}, outcome="ok"),
                    ],
                )
            ]
        )
        report = analyze_campaign(bundle)
        self.assertEqual(report["privacy"]["status"], "findings")
        self.assertTrue(
            any(f["kind"] == "unexpected_public_difference" for f in report["privacy"]["findings"])
        )

    def test_does_not_trust_provider_outcome_when_expected_matches(self):
        bundle = _bundle(
            [
                _case(
                    family="hidden_branch",
                    relation="equivalent",
                    opaque_paths=["/proof"],
                    records=[
                        _record(
                            view={"ok": True, "proof": "a"},
                            expected_outcome="fail",
                            outcome="fail",
                        ),
                        _record(
                            id="r2",
                            session="sess-2",
                            view={"ok": True, "proof": "b"},
                            expected_outcome="fail",
                            outcome="fail",
                        ),
                    ],
                )
            ]
        )
        report = analyze_campaign(bundle)
        self.assertEqual(report["privacy"]["status"], "clean")

    def test_secret_scan_retains_expected_outcome_mismatch(self):
        report = analyze_campaign(
            _bundle(
                [
                    _case(
                        relation="secret_scan",
                        secrets=[{"label": "canary", "value": SECRET}],
                        records=[
                            _record(
                                view={"token": "no-canary-here"},
                                expected_outcome="ok",
                                outcome="denied",
                            )
                        ],
                    )
                ]
            )
        )
        self.assertEqual(report["privacy"]["status"], "findings")
        self.assertTrue(any(f["kind"] == "functional_difference" for f in report["privacy"]["findings"]))
        self.assertNotIn(SECRET, json.dumps(report))

    def test_redaction_does_not_echo_secret_through_label_or_field(self):
        report = analyze_campaign(
            _bundle(
                [
                    _case(
                        secrets=[{"label": f"label-{SECRET}", "value": SECRET}],
                        opaque_paths=[f"/field-{SECRET}"],
                        records=[_record(subject=f"sub-{SECRET}", view={"ok": True})],
                    )
                ]
            )
        )
        blob = json.dumps(report)
        self.assertEqual(report["privacy"]["status"], "findings")
        self.assertNotIn(SECRET, blob)
        self.assertTrue(any(f["kind"] == "secret_disclosure" for f in report["privacy"]["findings"]))

    def test_retains_expected_outcome_differences(self):
        bundle = _bundle(
            [
                _case(
                    family="failure_fallback",
                    relation="equivalent",
                    records=[
                        _record(view={"ok": True}, expected_outcome="ok"),
                        _record(
                            id="r2",
                            session="sess-2",
                            view={"ok": True},
                            expected_outcome="denied",
                            outcome="ok",
                        ),
                    ],
                )
            ]
        )
        kinds = [f["kind"] for f in analyze_campaign(bundle)["privacy"]["findings"]]
        self.assertIn("functional_difference", kinds)

    def test_unlinkable_flags_subject_specific_reuse_across_sessions(self):
        bundle = _bundle(
            [
                _case(
                    family="linkability",
                    relation="unlinkable",
                    records=[
                        _record(view={"tok": "id-a", "v": 1}),
                        _record(id="r2", session="sess-2", view={"tok": "id-a", "v": 2}),
                        _record(id="r3", subject="subject-b", session="sess-1", view={"tok": "id-b", "v": 1}),
                        _record(id="r4", subject="subject-b", session="sess-2", view={"tok": "id-b", "v": 2}),
                    ],
                )
            ]
        )
        report = analyze_campaign(bundle)
        self.assertEqual(report["privacy"]["status"], "findings")
        self.assertTrue(any(f["kind"] == "linkable_identifier" for f in report["privacy"]["findings"]))

    def test_unlinkable_without_subject_controls_is_inconclusive(self):
        bundle = _bundle(
            [
                _case(
                    family="linkability",
                    relation="unlinkable",
                    records=[
                        _record(view={"tok": "id-a"}),
                        _record(id="r2", session="sess-2", view={"tok": "id-a"}),
                    ],
                )
            ]
        )
        report = analyze_campaign(bundle)
        self.assertEqual(report["privacy"]["status"], "inconclusive")
        self.assertIn("cryptographic", report["privacy"]["method"])

    def test_scoped_stable_within_policy_scope_distinct_across(self):
        clean = _bundle(
            [
                _case(
                    family="scoped_identifier",
                    relation="scoped",
                    compare_paths=["/sid"],
                    records=[
                        _record(view={"sid": "A-x"}, scope="scope-x"),
                        _record(id="r2", session="sess-2", view={"sid": "A-x"}, scope="scope-x"),
                        _record(id="r3", session="sess-3", view={"sid": "A-y"}, scope="scope-y"),
                    ],
                )
            ]
        )
        self.assertEqual(analyze_campaign(clean)["privacy"]["status"], "clean")
        colliding = deepcopy(clean)
        colliding["cases"][0]["records"][2]["view"] = {"sid": "A-x"}
        self.assertEqual(analyze_campaign(colliding)["privacy"]["status"], "findings")

    def test_same_and_different_compare_paths(self):
        same = _bundle(
            [
                _case(
                    family="prepared_state",
                    relation="same",
                    compare_paths=["/id"],
                    records=[_record(view={"id": "p"}), _record(id="r2", session="s2", view={"id": "p"})],
                )
            ]
        )
        self.assertEqual(analyze_campaign(same)["privacy"]["status"], "clean")
        different = _bundle(
            [
                _case(
                    family="session_isolation",
                    relation="different",
                    compare_paths=["/nonce"],
                    records=[
                        _record(view={"nonce": "n1"}),
                        _record(id="r2", session="s2", view={"nonce": "n1"}),
                    ],
                )
            ]
        )
        self.assertEqual(analyze_campaign(different)["privacy"]["status"], "findings")

    def test_metrics_exploratory_only_and_requires_samples(self):
        recs = []
        for subject, base in (("subject-a", 10), ("subject-b", 400)):
            for i in range(8):
                recs.append(
                    _record(
                        id=f"{subject}-{i}",
                        subject=subject,
                        session=f"s{i}",
                        view={"n": i},
                        metrics={"duration_ms": base + i, "size_bytes": 20 + i},
                    )
                )
        interleaved = [recs[i // 2 + (0 if i % 2 == 0 else 8)] for i in range(16)]
        report = analyze_campaign(
            _bundle([_case(family="side_channel", relation="metrics", records=interleaved)])
        )
        self.assertEqual(report["privacy"]["status"], "findings")
        self.assertTrue(
            any(f["kind"] == "exploratory_distinguishability" for f in report["privacy"]["findings"])
        )
        self.assertIn("not a cryptographic", report["privacy"]["findings"][0]["detail"].lower())

    def test_empty_observation_does_not_pass(self):
        report = analyze_campaign(_bundle([_case(records=[_record(view={})])]))
        self.assertEqual(report["privacy"]["status"], "findings")
        self.assertTrue(any(f["kind"] == "empty_observation" for f in report["privacy"]["findings"]))

    def test_skip_reason_is_coverage_gap_not_clean(self):
        report = analyze_campaign(
            _bundle([_case(skip_reason="runtime cannot export traces", records=[])])
        )
        self.assertEqual(report["privacy"]["status"], "not_run")
        self.assertTrue(report["privacy"]["coverage"]["gaps"])
        self.assertEqual(report["privacy"]["cases"][0]["status"], "coverage_gap")

    def test_unknown_relation_rejected(self):
        with self.assertRaises(CampaignError):
            analyze_campaign(_bundle([_case(relation="telepathy")]))

    def test_json_pointer_escaping_roundtrip_on_secret_field(self):
        bundle = _bundle(
            [
                _case(
                    secrets=[{"label": "canary", "value": SECRET}],
                    records=[_record(view={"a/b": {"~c": SECRET}})],
                )
            ]
        )
        field = analyze_campaign(bundle)["privacy"]["findings"][0]["field"]
        self.assertEqual(field, "/a~1b/~0c")


class TestPrivacyCampaignControls(unittest.TestCase):
    def test_control_cases_cover_each_rule_without_inflating_integration(self):
        cases = control_cases()
        relations = {c["relation"] for c in cases}
        self.assertEqual(relations, {"secret_scan", "equivalent", "unlinkable", "scoped", "same", "different", "metrics"})
        self.assertTrue(any(c["id"].endswith("clean") for c in cases))
        self.assertTrue(any(c["id"].endswith("faulty") for c in cases))
        for case in cases:
            self.assertEqual(case["evidence_kind"], "control")
        report = analyze_campaign(_bundle(cases))
        self.assertEqual(report["privacy"]["status"], "not_run")
        self.assertEqual(report["privacy"]["findings"], [])
        self.assertEqual(report["privacy"]["coverage"]["cases"], [])
        controls = report["privacy"]["detector_controls"]
        by_id = {c["id"]: c for c in controls["cases"]}
        self.assertEqual(by_id["ctrl-secret-clean"]["status"], "clean")
        self.assertEqual(by_id["ctrl-secret-faulty"]["status"], "findings")
        self.assertEqual(by_id["ctrl-equivalent-clean"]["status"], "clean")
        self.assertEqual(by_id["ctrl-equivalent-faulty"]["status"], "findings")
        self.assertEqual(by_id["ctrl-unlinkable-clean"]["status"], "clean")
        self.assertEqual(by_id["ctrl-unlinkable-faulty"]["status"], "findings")
        self.assertEqual(by_id["ctrl-unlinkable-inadequate"]["status"], "inconclusive")
        self.assertEqual(by_id["ctrl-scoped-clean"]["status"], "clean")
        self.assertEqual(by_id["ctrl-scoped-faulty"]["status"], "findings")
        self.assertEqual(by_id["ctrl-same-clean"]["status"], "clean")
        self.assertEqual(by_id["ctrl-same-faulty"]["status"], "findings")
        self.assertEqual(by_id["ctrl-different-clean"]["status"], "clean")
        self.assertEqual(by_id["ctrl-different-faulty"]["status"], "findings")
        self.assertEqual(by_id["ctrl-metrics-clean"]["status"], "clean")
        self.assertEqual(by_id["ctrl-metrics-faulty"]["status"], "findings")
        for case in controls["cases"]:
            if case["id"].endswith("-clean"):
                want = "clean"
            elif case["id"].endswith("-faulty"):
                want = "findings"
            else:
                want = "inconclusive"
            self.assertEqual(case.get("expected_status"), want, case["id"])
            self.assertEqual(case["status"], want, case["id"])
        self.assertNotIn("SYNTHETIC-CTRL-SECRET-aa11", json.dumps(report))


if __name__ == "__main__":
    unittest.main()

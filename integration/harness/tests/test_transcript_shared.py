"""Shared-claim OID4VP campaign: EPFL d10 and OpenAC age-25 on one flow."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs

HARNESS = Path(__file__).resolve().parents[1]
SEMANTICS = Path(__file__).resolve().parents[2] / "semantics"
for path in (str(HARNESS), str(SEMANTICS)):
    if path not in sys.path:
        sys.path.insert(0, path)

from transcript_shared import SHARED_CLAIM_ID, run_shared_transcript_campaign

CLAIM = SEMANTICS / "claims" / "age25-holder-challenge.json"


class SharedTranscriptCampaignTests(unittest.TestCase):
    def test_fixture_only_clean_pair_and_injected_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "out"
            code, bundle = run_shared_transcript_campaign(
                str(CLAIM),
                str(output),
                fixture_only=True,
                injections=["hidden_field", "hash_header"],
            )
            self.assertEqual(code, 0, [c["kind"] + ":" + str(c["report"].get("status")) for c in bundle["campaigns"]])
            self.assertEqual(bundle["claim"], SHARED_CLAIM_ID)
            self.assertFalse(bundle["evidence_usable"])
            self.assertEqual(bundle["mode"], "fixture-only")
            kinds = {}
            for campaign in bundle["campaigns"]:
                kinds.setdefault(campaign["kind"], []).append(campaign["report"])
            self.assertEqual({report["status"] for report in kinds["baseline"]}, {"clean"})
            self.assertEqual({report["status"] for report in kinds["injected regression"]}, {"findings"})
            self.assertEqual(kinds["cross-implementation"][0]["status"], "clean", kinds["cross-implementation"][0])
            self.assertEqual(kinds["cross-implementation injected"][0]["status"], "findings")
            compared = [
                pair
                for pair in kinds["cross-implementation"][0]["pairs"]
                if pair.get("eligibility") == "compared"
            ]
            self.assertGreaterEqual(len(compared), 4)
            self.assertTrue(all(pair.get("status") == "equivalent" for pair in compared), compared)
            implementations = {
                session["implementation"]
                for session in bundle["sessions"]
            }
            self.assertEqual(
                implementations,
                {"epfl-d10-swiyu-jwt-age25-v0", "openac-age25-jwt-v0"},
            )
            self.assertGreaterEqual(len(bundle["sessions"]), 8)
            for session in bundle["sessions"]:
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
                create = json.loads(session["events"][0]["request"]["body"])
                zkp = create["dcql_query"]["credentials"][0]["x_swiyu_zkp"]
                self.assertEqual(zkp["now_date"], 20240101)
                self.assertNotIn("cutoff_date", zkp)
                self.assertNotIn("status_list_snapshot", zkp)
            injected = [session for session in bundle["sessions"] if session["campaign"].startswith("injected-")]
            cred = injected[0]["credential"]
            form = parse_qs(injected[0]["events"][2]["request"]["body"], keep_blank_values=True)
            self.assertEqual(form["x_swiyu_wallet_tag"][0], cred)
            public = json.loads((output / "report.json").read_text(encoding="utf-8"))
            dumped = json.dumps(public)
            self.assertNotIn(cred, dumped)
            self.assertTrue((output / "report.html").is_file())
            for session in public["sessions"]:
                self.assertNotIn("events", session)
                self.assertNotIn("credential", session)

    def test_rejects_a_backend_branded_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(Exception, "shared-claim campaign requires"):
                run_shared_transcript_campaign(
                    str(SEMANTICS / "claims" / "epfl-d10-age25-jwt.json"),
                    str(Path(tmp) / "out"),
                    fixture_only=True,
                )


if __name__ == "__main__":
    unittest.main()

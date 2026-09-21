"""CLI zkbench tests (T20 subset)."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ZKBENCH = os.path.join(ROOT, "zkbench.py")
PROVIDERS = os.path.abspath(os.path.join(ROOT, "..", "providers"))
STUB = os.path.join(PROVIDERS, "test-stub", "manifest.json")
SEMANTIC_REFERENCE = os.path.join(PROVIDERS, "semantic-reference", "manifest.json")
OPENAC = os.path.join(PROVIDERS, "openac", "manifest.json")
OPENAC_SUPPORT = os.path.join(PROVIDERS, "openac", "support.json")


class TestZkbench(unittest.TestCase):
    def _run(self, *args, timeout=30):
        return subprocess.run(
            [sys.executable, ZKBENCH, *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def test_check_valid(self):
        r = self._run("check", STUB)
        self.assertEqual(r.returncode, 0)
        self.assertIn("ok", r.stdout.lower())

    def test_demo_four_cases_exit_zero(self):
        out = tempfile.mkdtemp(prefix="zk-demo-")
        r = self._run("demo", "--output", out, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertTrue(os.path.isfile(os.path.join(out, "result.json")))
        self.assertTrue(os.path.isfile(os.path.join(out, "report.html")))
        with open(os.path.join(out, "result.json")) as f:
            data = json.load(f)
        names = [c["name"] for c in data["cases"]]
        self.assertEqual(
            names,
            ["valid_adult", "underage", "wrong_nonce", "wrong_audience"],
        )
        self.assertEqual(data["overall"], "passed")
        for case in data["cases"]:
            self.assertEqual(case["outcome"], "passed", case)
            self.assertIn("expected", case)
            self.assertIn("observed", case)
        self.assertNotIn("provider_crash", names)
        adult = next(c for c in data["cases"] if c["name"] == "valid_adult")
        self.assertEqual(adult["expected"], "verified=true")
        underage = next(c for c in data["cases"] if c["name"] == "underage")
        self.assertEqual(underage["expected"], "verified=false")
        timings = data["metrics"]["valid_adult_timings"]
        for key in (
            "provider_startup_ms",
            "initialize_ms",
            "prepare_ms",
            "present_ms",
            "verify_ms",
            "cleanup_ms",
        ):
            self.assertIn(key, timings)
        self.assertIn("illustrative", data["metrics"]["label"].lower())
        dumped = json.dumps(data)
        self.assertNotIn("2000-06-15", dumped)
        self.assertNotIn("alice", dumped)

    def test_demo_inject_crash_exits_one(self):
        out = tempfile.mkdtemp(prefix="zk-demo-inject-")
        r = self._run("demo", "--output", out, "--inject-crash", timeout=60)
        self.assertEqual(r.returncode, 1)
        with open(os.path.join(out, "result.json")) as f:
            data = json.load(f)
        self.assertEqual(data["overall"], "provider_error")
        names = [c["name"] for c in data["cases"]]
        self.assertEqual(
            names[:4],
            ["valid_adult", "underage", "wrong_nonce", "wrong_audience"],
        )
        self.assertIn("inject_crash", names)
        inject = next(c for c in data["cases"] if c["name"] == "inject_crash")
        self.assertEqual(inject["outcome"], "provider_error")

    def test_demo_rerun_same_output_dir(self):
        out = tempfile.mkdtemp(prefix="zk-demo-rerun-")
        r1 = self._run("demo", "--output", out, timeout=60)
        r2 = self._run("demo", "--output", out, timeout=60)
        self.assertEqual(r1.returncode, 0, r1.stderr)
        self.assertEqual(r2.returncode, 0, r2.stderr)

    def test_call_initialize(self):
        inp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump({}, inp)
        inp.close()
        r = self._run("call", STUB, "initialize", "--input", inp.name)
        os.unlink(inp.name)
        self.assertEqual(r.returncode, 0)
        body = json.loads(r.stdout)
        self.assertIn("profiles", body.get("result", body))

    def test_provider_run_writes_stable_json_and_html_report(self):
        out = tempfile.mkdtemp(prefix="zk-provider-run-")
        r = self._run(
            "provider-run", STUB, "--output", out, timeout=60
        )
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        result_path = os.path.join(out, "provider-report.json")
        html_path = os.path.join(out, "provider-report.html")
        self.assertTrue(os.path.isfile(result_path))
        self.assertTrue(os.path.isfile(html_path))
        with open(result_path, encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["schema"], "swiyu.provider-report.v1")
        self.assertEqual(data["provider"]["id"], "swiyu-test-stub")
        self.assertEqual(data["provider"]["profiles"], ["swiyu-test-age18-v0"])
        self.assertEqual(data["overall"], "passed")
        self.assertEqual(data["benchmark"]["schema"], "swiyu.benchmark.v1")
        self.assertEqual(data["leakage"]["status"], "not_run")
        with open(html_path, encoding="utf-8") as f:
            rendered = f.read()
        for heading in (
            "Provider",
            "Operation readiness",
            "Stage timings",
            "Artifact sizes",
            "Cases",
            "Benchmark",
            "Differential leakage",
        ):
            self.assertIn(heading, rendered)

    def test_provider_run_conformance_only_profile_is_not_run_not_failed(self):
        out = tempfile.mkdtemp(prefix="zk-provider-semantic-")
        r = self._run(
            "provider-run", SEMANTIC_REFERENCE, "--output", out, timeout=60
        )
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        with open(os.path.join(out, "provider-report.json"), encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["overall"], "not_run")
        self.assertEqual(data["operation_readiness"]["initialize"], "ready")
        self.assertEqual(data["cases"][0]["outcome"], "not_run")

    def test_provider_run_uses_declared_profile_fixture_for_custom_profile(self):
        root = tempfile.mkdtemp(prefix="zk-provider-fixture-")
        provider_path = os.path.join(root, "provider.py")
        with open(provider_path, "w", encoding="utf-8") as f:
            f.write(
                """
import json, sys
PROTOCOL = "swiyu.provider.v1"
handles = set()
for line in sys.stdin:
    req = json.loads(line)
    op = req["operation"]
    payload = req.get("payload") or {}
    result = {}
    if op == "initialize":
        result = {
            "profiles": ["fixture-profile-v0"],
            "operations": ["initialize", "prepare", "present", "verify", "cleanup"],
            "operationReadiness": {
                "initialize": {"status": "implemented"},
                "prepare": {"status": "implemented"},
                "present": {"status": "implemented"},
                "verify": {"status": "implemented"},
                "cleanup": {"status": "implemented"},
            },
        }
    elif op == "prepare":
        handles.add("h1")
        result = {"handle": "h1"}
    elif op == "present":
        if payload.get("handle") not in handles:
            print(json.dumps({"protocol": PROTOCOL, "id": req["id"], "status": "error", "error": {"code": "bad_handle", "message": "bad handle"}}), flush=True)
            continue
        result = {"presentation": "fixture-presentation-token", "artifact_sizes": {"witness": 123, "proof": 456}}
    elif op == "verify":
        result = {"verified": payload.get("request_context", {}).get("nonce") == "ok", "reason": None}
    elif op == "cleanup":
        handles.clear()
        result = {}
    print(json.dumps({"protocol": PROTOCOL, "id": req["id"], "status": "ok", "result": result}), flush=True)
"""
            )
        manifest = os.path.join(root, "manifest.json")
        with open(manifest, "w", encoding="utf-8") as f:
            json.dump({
                "schema": "swiyu.provider-manifest.v1",
                "id": "fixture-provider",
                "title": "Fixture Provider",
                "kind": "test-only",
                "profiles": ["fixture-profile-v0"],
                "command": [sys.executable, "provider.py"],
                "source": {"provider_run_fixture": "fixture.json"},
            }, f)
        with open(os.path.join(root, "fixture.json"), "w", encoding="utf-8") as f:
            json.dump({
                "schema": "swiyu.provider-run-fixture.v1",
                "profile": "fixture-profile-v0",
                "prepare": {"profile": "fixture-profile-v0", "credential": {"format": "test", "data": "cred"}, "context": {}},
                "present": {"profile": "fixture-profile-v0", "request_context": {"nonce": "ok"}, "inputs": {}},
                "verify": {"profile": "fixture-profile-v0", "request_context": {"nonce": "ok"}, "inputs": {}},
                "negative_verify": {
                    "name": "tampered_challenge",
                    "payload": {"profile": "fixture-profile-v0", "request_context": {"nonce": "bad"}, "inputs": {}},
                    "expected_verified": False
                }
            }, f)
        out = os.path.join(root, "report")
        r = self._run("provider-run", manifest, "--output", out, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        with open(os.path.join(out, "provider-report.json"), encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["overall"], "passed")
        self.assertEqual(data["cases"][0]["name"], "fixture_lifecycle")
        self.assertEqual(data["cases"][0]["outcome"], "passed")
        self.assertEqual(data["cases"][1]["name"], "tampered_challenge")
        self.assertEqual(data["cases"][1]["outcome"], "passed")
        self.assertEqual(data["benchmark"]["stages"]["present"]["status"], "completed")
        self.assertEqual(data["benchmark"]["stages"]["verify"]["status"], "completed")
        self.assertEqual(data["benchmark"]["stages"]["witness"]["status"], "covered_by_present")
        self.assertEqual(data["benchmark"]["stages"]["prove"]["status"], "covered_by_present")
        self.assertEqual(data["artifacts"]["sizes_bytes"]["witness"], 123)
        self.assertEqual(data["artifacts"]["sizes_bytes"]["proof"], 456)

    def _mutated_openac_support(self, mutate):
        temp = tempfile.TemporaryDirectory(prefix="zk-openac-support-")
        self.addCleanup(temp.cleanup)
        # Preserve repository-relative artifact paths inside the temporary tree.
        root = os.path.join(temp.name, "integration", "providers", "openac")
        source_root = os.path.join(PROVIDERS, "openac")
        support_source = os.path.join(source_root, "support.json")
        with open(support_source, encoding="utf-8") as f:
            support = json.load(f)
        pinned = {pin["path"] for pin in support.get("artifact_pins", [])}
        for name in {"support.json", *pinned}:
            src = os.path.join(source_root, name)
            dst = os.path.join(root, name)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(src, encoding="utf-8") as fsrc, open(dst, "w", encoding="utf-8") as fdst:
                fdst.write(fsrc.read())
        support_path = os.path.join(root, "support.json")
        mutate(support)
        with open(support_path, "w", encoding="utf-8") as f:
            json.dump(support, f)
        return support_path

    def test_provider_run_validates_supplied_semantic_support(self):
        out = tempfile.mkdtemp(prefix="zk-provider-support-")
        r = self._run(
            "provider-run", OPENAC, "--support", OPENAC_SUPPORT, "--output", out, timeout=60
        )
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        with open(os.path.join(out, "provider-report.json"), encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["overall"], "not_run")
        self.assertEqual(data["support"]["status"], "passed")
        self.assertEqual(data["support"]["claims"][0]["id"], "swiyu.openac.age18-status-2k.v0")
        self.assertEqual(data["support"]["claims"][0]["profile_status"], "matched")
        self.assertEqual(data["support"]["claims"][0]["circuit_status"], "matched")
        self.assertIn("unavailable: ARTIFACTS_MISSING", data["operation_readiness"]["present"])
        self.assertIn("unavailable: ARTIFACTS_MISSING", data["operation_readiness"]["verify"])
        with open(os.path.join(out, "provider-report.html"), encoding="utf-8") as f:
            rendered = f.read()
        self.assertIn("Semantic support", rendered)
        self.assertIn("swiyu.openac.age18-status-2k.v0", rendered)

    def test_provider_run_fails_when_support_digest_is_stale(self):
        support_path = self._mutated_openac_support(
            lambda support: support["supported_claims"][0].update({"statement_digest": "0" * 64})
        )
        out = tempfile.mkdtemp(prefix="zk-provider-stale-support-")
        r = self._run(
            "provider-run", OPENAC, "--support", support_path, "--output", out, timeout=60
        )
        self.assertEqual(r.returncode, 1, r.stderr + r.stdout)
        with open(os.path.join(out, "provider-report.json"), encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["overall"], "failed")
        self.assertEqual(data["support"]["status"], "failed")
        self.assertIn("statement_digest", data["support"]["claims"][0]["detail"])

    def test_provider_run_fails_when_support_circuit_is_not_in_manifest(self):
        support_path = self._mutated_openac_support(
            lambda support: support["supported_claims"][0].update({"circuit": "wrong_circuit"})
        )
        out = tempfile.mkdtemp(prefix="zk-provider-wrong-circuit-")
        r = self._run(
            "provider-run", OPENAC, "--support", support_path, "--output", out, timeout=60
        )
        self.assertEqual(r.returncode, 1, r.stderr + r.stdout)
        with open(os.path.join(out, "provider-report.json"), encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["overall"], "failed")
        self.assertEqual(data["support"]["claims"][0]["circuit_status"], "circuit_not_in_manifest")

    def test_provider_run_records_launch_error_in_both_reports(self):
        root = tempfile.mkdtemp(prefix="zk-provider-error-")
        manifest = os.path.join(root, "manifest.json")
        with open(manifest, "w", encoding="utf-8") as f:
            json.dump({
                "schema": "swiyu.provider-manifest.v1",
                "id": "broken-provider",
                "title": "Broken Provider",
                "kind": "test-only",
                "profiles": ["broken-v0"],
                "command": ["definitely-not-a-real-provider-command"],
            }, f)
        out = os.path.join(root, "report")
        r = self._run("provider-run", manifest, "--output", out)
        self.assertEqual(r.returncode, 1)
        with open(os.path.join(out, "provider-report.json"), encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["overall"], "provider_error")
        self.assertEqual(data["provider"]["id"], "broken-provider")
        self.assertEqual(data["cases"][-1]["outcome"], "provider_error")
        with open(os.path.join(out, "provider-report.html"), encoding="utf-8") as f:
            rendered = f.read()
        self.assertIn("Broken Provider", rendered)
        self.assertIn("provider_error", rendered)

    def test_provider_run_imports_existing_claim_privacy_summary(self):
        root = tempfile.mkdtemp(prefix="zk-provider-privacy-")
        privacy_path = os.path.join(root, "claim-report.json")
        with open(privacy_path, "w", encoding="utf-8") as f:
            json.dump({"privacy": {
                "status": "findings",
                "summary": "Compared provider outputs and ran detector controls.",
                "findings": [{"kind": "direct_disclosure", "field": "birthdate"}],
                "pairs": [{"status": "inconclusive"}],
                "coverage": {"executed": 2, "total": 2},
                "detector_controls": [{"name": "clear_birthdate", "status": "passed"}],
                "matrix": {"real_variants": 2, "eligible_pairs": 1},
            }}, f)
        out = os.path.join(root, "report")
        r = self._run(
            "provider-run", STUB, "--output", out,
            "--privacy-report", privacy_path, timeout=60,
        )
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        with open(os.path.join(out, "provider-report.json"), encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["leakage"]["status"], "findings")
        self.assertEqual(data["leakage"]["summary"], "Compared provider outputs and ran detector controls.")
        self.assertEqual(data["leakage"]["findings"][0]["field"], "birthdate")
        self.assertEqual(data["leakage"]["detector_controls"][0]["name"], "clear_birthdate")
        self.assertEqual(data["leakage"]["matrix"]["eligible_pairs"], 1)
        self.assertEqual(data["leakage"]["source_path"], privacy_path)


if __name__ == "__main__":
    unittest.main()

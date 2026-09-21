"""Tests for semantics CLI."""

import json
import math
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from semantics.evaluate import evaluate
from semantics.vectors import PUBLIC_VECTORS

ROOT = Path(__file__).resolve().parents[1]


class TestCLI(unittest.TestCase):
    def run_cli(self, *args, **kwargs):
        return subprocess.run(
            [sys.executable, "-m", "semantics.cli", *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            **kwargs,
        )

    def test_check_passes(self):
        proc = self.run_cli("check")
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_evaluate_from_stdin(self):
        payload = {
            "predicate": "age-at-least.v1",
            "private_inputs": {"birthdate": "1990-01-01"},
            "parameters": {"reference_date": "2020-01-01", "min_age": 18},
        }
        proc = self.run_cli("evaluate", input=json.dumps(payload))
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout), {"status": "ok", "value": True})

    def test_vectors_outputs_corpus(self):
        proc = self.run_cli("vectors")
        self.assertEqual(proc.returncode, 0)
        corpus = json.loads(proc.stdout)
        self.assertIn("vectors", corpus)
        self.assertTrue(len(corpus["vectors"]) >= 5)
        self.assertIn("invented", corpus.get("note", "").lower())
        for item in corpus["vectors"]:
            self.assertIn("expected", item)
            self.assertIn("private_inputs", item)
            self.assertIn("birthdate", item["private_inputs"])

    def test_vectors_roundtrip_matches_manual_expected(self):
        proc = self.run_cli("vectors")
        self.assertEqual(proc.returncode, 0)
        corpus = json.loads(proc.stdout)
        by_id = {v["id"]: v for v in corpus["vectors"]}
        for fixture in PUBLIC_VECTORS:
            exported = by_id[fixture["id"]]
            result = evaluate(
                exported["predicate"],
                exported["private_inputs"],
                exported["parameters"],
            )
            self.assertEqual(
                result,
                fixture["expected"],
                msg=f"roundtrip failed for {fixture['id']}",
            )

    def test_evaluate_malformed_json(self):
        proc = self.run_cli("evaluate", input="{not json")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(json.loads(proc.stdout), {"status": "invalid_input"})
        self.assertNotIn("Traceback", proc.stderr)

    def test_evaluate_duplicate_keys(self):
        proc = self.run_cli(
            "evaluate",
            input='{"predicate":"age-at-least.v1","predicate":"dup","private_inputs":{},"parameters":{}}',
        )
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(json.loads(proc.stdout), {"status": "invalid_input"})

    def test_evaluate_null_root(self):
        proc = self.run_cli("evaluate", input="null")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(json.loads(proc.stdout), {"status": "invalid_input"})

    def test_evaluate_non_object_payload(self):
        proc = self.run_cli("evaluate", input="[]")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(json.loads(proc.stdout), {"status": "invalid_input"})

    def test_evaluate_nonfinite_json(self):
        proc = self.run_cli(
            "evaluate",
            input=json.dumps(
                {
                    "predicate": "age-at-least.v1",
                    "private_inputs": {"birthdate": "1990-01-01"},
                    "parameters": {
                        "reference_date": "2020-01-01",
                        "min_age": math.nan,
                    },
                }
            ),
        )
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(json.loads(proc.stdout), {"status": "invalid_input"})

    def test_evaluate_missing_file_safe_error(self):
        proc = self.run_cli("evaluate", "--input", "/nonexistent/payload.json")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(json.loads(proc.stdout), {"status": "invalid_input"})
        self.assertNotIn("/nonexistent", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

    def test_evaluate_extra_root_key_rejected(self):
        proc = self.run_cli(
            "evaluate",
            input=json.dumps(
                {
                    "predicate": "age-at-least.v1",
                    "private_inputs": {"birthdate": "1990-01-01"},
                    "parameters": {"reference_date": "2020-01-01", "min_age": 18},
                    "extra": None,
                }
            ),
        )
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(json.loads(proc.stdout), {"status": "invalid_input"})

    def test_evaluate_from_file(self):
        payload = {
            "predicate": "age-at-least.v1",
            "private_inputs": {"birthdate": "1990-01-01"},
            "parameters": {"reference_date": "2020-01-01", "min_age": 18},
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(payload, f)
            path = f.name
        proc = self.run_cli("evaluate", "--input", path)
        Path(path).unlink()
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout), {"status": "ok", "value": True})


if __name__ == "__main__":
    unittest.main()

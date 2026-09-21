"""Adversarial ProviderClient and report tests (T06/T19/T55 subset)."""
import json
import os
import sys
import tempfile
import time
import unittest

from manifest import ManifestError, load_manifest
from provider_client import ProviderClient, ProviderError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestAdversarial(unittest.TestCase):
    def _write_bad_provider(self, script_body: str) -> str:
        d = tempfile.mkdtemp(prefix="zk-bad-prov-")
        manifest = {
            "schema": "swiyu.provider-manifest.v1",
            "id": "bad-provider",
            "title": "Bad Provider",
            "kind": "test-only",
            "profiles": ["p"],
            "command": [sys.executable, "provider.py"],
        }
        with open(os.path.join(d, "manifest.json"), "w") as f:
            json.dump(manifest, f)
        with open(os.path.join(d, "provider.py"), "w") as f:
            f.write(script_body)
        return os.path.join(d, "manifest.json")

    def test_nonmatching_response_id(self):
        script = '''import sys
for line in sys.stdin:
    import json
    req = json.loads(line)
    sys.stdout.write(json.dumps({"protocol":"swiyu.provider.v1","id":"wrong","status":"ok","result":{}})+"\\n")
    sys.stdout.flush()
'''
        with ProviderClient(self._write_bad_provider(script), timeout=2.0) as client:
            with self.assertRaises(ProviderError) as ctx:
                client.call("initialize", {})
            self.assertIn("id", ctx.exception.code.lower() + ctx.exception.message.lower())

    def test_malformed_json_response(self):
        script = '''import sys
for line in sys.stdin:
    sys.stdout.write("not json\\n")
    sys.stdout.flush()
'''
        with ProviderClient(self._write_bad_provider(script), timeout=2.0) as client:
            with self.assertRaises(ProviderError):
                client.call("initialize", {})

    def test_premature_exit(self):
        script = "import sys; sys.exit(1)\n"
        with self.assertRaises(ProviderError) as ctx:
            with ProviderClient(self._write_bad_provider(script), timeout=2.0) as client:
                client.call("initialize", {})
        self.assertEqual(ctx.exception.code, "crashed")

    def test_duplicate_response_status_rejected(self):
        script = '''import sys, json
for line in sys.stdin:
    req = json.loads(line)
    sys.stdout.write('{"protocol":"swiyu.provider.v1","id":"%s","status":"error","status":"ok","result":{}}\\n' % req["id"])
    sys.stdout.flush()
'''
        with ProviderClient(self._write_bad_provider(script), timeout=2.0) as client:
            with self.assertRaises(ProviderError):
                client.call("initialize", {})

    def test_verified_string_rejected(self):
        script = '''import sys, json
for line in sys.stdin:
    req = json.loads(line)
    sys.stdout.write(json.dumps({"protocol":"swiyu.provider.v1","id":req["id"],"status":"ok","result":{"verified":"false"}})+"\\n")
    sys.stdout.flush()
'''
        with ProviderClient(self._write_bad_provider(script), timeout=2.0) as client:
            with self.assertRaises(ProviderError) as ctx:
                client.call("verify", {})
            self.assertEqual(ctx.exception.code, "malformed")
            with self.assertRaises(ProviderError) as ctx2:
                client.call("initialize", {})
            self.assertEqual(ctx2.exception.code, "state")

    def test_no_newline_stdout_limit(self):
        script = """import sys, time
sys.stdout.write("x" * 200000)
sys.stdout.flush()
time.sleep(30)
"""
        with ProviderClient(self._write_bad_provider(script), timeout=1.5,
                            max_output_bytes=1024) as client:
            with self.assertRaises(ProviderError) as ctx:
                client.call("initialize", {})
            self.assertEqual(ctx.exception.code, "limit")

    def test_oversized_response(self):
        script = '''import sys, json
for line in sys.stdin:
    req = json.loads(line)
    big = "x" * 200000
    sys.stdout.write(json.dumps({"protocol":"swiyu.provider.v1","id":req["id"],"status":"ok","result":{"data":big}})+"\\n")
    sys.stdout.flush()
'''
        with ProviderClient(self._write_bad_provider(script), timeout=2.0,
                            max_output_bytes=1024) as client:
            with self.assertRaises(ProviderError) as ctx:
                client.call("initialize", {})
            self.assertIn("limit", ctx.exception.message.lower())

    def test_wrong_protocol_version(self):
        script = '''import sys, json
for line in sys.stdin:
    req = json.loads(line)
    sys.stdout.write(json.dumps({"protocol":"swiyu.provider.v0","id":req["id"],"status":"ok","result":{}})+"\\n")
    sys.stdout.flush()
'''
        with ProviderClient(self._write_bad_provider(script), timeout=2.0) as client:
            with self.assertRaises(ProviderError):
                client.call("initialize", {})

    def test_stdin_write_times_out(self):
        script = "import time; time.sleep(60)\n"
        t0 = time.monotonic()
        with self.assertRaises(ProviderError) as ctx:
            with ProviderClient(
                self._write_bad_provider(script), timeout=1.0
            ) as client:
                client.call("initialize", {"pad": "x" * 200000})
        self.assertLess(time.monotonic() - t0, 6.0)
        self.assertEqual(ctx.exception.code, "timeout")

    def test_valid_error_envelope(self):
        script = '''import sys, json
for line in sys.stdin:
    req = json.loads(line)
    sys.stdout.write(json.dumps({"protocol":"swiyu.provider.v1","id":req["id"],"status":"error","error":{"code":"bad_input","message":"nope"}})+"\\n")
    sys.stdout.flush()
'''
        with ProviderClient(self._write_bad_provider(script), timeout=2.0) as client:
            with self.assertRaises(ProviderError) as ctx:
                client.call("initialize", {})
            self.assertEqual(ctx.exception.code, "bad_input")
            self.assertEqual(ctx.exception.status, "error")
            with self.assertRaises(ProviderError) as ctx2:
                client.call("cleanup", {})
            self.assertEqual(ctx2.exception.code, "bad_input")

    def test_invalid_error_envelope_invalidates(self):
        script = '''import sys, json
for line in sys.stdin:
    req = json.loads(line)
    sys.stdout.write(json.dumps({"protocol":"swiyu.provider.v1","id":req["id"],"status":"error","error":{"code":""}})+"\\n")
    sys.stdout.flush()
'''
        with ProviderClient(self._write_bad_provider(script), timeout=2.0) as client:
            with self.assertRaises(ProviderError) as ctx:
                client.call("initialize", {})
            self.assertEqual(ctx.exception.code, "malformed")
            with self.assertRaises(ProviderError) as ctx2:
                client.call("initialize", {})
            self.assertEqual(ctx2.exception.code, "state")

    def test_missing_id_invalidates(self):
        script = '''import sys, json
for line in sys.stdin:
    sys.stdout.write(json.dumps({"protocol":"swiyu.provider.v1","status":"ok","result":{}})+"\\n")
    sys.stdout.flush()
'''
        with ProviderClient(self._write_bad_provider(script), timeout=2.0) as client:
            with self.assertRaises(ProviderError):
                client.call("initialize", {})
            with self.assertRaises(ProviderError) as ctx:
                client.call("initialize", {})
            self.assertEqual(ctx.exception.code, "state")

    def test_unknown_status_invalidates(self):
        script = '''import sys, json
for line in sys.stdin:
    req = json.loads(line)
    sys.stdout.write(json.dumps({"protocol":"swiyu.provider.v1","id":req["id"],"status":"weird","result":{}})+"\\n")
    sys.stdout.flush()
'''
        with ProviderClient(self._write_bad_provider(script), timeout=2.0) as client:
            with self.assertRaises(ProviderError) as ctx:
                client.call("initialize", {})
            self.assertEqual(ctx.exception.code, "malformed")
            with self.assertRaises(ProviderError) as ctx2:
                client.call("initialize", {})
            self.assertEqual(ctx2.exception.code, "state")

    def test_nan_json_rejected(self):
        script = '''import sys, json
for line in sys.stdin:
    req = json.loads(line)
    sys.stdout.write('{"protocol":"swiyu.provider.v1","id":"%s","status":"ok","result":{"n":NaN}}\\n' % req["id"])
    sys.stdout.flush()
'''
        with ProviderClient(self._write_bad_provider(script), timeout=2.0) as client:
            with self.assertRaises(ProviderError) as ctx:
                client.call("initialize", {})
            self.assertEqual(ctx.exception.code, "malformed")

    def test_prepare_handle_must_be_nonempty_string(self):
        script = '''import sys, json
for line in sys.stdin:
    req = json.loads(line)
    sys.stdout.write(json.dumps({"protocol":"swiyu.provider.v1","id":req["id"],"status":"ok","result":{"handle":""}})+"\\n")
    sys.stdout.flush()
'''
        with ProviderClient(self._write_bad_provider(script), timeout=2.0) as client:
            with self.assertRaises(ProviderError) as ctx:
                client.call("prepare", {})
            self.assertEqual(ctx.exception.code, "malformed")

    def test_present_presentation_must_be_string(self):
        script = '''import sys, json
for line in sys.stdin:
    req = json.loads(line)
    sys.stdout.write(json.dumps({"protocol":"swiyu.provider.v1","id":req["id"],"status":"ok","result":{"presentation":1}})+"\\n")
    sys.stdout.flush()
'''
        with ProviderClient(self._write_bad_provider(script), timeout=2.0) as client:
            with self.assertRaises(ProviderError) as ctx:
                client.call("present", {})
            self.assertEqual(ctx.exception.code, "malformed")

    def test_unknown_operation_may_be_unsupported(self):
        script = '''import sys, json
for line in sys.stdin:
    req = json.loads(line)
    sys.stdout.write(json.dumps({"protocol":"swiyu.provider.v1","id":req["id"],"status":"unsupported","error":{"code":"unknown_operation","message":req["operation"]}})+"\\n")
    sys.stdout.flush()
'''
        with ProviderClient(self._write_bad_provider(script), timeout=2.0) as client:
            with self.assertRaises(ProviderError) as ctx:
                client.call("not_a_real_op", {})
            self.assertEqual(ctx.exception.status, "unsupported")

    def test_broken_protocol_skips_long_cleanup(self):
        script = '''import sys, json, time
n = 0
for line in sys.stdin:
    n += 1
    req = json.loads(line)
    if n == 1:
        sys.stdout.write(json.dumps({"protocol":"swiyu.provider.v1","id":req["id"],"status":"ok","result":{"verified":"true"}})+"\\n")
        sys.stdout.flush()
    else:
        time.sleep(30)
'''
        t0 = time.monotonic()
        with ProviderClient(self._write_bad_provider(script), timeout=5.0) as client:
            with self.assertRaises(ProviderError):
                client.call("verify", {})
        self.assertLess(time.monotonic() - t0, 2.0)

    def test_sentinel_grandchild_flag_not_deleted(self):
        d = tempfile.mkdtemp(prefix="zk-sentinel-")
        flag = os.path.join(d, "grandchild-x.flag")
        with open(flag, "w", encoding="utf-8") as f:
            f.write("999999999\n")
        manifest = {
            "schema": "swiyu.provider-manifest.v1",
            "id": "sentinel",
            "title": "sentinel",
            "kind": "test-only",
            "profiles": ["p"],
            "command": [sys.executable, "-c", "import sys; sys.exit(1)"],
        }
        path = os.path.join(d, "manifest.json")
        with open(path, "w") as f:
            json.dump(manifest, f)
        with self.assertRaises(ProviderError):
            with ProviderClient(path, timeout=2.0) as client:
                client.call("initialize", {})
        self.assertTrue(os.path.isfile(flag), "sentinel grandchild-x.flag must stay intact")
        with open(flag, encoding="utf-8") as f:
            self.assertEqual(f.read().strip(), "999999999")

    def test_same_session_grandchild_dead_and_silent_after_cleanup(self):
        d = tempfile.mkdtemp(prefix="zk-gc-")
        pidfile = os.path.join(d, "child.pid")
        logfile = os.path.join(d, "child.log")
        script = f'''import os, sys, time
pid = os.fork()
if pid == 0:
    with open({pidfile!r}, "w") as f:
        f.write(str(os.getpid()))
    while True:
        with open({logfile!r}, "a") as f:
            f.write("tick\\n")
        time.sleep(0.05)
for line in sys.stdin:
    time.sleep(30)
'''
        path = self._write_bad_provider(script)
        with ProviderClient(path, timeout=1.0) as client:
            try:
                client.call("initialize", {})
            except ProviderError:
                pass
        deadline = time.monotonic() + 2.0
        pid = None
        while time.monotonic() < deadline:
            if os.path.isfile(pidfile):
                with open(pidfile, encoding="utf-8") as f:
                    raw = f.read().strip()
                if raw.isdigit():
                    pid = int(raw)
                    break
            time.sleep(0.05)
        self.assertIsNotNone(pid, "grandchild should have recorded pid before kill")
        time.sleep(0.2)
        with self.assertRaises(OSError):
            os.kill(pid, 0)
        size = os.path.getsize(logfile) if os.path.isfile(logfile) else 0
        time.sleep(0.25)
        size2 = os.path.getsize(logfile) if os.path.isfile(logfile) else 0
        self.assertEqual(size, size2, "grandchild must not write after cleanup")

    def test_leader_exited_group_still_killed(self):
        d = tempfile.mkdtemp(prefix="zk-leader-")
        pidfile = os.path.join(d, "child.pid")
        logfile = os.path.join(d, "child.log")
        script = f'''import os, sys, time
pid = os.fork()
if pid == 0:
    with open({pidfile!r}, "w") as f:
        f.write(str(os.getpid()))
    while True:
        with open({logfile!r}, "a") as f:
            f.write("tick\\n")
        time.sleep(0.05)
os._exit(0)
'''
        path = self._write_bad_provider(script)
        with self.assertRaises(ProviderError):
            with ProviderClient(path, timeout=2.0) as client:
                client.call("initialize", {})
        deadline = time.monotonic() + 2.0
        pid = None
        while time.monotonic() < deadline:
            if os.path.isfile(pidfile):
                with open(pidfile, encoding="utf-8") as f:
                    raw = f.read().strip()
                if raw.isdigit():
                    pid = int(raw)
                    break
            time.sleep(0.05)
        self.assertIsNotNone(pid)
        time.sleep(0.2)
        with self.assertRaises(OSError):
            os.kill(pid, 0)
        size = os.path.getsize(logfile) if os.path.isfile(logfile) else 0
        time.sleep(0.25)
        size2 = os.path.getsize(logfile) if os.path.isfile(logfile) else 0
        self.assertEqual(size, size2)

    def test_request_size_cap(self):
        script = '''import sys, json
for line in sys.stdin:
    req = json.loads(line)
    sys.stdout.write(json.dumps({"protocol":"swiyu.provider.v1","id":req["id"],"status":"ok","result":{}})+"\\n")
    sys.stdout.flush()
'''
        with ProviderClient(self._write_bad_provider(script), timeout=2.0, max_input_bytes=64) as client:
            with self.assertRaises(ProviderError) as ctx:
                client.call("initialize", {"pad": "x" * 1000})
            self.assertEqual(ctx.exception.code, "limit")

    def test_duplicate_manifest_bad_fields(self):
        path = os.path.join(ROOT, "tests", "fixtures", "bad_manifests", "empty_id.json")
        with open(path, "w") as f:
            json.dump({
                "schema": "swiyu.provider-manifest.v1",
                "id": "",
                "title": "x",
                "kind": "test-only",
                "profiles": ["p"],
                "command": ["true"],
            }, f)
        with self.assertRaises(ManifestError):
            load_manifest(path)


if __name__ == "__main__":
    unittest.main()

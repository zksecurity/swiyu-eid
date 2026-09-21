import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from transcript_local import _wait_ready, _stop_process
class LocalRuntimeTests(unittest.TestCase):
    def test_failed_runtime_is_detected_before_campaign(self):
        with tempfile.TemporaryDirectory() as d:
            proc=subprocess.Popen([sys.executable,'-c','raise SystemExit(3)'],start_new_session=True)
            proc.wait()
            with self.assertRaises(RuntimeError): _wait_ready(proc,Path(d)/'ready.json',timeout=1)
    def test_owned_runtime_is_stopped(self):
        proc=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],start_new_session=True)
        _stop_process(proc)
        self.assertIsNotNone(proc.poll())
    def test_ready_file_is_parsed(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'ready.json';path.write_text(json.dumps({'url':'http://127.0.0.1:9999/verify'}))
            proc=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],start_new_session=True)
            try:self.assertIn('url',_wait_ready(proc,path,timeout=1))
            finally:_stop_process(proc)
    def test_non_loopback_ready_url_is_rejected(self):
        from transcript_local import require_loopback_http_url
        with self.assertRaises(ValueError):
            require_loopback_http_url('http://evil.example/verify')
        self.assertEqual(
            require_loopback_http_url('http://127.0.0.1:9/verify'),
            'http://127.0.0.1:9/verify',
        )
    def test_runtime_log_symlink_is_rejected(self):
        from transcript_local import export_runtime_logs
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'out';out.mkdir()
            scratch=Path(d)/'scratch';scratch.mkdir()
            log=scratch/'sidecar.log';log.write_text('ok')
            planted=out/'runtime-logs'
            planted.symlink_to(scratch)
            with self.assertRaises(ValueError):
                export_runtime_logs(out,[log])
    def test_qualify_local_report_updates_sanitized_disk_not_raw_sessions(self):
        from transcript_local import qualify_local_report
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)
            public={'schema':'swiyu.transcript-campaign-bundle.v1','provider':'example-sidecar','qualification':'stale','sessions':[{'id':'public'}]}
            (out/'report.json').write_text(json.dumps(public))
            (out/'report.html').write_text('<html>stale</html>')
            bundle={'provider':'example-sidecar','qualification':'stale','sessions':[{'id':'SECRET-RAW-SESSION','events':[{'body':'SECRET-WIRE'}]}]}
            returned=qualify_local_report(out,bundle)
            disk=json.loads((out/'report.json').read_text())
            html=(out/'report.html').read_text()
            self.assertIs(returned,bundle)
            self.assertIn('Java production controllers',returned['qualification'])
            self.assertIn('JDK HTTP adapter',returned['qualification'])
            self.assertIn('memory repository',returned['qualification'])
            self.assertIn('local signed request objects',returned['qualification'])
            self.assertIn('preprovisioned issuer/status',returned['qualification'])
            self.assertIn('Provider-generated proofs',returned['qualification'])
            self.assertIn('example-sidecar',returned['qualification'])
            self.assertNotIn('OpenAC',returned['qualification'])
            self.assertIn('Not full Spring dispatch',returned['qualification'])
            self.assertIn('BeanValidation',returned['qualification'])
            self.assertIn('deployment filters',returned['qualification'])
            self.assertIn('Android',returned['qualification'])
            self.assertIn('TLS',returned['qualification'])
            self.assertIn('live authority',returned['qualification'])
            self.assertEqual(disk['qualification'],returned['qualification'])
            self.assertEqual(disk['sessions'],[{'id':'public'}])
            self.assertNotIn('SECRET-RAW-SESSION',(out/'report.json').read_text())
            self.assertNotIn('SECRET-WIRE',html)
            self.assertIn('Java production controllers',html)
if __name__=='__main__':unittest.main()

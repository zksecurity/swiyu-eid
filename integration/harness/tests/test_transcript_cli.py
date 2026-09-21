import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
CLI=Path(__file__).resolve().parents[1]/'zkbench.py'
CLAIM=Path(__file__).resolve().parents[2]/'semantics'/'claims'/'age25-holder-challenge.json'
class TranscriptCliTests(unittest.TestCase):
    def test_selected_flow_is_available_on_provider_run(self):
        r=subprocess.run([sys.executable,str(CLI),'provider-run','--help'],capture_output=True,text=True)
        self.assertEqual(r.returncode,0)
        self.assertIn('--flow',r.stdout)
        self.assertIn('--claim',r.stdout)
    def test_selected_flow_requires_claim_before_starting_provider(self):
        r=subprocess.run([sys.executable,str(CLI),'provider-run','missing.json','--flow','oid4vp','--output','/unused'],capture_output=True,text=True)
        self.assertEqual(r.returncode,2)
        self.assertIn('--claim',r.stderr)
    def test_shared_claim_run_is_available(self):
        r=subprocess.run([sys.executable,str(CLI),'shared-claim-run','--help'],capture_output=True,text=True)
        self.assertEqual(r.returncode,0)
        self.assertIn('--fixture-only',r.stdout)
        self.assertIn('--claim',r.stdout)
    def test_shared_claim_run_fixture_only_writes_a_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            r=subprocess.run(
                [sys.executable,str(CLI),'shared-claim-run','--claim',str(CLAIM),'--fixture-only','--output',tmp],
                capture_output=True,text=True,timeout=60,
            )
            self.assertEqual(r.returncode,0,r.stderr+r.stdout)
            report=json.loads((Path(tmp)/'report.json').read_text(encoding='utf-8'))
            self.assertEqual(report['claim'],'swiyu.shared.age25-holder-challenge.v0')
            self.assertEqual(report['mode'],'fixture-only')
            kinds={c['kind']:c['report']['status'] for c in report['campaigns']}
            self.assertEqual(kinds['cross-implementation'],'clean')
if __name__=='__main__': unittest.main()

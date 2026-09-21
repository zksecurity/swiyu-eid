import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from privacy_runner import collect_provider_traces, run_privacy, execute_collector

ROOT = Path(__file__).resolve().parents[2]


class PrivacyRunnerTests(unittest.TestCase):
    def test_executes_declared_provider_without_provider_specific_profile_logic(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'provider.py').write_text('''import json,sys
for line in sys.stdin:
 r=json.loads(line); op=r['operation']; p=r['payload']
 result={'protocol':r['protocol'],'id':r['id'],'status':'ok','result':{}}
 if op=='prepare':
  result={'protocol':r['protocol'],'id':r['id'],'status':'error','error':{'code':'invalid','message':p['credential']['data']}}
 print(json.dumps(result),flush=True)
''')
            manifest = path / 'manifest.json'
            manifest.write_text(json.dumps({'schema':'swiyu.provider-manifest.v1','id':'external',
                'title':'External provider','kind':'implementation','profiles':['eligibility-v9'],
                'command':[sys.executable,'provider.py']}))
            bundle = collect_provider_traces(str(manifest))
            cases = [c for c in bundle['cases'] if c.get('records')]
            self.assertTrue(cases)
            self.assertTrue(any('private-credential-' in json.dumps(c['records']) for c in cases))
            output = path / 'output'
            code, report = run_privacy(output=str(output), manifest=str(manifest))
            self.assertEqual(code, 1)
            self.assertTrue(report['privacy']['findings'])
            self.assertNotIn('private-credential-', (output/'privacy-report.json').read_text())
            self.assertTrue((output/'privacy-report.html').exists())

    def test_missing_observer_is_reported_as_a_gap(self):
        with tempfile.TemporaryDirectory() as directory:
            code, report = run_privacy(output=directory, traces={
                'schema':'swiyu.privacy-traces.v1','provider':{'id':'x','title':'Example'},'cases':[{
                'id':'android','family':'session_isolation','relation':'secret_scan',
                'observer':'verifier HTTP','runtime':'android-emulator','evidence_kind':'integration',
                'skip_reason':'No Android collector installed','records':[]}]})
            self.assertEqual(code, 2)
            self.assertNotEqual(report['privacy']['status'], 'clean')
            self.assertIn('No Android collector installed',(Path(directory)/'privacy-report.html').read_text())

class ManifestCollectorTests(unittest.TestCase):
    def test_manifest_declares_its_own_privacy_collector(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'provider.py').write_text('import json,sys\nfor line in sys.stdin:\n r=json.loads(line);print(json.dumps({"protocol":r["protocol"],"id":r["id"],"status":"error","error":{"code":"bad","message":"rejected"}}),flush=True)\n')
            manifest={'schema':'swiyu.provider-manifest.v1','id':'external','title':'External',
                'kind':'implementation','profiles':['membership-v2'],'command':[sys.executable,'provider.py'],
                'source':{'privacy_collector':'observations.json'}}
            (root/'manifest.json').write_text(json.dumps(manifest))
            (root/'observations.json').write_text(json.dumps({'schema':'swiyu.privacy-traces.v1',
                'provider':{'id':'external','title':'External'},'cases':[{
                'id':'custom-observer','family':'disclosure','relation':'secret_scan','observer':'custom HTTP',
                'runtime':'local','evidence_kind':'integration','skip_reason':'not available','records':[]}]}))
            _, report=run_privacy(manifest=str(root/'manifest.json'),output=str(root/'out'))
            self.assertTrue(any(c['id']=='custom-observer' for c in report['privacy']['cases']))

class CollectorLimitsTests(unittest.TestCase):
    def test_hanging_collector_is_stopped_without_printing_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            collector = Path(directory)/'hang.py'
            collector.write_text('import time,sys\nprint("PRIVATE-STDERR",file=sys.stderr,flush=True)\ntime.sleep(20)\n')
            with self.assertRaisesRegex(ValueError, 'time limit') as caught:
                execute_collector(str(collector), timeout=.1)
            self.assertNotIn('PRIVATE-STDERR', str(caught.exception))

    def test_output_budget_applies_to_stderr_as_well_as_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            collector = Path(directory)/'flood.py'
            collector.write_text('import os\nfor _ in range(400): os.write(2,b"x"*65536)\n')
            with self.assertRaisesRegex(ValueError, 'output limit'):
                execute_collector(str(collector))

    def test_timeout_stops_a_provider_child_in_its_own_session(self):
        import os, signal, time
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); pidfile=root/'child.pid'; collector=root/'spawn.py'
            collector.write_text('import subprocess,sys,time\nfrom pathlib import Path\n'
                + 'child=subprocess.Popen([sys.executable,"-c","import time;time.sleep(30)"],start_new_session=True)\n'
                + 'Path('+repr(str(pidfile))+').write_text(str(child.pid))\ntime.sleep(30)\n')
            try:
                with self.assertRaisesRegex(ValueError,'time limit'):
                    execute_collector(str(collector),timeout=.8)
                pid=int(pidfile.read_text())
                time.sleep(.1)
                ps=subprocess.run(['ps','-o','stat=','-p',str(pid)],capture_output=True,text=True)
                self.assertTrue(not ps.stdout.strip() or ps.stdout.strip().startswith('Z'),ps.stdout)
            finally:
                if pidfile.exists():
                    try:os.kill(int(pidfile.read_text()),signal.SIGKILL)
                    except ProcessLookupError:pass

    def test_duplicate_keys_in_trace_source_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'trace.json'
            path.write_text('{"schema":"a","schema":"b"}')
            with self.assertRaises(Exception): execute_collector(str(path))

class PrivacyCliTests(unittest.TestCase):
    def test_cli_runs_collector_and_returns_finding_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            collector = path / 'collect.py'
            bundle = {'schema':'swiyu.privacy-traces.v1','provider':{'id':'cli','title':'CLI example'},
                'cases':[{'id':'leak','family':'disclosure','relation':'secret_scan',
                    'observer':'HTTP','runtime':'controlled fixture','evidence_kind':'integration',
                    'secrets':[{'label':'canary','value':'SYNTHETIC-CLI-SECRET'}],
                    'records':[{'id':'1','subject':'1','session':'1','scope':'1','public_context':{},
                        'expected_outcome':'ok','outcome':'ok','allowed_public':{},
                        'view':{'unexpected':'SYNTHETIC-CLI-SECRET'}}]}]}
            collector.write_text('import json\nprint(json.dumps('+repr(bundle)+'))\n')
            result = subprocess.run([sys.executable, str(ROOT/'harness/zkbench.py'),
                'privacy-run', '--adapter', str(collector), '--output', str(path/'out')],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertTrue((path/'out/privacy-report.html').exists())
            self.assertNotIn('SYNTHETIC-CLI-SECRET', (path/'out/privacy-report.json').read_text())

class PrivacyImportTests(unittest.TestCase):
    def test_provider_report_rejects_campaign_from_another_provider(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            report = path/'privacy.json'
            report.write_text(json.dumps({'schema':'swiyu.privacy-campaign.v1',
                'provider':{'id':'different-provider','title':'Other'},
                'privacy':{'status':'clean','findings':[],'cases':[]}}))
            result = subprocess.run([sys.executable, str(ROOT/'harness/zkbench.py'),
                'provider-run', str(ROOT/'providers/test-stub/manifest.json'),
                '--privacy-report',str(report),'--output',str(path/'out')],
                capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            imported = json.loads((path/'out/provider-report.json').read_text())['leakage']
            self.assertEqual(imported['status'],'inconclusive')
            self.assertIn('different provider', imported['summary'])

if __name__ == '__main__': unittest.main()

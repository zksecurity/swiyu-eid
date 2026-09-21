"""Human-readable report contract, independent of cryptographic evaluation."""
import unittest
from claim_campaign import _render_campaign_html


class ClaimReportReadabilityTests(unittest.TestCase):
    def test_condition_precedes_collapsed_raw_definition(self):
        where = {'all': [
            {'predicate': 'date.on-or-before@1', 'args': {'value': {'attribute': 'birthday'}, 'limit': {'given': 'cutoff'}}},
            {'any': [
                {'predicate': 'value.equals@1', 'args': {'left': {'attribute': 'residence'}, 'right': {'given': 'country'}}},
                {'predicate': 'value.in-set@1', 'args': {'value': {'attribute': 'nationality'}, 'set': {'given': 'allowed'}}},
            ]},
        ]}
        report = {'overall': 'passed', 'claim': {'id': 'custom', 'require': ['issuer_check'], 'where': where}, 'cases': [], 'privacy': {}}
        rendered = _render_campaign_html(report)
        self.assertIn('attribute birthday on or before given cutoff', rendered)
        self.assertIn('AND', rendered)
        self.assertIn('OR', rendered)
        self.assertIn('<details>', rendered)
        self.assertIn('<summary>Full condition definition</summary>', rendered)
        self.assertIn('milliseconds', rendered)
        self.assertIn('Functional result', rendered)
        self.assertIn('Coverage', rendered)

    def test_expression_labels_are_html_escaped(self):
        report = {'claim': {'where': {'predicate': 'value.equals@1', 'args': {'left': {'attribute': '<script>'}, 'right': {'given': 'wanted'}}}}, 'cases': [], 'privacy': {}}
        rendered = _render_campaign_html(report)
        self.assertNotIn('<script>', rendered)
        self.assertIn('&lt;script&gt;', rendered)

    def test_cli_accepts_explicit_local_provider_registration(self):
        import json
        from pathlib import Path
        import subprocess
        import sys
        import tempfile
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as output:
            result = subprocess.run([
                sys.executable, str(root / 'zkbench.py'), 'claims-demo',
                '--claim', str(root.parent / 'semantics/claims/clearance-status.json'),
                '--manifest', str(root.parent / 'providers/semantic-reference/manifest.json'),
                '--support', str(root.parent / 'providers/semantic-reference/support.json'),
                '--max-cases', '2', '--output', output,
            ], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((Path(output) / 'report.json').read_text())
            self.assertTrue(any(case['outcome'] == 'not_run' for case in report['cases']))

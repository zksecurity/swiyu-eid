import unittest
from report import render_privacy_report


class PrivacyReportTests(unittest.TestCase):
    def test_report_distinguishes_observed_findings_controls_and_missing_surfaces(self):
        report = {'provider': {'title': 'Example provider'}, 'privacy': {
            'status': 'findings', 'summary': 'Observed boundary leakage',
            'findings': [{'kind': 'secret_disclosed', 'case_id': 'failure', 'field': '/error',
                          'observer': 'facade stderr', 'runtime': 'desktop', 'detail': 'Synthetic marker exposed'}],
            'cases': [{'id': 'failure', 'family': 'failure_fallback', 'status': 'findings',
                       'observer': 'facade stderr', 'runtime': 'desktop', 'evidence_kind': 'integration'},
                      {'id': 'android', 'family': 'session_isolation', 'status': 'not_run',
                       'skip_reason': 'Android runtime is not connected'}],
            'detector_controls': [{'id': 'control-secret', 'status': 'passed'}]}}
        page = render_privacy_report(report)
        for value in ['Observed findings', 'Detector controls', 'Coverage gaps', 'facade stderr',
                      'Android runtime is not connected', 'control-secret', 'failure_fallback']:
            self.assertIn(value, page)
        self.assertNotIn('All privacy tests passed', page)

    def test_escapes_untrusted_metadata_and_does_not_render_raw_trace_inputs(self):
        page = render_privacy_report({'provider': {'title': '<script>alert(1)</script>'}, 'privacy': {
            'status': 'inconclusive', 'cases': [{'id': 'case', 'view': {'credential': 'RAW_SECRET'},
                                              'secrets': ['RAW_SECRET'], 'status': 'clean'}]}})
        self.assertNotIn('<script>alert', page)
        self.assertNotIn('RAW_SECRET', page)
        self.assertIn('&lt;script&gt;', page)

class ControlDisplayTests(unittest.TestCase):
    def test_detected_fault_is_a_passed_control_with_expected_and_actual_columns(self):
        page=render_privacy_report({'provider':{'title':'Test'},'privacy':{
            'status':'clean','detector_controls':{'status':'clean','cases':[{
                'id':'ctrl-secret-faulty','expected_status':'findings','status':'findings'}]}}})
        self.assertIn('Expected observation',page)
        self.assertIn('Actual observation',page)
        self.assertIn('<td>passed</td>',page)

if __name__ == '__main__': unittest.main()

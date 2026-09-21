import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from transcript_report import render_transcript_report

class TranscriptReportTests(unittest.TestCase):
    def test_report_is_explicit_about_evidence_and_does_not_dump_private_input(self):
        bundle = {
            'provider': 'Example <provider>',
            'claim': 'example.claim',
            'qualification': 'Production controller; memory repository; real proofs.',
            'campaigns': [{'name': 'Clean', 'kind': 'baseline', 'report': {'status': 'passed', 'findings': [], 'pairs': [{'left': 'a', 'right': 'b', 'status': 'passed'}]}}],
            'sessions': [{'id': 'a', 'variant': 'hidden-a', 'accepted': True, 'event_count': 3, 'proof_bytes': 123, 'witness_bytes': 456, 'present_ms': 25, 'credential': 'PRIVATE-CREDENTIAL'}],
        }
        result = render_transcript_report(bundle)
        self.assertIn('Example &lt;provider&gt;', result)
        self.assertIn('Production controller', result)
        self.assertIn('123', result)
        self.assertIn('456', result)
        self.assertNotIn('PRIVATE-CREDENTIAL', result)
        self.assertIn('Finite tests', result)
        self.assertIn('baseline', result)

    def test_injected_finding_and_failed_session_remain_visible(self):
        result = render_transcript_report({'provider': 'p', 'claim': 'c', 'campaigns': [
            {'name': 'Extra field', 'kind': 'injected regression', 'report': {'status': 'findings', 'findings': [{'kind': 'transcript_difference', 'pointer': '/events/1/request/body/tag', 'explanation': 'Unknown identifier differs'}]}}
        ], 'sessions': [{'id': 'broken', 'accepted': False}]})
        self.assertIn('injected regression', result)
        self.assertIn('/events/1/request/body/tag', result)
        self.assertIn('Rejected', result)
        self.assertIn('Unknown identifier differs', result)
        self.assertIn('Not measured', result)

    def test_findings_and_provider_text_cannot_inject_html(self):
        result = render_transcript_report({'provider': '<script>alert(1)</script>', 'campaigns': [
            {'name': '<img src=x>', 'report': {'findings': [{'kind': '<script>', 'path': '<svg onload=x>'}]}}
        ]})
        self.assertNotIn('<script>', result)
        self.assertNotIn('<svg onload=x>', result)
        self.assertIn('&lt;svg onload=x&gt;', result)

    def test_finding_shows_boundary_and_pointers_or_location_fallback(self):
        result = render_transcript_report({'provider': 'p', 'campaigns': [
            {'name': 'Diff', 'report': {'findings': [
                {'kind': 'transcript_mismatch', 'boundary': 'wallet->verifier:direct_post', 'pointers': ['/events/2/request/body/tag', '/events/2/request/headers/0']},
                {'kind': 'secret_disclosure', 'boundary': 'verifier:management_create', 'location': 'decoded-body'},
            ]}}
        ]})
        self.assertIn('wallet-&gt;verifier:direct_post', result)
        self.assertIn('/events/2/request/body/tag', result)
        self.assertIn('/events/2/request/headers/0', result)
        self.assertIn('verifier:management_create', result)
        self.assertIn('decoded-body', result)

    def test_malformed_finding_locations_are_escaped_and_do_not_crash(self):
        result = render_transcript_report({'provider': 'p', 'campaigns': [
            {'name': 'Bad', 'report': {'findings': [
                {'kind': 'x', 'boundary': '<b>', 'pointers': ['<img src=x>', 12, None], 'location': '<script>'},
                {'kind': 'y', 'pointers': 'not-a-list', 'location': 'fallback-loc'},
                'not-an-object',
                None,
            ]}}
        ]})
        self.assertNotIn('<img src=x>', result)
        self.assertNotIn('<script>', result)
        self.assertIn('&lt;b&gt;', result)
        self.assertIn('&lt;img src=x&gt;', result)
        self.assertIn('fallback-loc', result)

    def test_size_labels_distinguish_provider_witness_and_presentation_proof(self):
        result = render_transcript_report({'sessions': [{'id': 'a', 'proof_bytes': 9, 'witness_bytes': 8}]})
        self.assertRegex(result, r'(?i)proof[^<]*presentation leaf')
        self.assertRegex(result, r'(?i)witness[^<]*provider-reported')

if __name__ == '__main__':
    unittest.main()

import unittest
import json
from facade_privacy import collect_facade_traces


class FacadePrivacyTests(unittest.TestCase):
    def test_provider_messages_codes_and_reasons_cannot_escape_shared_facade(self):
        bundle = collect_facade_traces()
        for case in bundle['cases']:
            with self.subTest(case=case['id']):
                record = case['records'][0]
                self.assertEqual(record['outcome'], record['expected_outcome'])
                self.assertNotIn(case['secrets'][0]['value'], str(record['view']))
                if case['id'] == 'facade-accepted-reason':
                    self.assertIsNone(json.loads(record['view']['stdout'])['verifier']['reason'])
                elif case['id'] != 'facade-verifier-reason':
                    self.assertIn('provider_error', record['view']['stderr'])
                else:
                    self.assertIn('presentation_rejected', record['view']['stdout'])

    def test_successful_verifier_cannot_attach_a_private_diagnostic(self):
        case = next((c for c in collect_facade_traces()['cases'] if c['id'] == 'facade-accepted-reason'), None)
        self.assertIsNotNone(case)
        record = case['records'][0]
        self.assertEqual(record['outcome'], 'accepted')
        self.assertNotIn(case['secrets'][0]['value'], str(record['view']))

if __name__ == '__main__': unittest.main()

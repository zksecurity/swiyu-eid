import base64
import copy
import json
import unittest
from privacy_campaign import CampaignError, MAX_DECODE_BYTES, analyze_campaign


def bundle():
    return {'schema':'swiyu.privacy-traces.v1','provider':{'id':'test','title':'Test'},'cases':[{
        'id':'case','family':'disclosure','relation':'secret_scan','observer':'wire','runtime':'desktop',
        'evidence_kind':'integration','secrets':[{'label':'canary','value':'PRIVATE-MARKER-59a210'}],
        'records':[{'id':'1','subject':'a','session':'a','scope':'a','public_context':{},
            'expected_outcome':'accept','outcome':'accept','view':{'proof':'ordinary opaque bytes'},'allowed_public':{}}]}]}


class PrivacyHardeningTests(unittest.TestCase):
    def test_scans_a_realistic_large_encoded_envelope(self):
        trace=bundle()
        envelope=json.dumps({'proof':'x'*562_000,'unexpected':trace['cases'][0]['secrets'][0]['value']})
        trace['cases'][0]['records'][0]['view']={'presentation':base64.urlsafe_b64encode(envelope.encode()).decode()}
        result=analyze_campaign(trace)
        self.assertTrue(any(f['kind']=='secret_disclosure' for f in result['privacy']['findings']))

    def test_missing_outcome_cannot_pass(self):
        trace=bundle();del trace['cases'][0]['records'][0]['outcome']
        with self.assertRaises(CampaignError): analyze_campaign(trace)

    def test_nonfinite_or_negative_or_boolean_metrics_are_invalid(self):
        for value in [float('nan'), float('inf'), -1, True]:
            trace=bundle();trace['cases'][0]['records'][0]['metrics']={'duration_ms':value}
            with self.subTest(value=value), self.assertRaises(CampaignError): analyze_campaign(trace)

    def test_control_mismatch_fails_run_without_becoming_a_provider_finding(self):
        trace=bundle(); case=trace['cases'][0]
        case['id']='ctrl-secret-faulty';case['evidence_kind']='control'
        result=analyze_campaign(trace)
        self.assertEqual(result['privacy']['detector_controls']['status'],'findings')
        self.assertEqual(result['privacy']['findings'],[])

class SharedPrefixDecodeTests(unittest.TestCase):
    def test_distinct_envelopes_with_the_same_prefix_are_both_scanned(self):
        trace=bundle()
        def encoded(value):
            return base64.urlsafe_b64encode(json.dumps({'padding':'x'*400,'hidden':value}).encode()).decode()
        trace['cases'][0]['records'][0]['view']={
            'first':encoded('ordinary'),'second':encoded(trace['cases'][0]['secrets'][0]['value'])}
        result=analyze_campaign(trace)
        self.assertTrue(any(f['kind']=='secret_disclosure' for f in result['privacy']['findings']))

if __name__=='__main__':unittest.main()

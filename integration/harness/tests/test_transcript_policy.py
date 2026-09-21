"""Realistic OID4VP wrappers must compare without hiding extra channels."""
import base64
import copy
import json
import sys
import unittest
from pathlib import Path
from urllib.parse import urlencode
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT.parent / 'semantics')]
from semantics.claims import load_claim
from semantics.fixtures import make_fixture
from transcript_equivalence import analyze_transcripts
from transcript_policy import build_flow_policy
CLAIM = ROOT.parent / 'semantics/claims/openac-age18-status-2k.json'

def b64(data): return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
def token(value): return b64(json.dumps(value, separators=(',', ':')).encode())

def sessions():
    result = []
    for i in (1, 2):
        f = make_fixture(load_claim(CLAIM), seed=7, attributes={'birthdate': f'199{i}-02-01'})
        state, nonce = f'session-identifier-{i:016d}', f'nonce-identifier-{i:016d}'
        callback = f'http://127.0.0.1:9999/oid4vp/api/request-object/{state}/response-data'
        given = copy.deepcopy(f['given'])
        given['session'].update(nonce=nonce, state=state, response_uri=callback)
        envelope = token({'proof': b64(bytes([i]) * 315967), 'lookup': {'issuer': given['issuer']['issuer_id']}})
        payload = {'nonce': nonce, 'state': state, 'response_uri': callback, 'client_id': given['session']['client_id']}
        jwt = token({'alg':'ES256'}) + '.' + token(payload) + '.' + b64(bytes([i])*64)
        bodies = [('{}', json.dumps({'id': state})), ('', jwt), (urlencode({'state': state, 'vp_token': json.dumps({'q': [envelope]})}), '{}'), ('', json.dumps({'id':state, 'state':'SUCCESS'}))]
        boundaries = ['verifier:management_create','verifier:request_object','wallet->verifier:direct_post','verifier:management_result']
        events=[]
        for j,(request,response) in enumerate(bodies):
            events.append({'boundary':boundaries[j], 'request':{'method':'POST' if j in (0,2) else 'GET','url': callback,'headers':[['Content-Length',str(len(request.encode()))]],'body':request},'response':{'status':200,'headers':[['Date',f'Tue, 15 Sep 2026 18:0{i}:00 GMT'],['Content-Length',str(len(response.encode()))]],'body':response}})
        result.append({'id':f's{i}', 'variant':f'v{i}', 'credential':f['fixture']['credential'],'given':given,'accepted':True,'fresh':{'nonce':nonce,'state':state},'events':events})
    return result

class PolicyTests(unittest.TestCase):
    def setUp(self): self.policy=build_flow_policy({'mapping':{'query_id':'q'},'proof_path':'/proof'})
    def test_real_sized_proofs_and_fresh_urls_compare_and_clocks_are_explicitly_unassessed(self):
        report=analyze_transcripts(CLAIM,sessions(),self.policy)
        self.assertEqual(report['status'],'clean', report)
        self.assertEqual(report['coverage']['compared_pairs'],1)
        self.assertIn('response Date values',report['unassessed_channels'])
    def test_request_object_clock_shifts_preserve_expiration_lifetime(self):
        rows=sessions()
        for i,row in enumerate(rows):
            body=row['events'][1]['response']['body']; parts=body.split('.')
            payload=json.loads(base64.urlsafe_b64decode(parts[1]+'='*(-len(parts[1])%4)))
            payload.update(iat=1789495000+i*60, exp=1789498600+i*60)
            parts[1]=token(payload)
            response=row['events'][1]['response'];response['body']='.'.join(parts)
            response['headers']=[h for h in response['headers'] if h[0].lower()!='content-length']+[['Content-Length',str(len(response['body']))]]
        self.assertEqual(analyze_transcripts(CLAIM,rows,self.policy)['status'],'clean')
        response=rows[1]['events'][1]['response'];parts=response['body'].split('.')
        payload=json.loads(base64.urlsafe_b64decode(parts[1]+'='*(-len(parts[1])%4)));payload['exp']+=60;parts[1]=token(payload);response['body']='.'.join(parts)
        self.assertEqual(analyze_transcripts(CLAIM,rows,self.policy)['status'],'findings')

    def test_unknown_hash_header_remains_detectable(self):
        rows=sessions()
        for i,row in enumerate(rows): row['events'][2]['request']['headers'].append(['X-Correlation',str(i)*64])
        report=analyze_transcripts(CLAIM,rows,self.policy)
        self.assertEqual(report['status'],'findings')
        self.assertTrue(any('headers' in p for pair in report['pairs'] for d in pair['diffs'] for p in [d['pointer']]))
    def test_missing_same_exchange_in_both_runs_is_inconclusive(self):
        rows=sessions()
        for row in rows: row['events'].pop()
        self.assertEqual(analyze_transcripts(CLAIM,rows,self.policy)['status'],'inconclusive')
    def test_provider_cannot_mask_entire_vp_token_or_select_ignored_headers(self):
        with self.assertRaises(ValueError): build_flow_policy({'mapping':{'query_id':'q'},'proof_path':''})
        self.assertEqual(self.policy['ignored_headers'],[])
        self.assertEqual(self.policy['opaque_fields'][0]['path'],'/vp_token/q/0/proof')
    def test_missing_response_body_in_both_runs_is_not_a_clean_capture(self):
        rows=sessions()
        for row in rows: del row['events'][0]['response']['body']
        self.assertEqual(analyze_transcripts(CLAIM,rows,self.policy)['status'],'inconclusive')

    def test_invalid_date_not_silently_normalized(self):
        rows=sessions(); rows[0]['events'][0]['response']['headers'][0][1]='private-date-tag'
        self.assertNotEqual(analyze_transcripts(CLAIM,rows,self.policy)['status'],'clean')

    def test_duplicate_date_headers_are_not_collapsed_to_a_clock_token(self):
        rows=sessions()
        a='Tue, 15 Sep 2026 18:01:00 GMT'
        b='Tue, 15 Sep 2026 18:02:00 GMT'
        rows[0]['events'][0]['response']['headers']=[
            ['Date', a], ['Date', b],
            ['Content-Length', str(len(rows[0]['events'][0]['response']['body'].encode()))],
        ]
        rows[1]['events'][0]['response']['headers']=[
            ['Date', a], ['Date', a],
            ['Content-Length', str(len(rows[1]['events'][0]['response']['body'].encode()))],
        ]
        self.assertNotEqual(analyze_transcripts(CLAIM,rows,self.policy)['status'],'clean')

    def test_overlapping_fresh_tokens_are_rejected(self):
        rows=sessions()
        rows[0]['fresh']['request_id']=rows[0]['fresh']['state']+'suffix'
        rows[0]['given']['session']['response_uri']+=rows[0]['fresh']['request_id']
        report=analyze_transcripts(CLAIM,rows,self.policy)
        self.assertNotEqual(report['status'],'clean')
        self.assertTrue(any('overlap' in str(f).lower() or 'collid' in str(f).lower() for f in report['findings']))

    def _request_object_payload(self, row):
        body=row['events'][1]['response']['body']; parts=body.split('.')
        payload=json.loads(base64.urlsafe_b64decode(parts[1]+'='*(-len(parts[1])%4)))
        return parts, payload

    def _set_request_object_payload(self, row, payload):
        parts, _ = self._request_object_payload(row)
        parts[1]=token(payload)
        response=row['events'][1]['response']; response['body']='.'.join(parts)
        response['headers']=[h for h in response['headers'] if h[0].lower()!='content-length']+[['Content-Length',str(len(response['body']))]]

    def test_request_object_extra_payload_field_beside_clock_remains_visible(self):
        rows=sessions()
        for i,row in enumerate(rows):
            _, payload=self._request_object_payload(row)
            payload.update(iat=1789495000+i*60, exp=1789498600+i*60)
            self._set_request_object_payload(row, payload)
        _, payload=self._request_object_payload(rows[1])
        payload['extra_channel']= 'session-private-'+rows[1]['id']
        self._set_request_object_payload(rows[1], payload)
        report=analyze_transcripts(CLAIM,rows,self.policy)
        self.assertEqual(report['status'],'findings', report)
        blob=json.dumps(report)
        self.assertTrue('extra_channel' in blob or any('payload' in str(f).lower() for f in report['findings']))

    def test_missing_or_non_int_request_object_exp_is_not_clean(self):
        rows=sessions()
        for i,row in enumerate(rows):
            _, payload=self._request_object_payload(row)
            payload.update(iat=1789495000, exp=1789498600)
            self._set_request_object_payload(row, payload)
        _, payload=self._request_object_payload(rows[0])
        del payload['exp']
        self._set_request_object_payload(rows[0], payload)
        self.assertNotEqual(analyze_transcripts(CLAIM,rows,self.policy)['status'],'clean')
        rows=sessions()
        for i,row in enumerate(rows):
            _, payload=self._request_object_payload(row)
            payload.update(iat=1789495000, exp=1789498600)
            self._set_request_object_payload(row, payload)
        _, payload=self._request_object_payload(rows[1])
        payload['exp']='1789498600'
        self._set_request_object_payload(rows[1], payload)
        self.assertNotEqual(analyze_transcripts(CLAIM,rows,self.policy)['status'],'clean')

if __name__=='__main__': unittest.main()

"""Reference-public projection and malformed-wire regression tests."""
import base64
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import claim_campaign as campaign
from semantics.assertions import evaluate_claim, expected_transcript
from semantics.claims import load_claim
from semantics.fixtures import make_fixture, reauthorize_fixture, derive_fixture_private_key
from semantics.leakage import (
    FINDING_DERIVED_DIGEST,
    FINDING_STRUCTURE,
    analyze_pair,
    analyze_presentation_leakage,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

CLAIM = Path(__file__).resolve().parents[2] / 'semantics/claims/clearance-status.json'


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')


def case(bundle, claim):
    return SimpleNamespace(**bundle, expected_verdict=evaluate_claim(claim, bundle['fixture'], bundle['given'])['value'])


class PublicProjectionTests(unittest.TestCase):
    def setUp(self):
        self.claim = load_claim(CLAIM)
        self.bundle = make_fixture(self.claim)
        self.plan = case(self.bundle, self.claim)
        self.projection = campaign._harness_permitted_projection(self.claim, self.plan)
        self.digest = expected_transcript(self.claim, self.plan.given).hex()

    def inspect(self, envelope, projection=None):
        return analyze_presentation_leakage(
            raw_bytes=json.dumps(envelope).encode(), release=self.claim.document['release'],
            expected_given=self.plan.given, expected_derived_digest=self.digest,
            permitted_projection=self.projection if projection is None else projection,
        )

    def test_authenticated_metadata_is_in_projection_and_wrong_wire_values_fail(self):
        issuer = self.plan.given['issuer']
        expected = {'eid.issuer': issuer['issuer_id'], 'eid.key_id': issuer['key_id'], 'eid.credential_type': 'swiyu.synthetic-eid@0'}
        self.assertEqual({k:self.projection.get(k) for k in expected}, expected)
        result = self.inspect({**self.projection, 'protocol_derived_digest':self.digest, **{key:'wrong' for key in expected}})
        fields = {f['field'] for f in result['findings']}
        self.assertTrue(set(expected) <= fields)

    def test_allowed_omissions_and_matching_public_context_are_not_findings(self):
        projection = {**self.projection, 'eid.issuer': 'synthetic-issuer-1'}
        result = self.inspect({'protocol_derived_digest': self.digest, 'presentation_context': self.digest, 'proof':'opaque'}, projection)
        self.assertEqual(result['findings'], [])

    def test_wrong_public_context_digest_is_a_structure_finding(self):
        result = self.inspect(
            {'protocol_derived_digest': self.digest, 'presentation_context': 'f' * 64, 'proof': 'opaque'},
            self.projection,
        )
        fields = {(f['kind'], f['field']) for f in result['findings']}
        self.assertTrue(
            (FINDING_DERIVED_DIGEST, 'presentation_context') in fields
            or (FINDING_STRUCTURE, 'presentation_context') in fields
        )

    def test_missing_expected_projection_makes_pair_ineligible(self):
        base = {
            'statement_identity': self.claim.statement_digest,
            'stage': 'accepted',
            'given': self.plan.given,
            'outcome': True,
            'release': self.claim.document['release'],
            'raw_bytes': b'{"proof":"opaque"}',
        }
        left = {**base, 'permitted_projection': self.projection}
        right = {**base, 'permitted_projection': None}
        self.assertEqual(analyze_pair(left=left, right=right)['eligibility'], 'ineligible')

    def test_unauthenticated_metadata_makes_projection_unavailable(self):
        other = make_fixture(self.claim, seed=2)
        broken = copy.deepcopy(self.bundle)
        broken['given']['issuer'] = other['given']['issuer']
        self.assertIsNone(campaign._harness_permitted_projection(self.claim, case(broken, self.claim)))

    def test_two_authentic_allowed_types_are_not_an_equivalent_pair(self):
        given = copy.deepcopy(self.bundle['given'])
        given['issuer']['allowed_vcts'].append('swiyu.other-eid@0')
        first = reauthorize_fixture(self.claim, self.bundle['fixture'], given)
        second_fixture = copy.deepcopy(first['fixture'])
        pieces = second_fixture['credential'].split('~')
        head, body, signature = pieces[0].split('.')
        payload = json.loads(base64.urlsafe_b64decode(body+'=='))
        payload['vct'] = 'swiyu.other-eid@0'
        signing = head+'.'+b64(json.dumps(payload,separators=(',',':')).encode())
        sig = derive_fixture_private_key(1,'issuer').sign(signing.encode(), ec.ECDSA(hashes.SHA256()))
        r,s = decode_dss_signature(sig)
        pieces[0] = signing+'.'+b64(r.to_bytes(32,'big')+s.to_bytes(32,'big'))
        second_fixture['credential'] = '~'.join(pieces)
        second = reauthorize_fixture(self.claim, second_fixture, given)
        observations=[]
        for bundle in [first,second]:
            p=case(bundle,self.claim)
            self.assertTrue(p.expected_verdict)
            projection=campaign._harness_permitted_projection(self.claim,p)
            observations.append({'statement_identity':self.claim.statement_digest,'stage':'accepted','given':p.given,'outcome':True,'permitted_projection':projection,'release':self.claim.document['release'],'raw_bytes':b'{"proof":"opaque"}'})
        self.assertNotEqual(observations[0]['permitted_projection'], observations[1]['permitted_projection'])
        self.assertEqual(analyze_pair(left=observations[0],right=observations[1])['eligibility'],'ineligible')

    def test_privacy_status_preserves_inconclusive(self):
        self.assertEqual(campaign._privacy_status([], 0, ['inconclusive']), 'inconclusive')

    def test_malformed_presentation_is_a_reported_provider_error(self):
        class BrokenClient:
            token='A'
            def __init__(self,*args,**kwargs): pass
            def __enter__(self): return self
            def __exit__(self,*args): return False
            def call(self,operation,payload):
                if operation=='prepare': return {'handle':'h'}
                if operation=='present': return {'presentation':self.token}
                if operation=='verify': return {'verified':True}
                return {}
        for token in ['A','!!!invalid!!!']:
            with self.subTest(token=token), tempfile.TemporaryDirectory() as output, patch.object(campaign,'ProviderClient',BrokenClient):
                BrokenClient.token=token
                code, report=campaign.run_claims_demo(claim_path=str(CLAIM),output=output)
                self.assertEqual(code,1)
                self.assertEqual(report['overall'],'provider_error')
                self.assertTrue(all(row['outcome']=='provider_error' for row in report['cases']))
                self.assertTrue((Path(output)/'report.json').is_file())

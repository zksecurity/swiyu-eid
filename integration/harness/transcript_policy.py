"""Harness-owned observer policy for the selected Swiyu direct_post flow."""
BOUNDARIES = ['verifier:management_create', 'verifier:request_object', 'wallet->verifier:direct_post', 'verifier:management_result']


def build_flow_policy(document):
    query = document.get('mapping', {}).get('query_id')
    leaf = document.get('proof_path', '/proof')
    if not isinstance(query, str) or not query or not isinstance(leaf, str) or not leaf.startswith('/') or len(leaf) < 2:
        raise ValueError('query identifier and a proof leaf pointer are required')
    escaped = query.replace('~', '~0').replace('/', '~1')
    return {
        'id': 'swiyu-direct-post-http-v1', 'observer': 'verifier',
        'expected_boundaries': list(BOUNDARIES),
        'opaque_fields': [{'event': BOUNDARIES[2], 'side': 'request', 'path': f'/vp_token/{escaped}/0{leaf}', 'channel': 'proof'}],
        'public_fields': [
            {'event': BOUNDARIES[1], 'side': 'response', 'path': '/payload/nonce', 'expected_key': 'nonce'},
            {'event': BOUNDARIES[1], 'side': 'response', 'path': '/payload/state', 'expected_key': 'state'},
            {'event': BOUNDARIES[2], 'side': 'request', 'path': '/state', 'expected_key': 'state'},
        ],
        'rename_session_tokens': True,
        'request_object_clock': True,
        'response_clock_headers': ['date'],
        'ignored_headers': [],
    }


IMPLEMENTATION_KEYS = ('profile', 'circuit_id', 'issuer_pub_x', 'issuer_pub_y')


def build_cross_flow_policy(documents):
    if not isinstance(documents, list) or len(documents) < 2:
        raise ValueError('cross-implementation policy needs at least two factory documents')
    query_ids = {document.get('mapping', {}).get('query_id') for document in documents}
    if len(query_ids) != 1 or not isinstance(next(iter(query_ids)), str) or not next(iter(query_ids)):
        raise ValueError('cross-implementation factories must share one query identifier')
    query = next(iter(query_ids))
    escaped = query.replace('~', '~0').replace('/', '~1')
    opaque = []
    seen = set()
    for document in documents:
        leaf = document.get('proof_path', '/proof')
        if not isinstance(leaf, str) or not leaf.startswith('/') or len(leaf) < 2:
            raise ValueError('query identifier and a proof leaf pointer are required')
        path = f'/vp_token/{escaped}/0{leaf}'
        if path in seen:
            continue
        seen.add(path)
        opaque.append({'event': BOUNDARIES[2], 'side': 'request', 'path': path, 'channel': 'proof'})
    policy = build_flow_policy(documents[0])
    policy['id'] = 'swiyu-direct-post-http-cross-impl-v1'
    policy['opaque_fields'] = opaque
    policy['implementation_keys'] = list(IMPLEMENTATION_KEYS)
    policy['implementation_exempt_sizes'] = True
    policy['opaque_missing_ok'] = True
    return policy

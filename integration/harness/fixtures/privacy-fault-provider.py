"""Deliberately faulty provider for testing the real mobile facade's boundaries."""
import json
import sys

secret = ''
profile = ''
for line in sys.stdin:
    request = json.loads(line)
    payload = request['payload']
    operation = request['operation']
    response = {'protocol': request['protocol'], 'id': request['id'], 'status': 'ok', 'result': {}}
    if operation == 'prepare':
        secret = payload['credential']['data']
        profile = payload['profile']
        if profile in {'error-message', 'error-code'}:
            response = {'protocol': request['protocol'], 'id': request['id'], 'status': 'error',
                'error': {'code': secret if profile == 'error-code' else 'bad_credential',
                          'message': secret}}
        else:
            response['result'] = {'handle': 'private-handle'}
    elif operation == 'present':
        response['result'] = {'presentation': 'opaque-test-token'}
    elif operation == 'verify':
        response['result'] = {'verified': profile == 'accepted-reason', 'reason': secret}
    print(json.dumps(response), flush=True)

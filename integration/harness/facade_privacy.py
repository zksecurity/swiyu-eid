"""Fault injection at a real shared facade, explicitly separate from real providers."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def collect_facade_traces():
    integration = Path(__file__).resolve().parents[1]
    cases = []
    with tempfile.TemporaryDirectory(prefix='swiyu-privacy-facade-') as directory:
        manifest = Path(directory) / 'manifest.json'
        manifest.write_text(json.dumps({'schema': 'swiyu.provider-manifest.v1',
            'id': 'fault-injected-provider', 'title': 'Deliberately faulty provider',
            'kind': 'test-only', 'profiles': ['error-message', 'error-code', 'verifier-reason', 'accepted-reason'],
            'command': [sys.executable, str(integration/'harness/fixtures/privacy-fault-provider.py')]}))
        for variant in ('error-message', 'error-code', 'verifier-reason', 'accepted-reason'):
            secret = f'private-credential-{variant}-57acf019'
            request = {'schema': 'swiyu.mobile-runtime-facade.v1',
                'provider_manifest': str(manifest), 'profile': variant,
                'credential': {'format': 'dc+sd-jwt', 'data': secret},
                'request_context': {'nonce': 'session-nonce', 'audience': 'verifier.example'},
                'inputs': {}}
            result = subprocess.run([sys.executable, str(integration/'runtime/mobile_runtime.py'), '-'],
                input=json.dumps(request), text=True, capture_output=True, timeout=15)
            observed = json.loads(result.stdout) if result.returncode == 0 else None
            accepted = observed and observed.get('verifier', {}).get('verified') is True
            cases.append({'id': f'facade-{variant}', 'family': 'failure_fallback',
                'relation': 'secret_scan', 'observer': 'mobile facade CLI stdout/stderr',
                'runtime': 'desktop facade; fault-injected provider', 'evidence_kind': 'integration',
                'secrets': [{'label': 'private-credential', 'value': secret}],
                'records': [{'id': variant, 'subject': 'fixture-1', 'session': variant, 'scope': 'local',
                    'public_context': {}, 'expected_outcome': 'accepted' if variant == 'accepted-reason' else 'rejected',
                    'outcome': 'accepted' if accepted else 'rejected',
                    'view': {'stdout': result.stdout, 'stderr': result.stderr}, 'allowed_public': {}}]})
    return {'schema': 'swiyu.privacy-traces.v1', 'provider': {
        'id': 'mobile-facade-fault-injection',
        'title': 'Shared mobile facade under provider fault injection'}, 'cases': cases}


if __name__ == '__main__':
    print(json.dumps(collect_facade_traces()))

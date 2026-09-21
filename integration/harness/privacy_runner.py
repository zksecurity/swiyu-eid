"""Bounded execution of provider-neutral privacy trace collectors.

Raw fixtures and observer traces live only in memory; exported reports contain
analyzer summaries. Running an adapter executes local contributor code.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

from manifest import load_manifest
from provider_client import ProviderClient, ProviderError, _parse_json_strict
from report import render_privacy_report

MAX_TRACE_BYTES = 16 * 1024 * 1024
FAMILIES = ('disclosure', 'hidden_branch', 'linkability', 'failure_fallback', 'probing',
            'status_access', 'session_isolation', 'diagnostics', 'side_channel',
            'prepared_state', 'scoped_identifier')


def _process_snapshot():
    """PID parent and birth time let us avoid killing a recycled unrelated PID."""
    result = subprocess.run(['ps', '-axo', 'pid=,ppid=,lstart='],
                            capture_output=True, text=True, timeout=2, check=True)
    entries = {}
    for line in result.stdout.splitlines():
        fields = line.split(None, 2)
        if len(fields) == 3:
            entries[int(fields[0])] = (int(fields[1]), fields[2])
    return entries


def _track_descendants(root_pid, owned, snapshot):
    # Include already observed children if they became orphans or changed session.
    parents = {root_pid} | {pid for pid, birth in owned.items()
                            if pid in snapshot and snapshot[pid][1] == birth}
    while True:
        discovered = {pid for pid, (parent, _) in snapshot.items() if parent in parents}
        new = discovered - parents
        if not new:
            break
        parents |= new
    for pid in parents - {root_pid}:
        if pid in snapshot:
            owned[pid] = snapshot[pid][1]


def execute_collector(path: str, timeout: float = 180) -> dict:
    target = Path(path).resolve(strict=True)
    if target.suffix == '.json':
        if target.stat().st_size > MAX_TRACE_BYTES:
            raise ValueError('trace file exceeds size limit')
        return _parse_json_strict(target.read_text())
    command = {'mjs': ['node'], 'js': ['node'], 'py': [sys.executable]}.get(target.suffix[1:])
    if command is None:
        raise ValueError('collector must be JSON, Python or JavaScript')
    _process_snapshot()  # Fail before launching if process ownership cannot be observed.
    process = subprocess.Popen(command + [str(target)], cwd=target.parent,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True)
    output = bytearray()
    consumed = 0
    deadline = time.monotonic() + timeout
    owned = {}
    next_snapshot = 0
    try:
        with selectors.DefaultSelector() as selector:
            for stream in (process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                if time.monotonic() >= next_snapshot:
                    _track_descendants(process.pid, owned, _process_snapshot())
                    next_snapshot = time.monotonic() + .25
                if time.monotonic() >= deadline:
                    raise ValueError('collector exceeded time limit')
                for key, _ in selector.select(min(.2, max(0, deadline-time.monotonic()))):
                    block = os.read(key.fd, 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    consumed += len(block)
                    if consumed > MAX_TRACE_BYTES:
                        raise ValueError('collector exceeded output limit')
                    if key.fileobj is process.stdout:
                        output.extend(block)
        if process.wait(timeout=max(.01, deadline-time.monotonic())):
            raise ValueError('collector failed; raw diagnostic output was withheld')
        return _parse_json_strict(output.decode('utf-8'))
    finally:
        # ProviderClient starts its own session, so killpg alone is insufficient.
        try:
            snapshot = _process_snapshot()
            _track_descendants(process.pid, owned, snapshot)
        except (OSError, subprocess.SubprocessError):
            snapshot = {}
        for pid, birth in owned.items():
            if pid in snapshot and snapshot[pid][1] == birth:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        process.stdout.close()
        process.stderr.close()


def _record(index, view, *, expected='rejected', outcome='rejected', context=None):
    return {'id': str(index), 'subject': f'fixture-{index}', 'session': f'session-{index}',
        'scope': 'local', 'public_context': context or {}, 'expected_outcome': expected,
        'outcome': outcome, 'view': view, 'allowed_public': {}}


def _case(name, family, relation, records=None, **kwargs):
    return {'id': name, 'family': family, 'relation': relation,
        'observer': 'provider caller', 'runtime': 'desktop-provider-process',
        'evidence_kind': 'integration', 'records': records or [], **kwargs}


def _fixture(manifest):
    source = manifest.get('source', {})
    relative = source.get('provider_run_fixture')
    if not relative:
        return None
    root = Path(manifest['_manifest_dir']).resolve()
    target = (root / relative).resolve()
    if not target.is_relative_to(root):
        raise ValueError('fixture must remain inside provider directory')
    result = execute_collector(str(target), timeout=30)
    if result.get('schema') != 'swiyu.provider-run-fixture.v1':
        raise ValueError('unsupported fixture schema')
    return result


def collect_provider_traces(manifest_path: str, presentations: int = 0) -> dict:
    """Exercise the common JSONL contract without assumptions about predicates."""
    if not 0 <= presentations <= 8:
        raise ValueError('presentations must be between 0 and 8')
    manifest = load_manifest(manifest_path)
    declared = manifest.get('source', {}).get('privacy_collector')
    if declared is not None:
        if not isinstance(declared, str) or not declared:
            raise ValueError('privacy_collector must be a nonempty relative path')
        if presentations:
            raise ValueError('declared collectors own their scenario counts; omit --presentations')
        root = Path(manifest['_manifest_dir']).resolve()
        target = (root / declared).resolve()
        if Path(declared).is_absolute() or not target.is_relative_to(root):
            raise ValueError('privacy_collector must remain inside provider directory')
        bundle = execute_collector(str(target))
        if bundle.get('provider', {}).get('id') != manifest['id']:
            raise ValueError('collector provider ID differs from manifest')
        return bundle
    fixture = _fixture(manifest) if presentations else None
    profile = fixture.get('profile') if fixture else manifest['profiles'][0]
    cases, records, markers = [], [], []
    with ProviderClient(manifest_path, timeout=180, max_output_bytes=8*1024*1024,
                        max_input_bytes=8*1024*1024) as provider:
        provider.call('initialize', {})
        for index in range(2):
            marker = f'private-credential-canary-{index}-7a5c912b'
            markers.append({'label': f'credential-{index}', 'value': marker})
            try:
                result = provider.call('prepare', {'profile': profile,
                    'credential': {'format': 'dc+sd-jwt', 'data': marker}, 'context': {}})
                records.append(_record(index, result, outcome='accepted'))
            except ProviderError as error:
                records.append(_record(index, {'error': {'code': error.code, 'message': str(error)}}))
        cases.append(_case('malformed-credential-errors', 'failure_fallback', 'secret_scan',
                           records, secrets=markers))
        if fixture and presentations:
            prepared = provider.call('prepare', copy.deepcopy(fixture['prepare']))
            observed = []
            secrets = [{'label': 'raw-credential', 'value': fixture['prepare']['credential']['data']}]
            privacy = fixture.get('privacy', {})
            secrets += privacy.get('secrets', [])
            for index in range(presentations):
                request = copy.deepcopy(fixture['present'])
                request['handle'] = prepared['handle']
                context = request.get('request_context', {})
                context['nonce'] = f'privacy-session-{index}'
                started = time.perf_counter()
                result = provider.call('present', request)
                elapsed = (time.perf_counter()-started)*1000
                verify = copy.deepcopy(fixture['verify'])
                verify['presentation'] = result['presentation']
                verify['request_context'] = copy.deepcopy(context)
                verified = provider.call('verify', verify)
                record = _record(index, {'presentation': result['presentation']},
                    expected='accepted', outcome='accepted' if verified.get('verified') else 'rejected',
                    context=context)
                record['subject'] = 'credential-0'
                record['metrics'] = {'duration_ms': elapsed,
                    'size_bytes': len(result['presentation'].encode())}
                observed.append(record)
            cases.append(_case('presentation-private-material', 'disclosure', 'secret_scan',
                observed, secrets=secrets, opaque_paths=['/presentation'],
                evidence_kind='integration', observer='provider presentation output'))
            cases.append(_case('presentation-linkability', 'linkability', 'unlinkable',
                skip_reason='Requires independent credential controls and decoded linking fields; randomized token bytes alone are insufficient.'))
    supplied = {c['family'] for c in cases}
    for family in FAMILIES:
        if family not in supplied:
            cases.append(_case(f'{family}-coverage', family, 'secret_scan', skip_reason={
                'disclosure': 'Use --presentations with a provider-run fixture to collect actual presentations.',
                'status_access': 'Provider JSONL boundary does not capture status-service HTTP traffic.',
                'diagnostics': 'Provider-internal logs and mobile logs are not captured by this collector.',
                'probing': 'Requires a wallet consent and credential-selection observer.',
                'hidden_branch': 'Requires contributor fixtures with alternative satisfying branches.',
            }.get(family, 'Requires the matching lifecycle or observer adapter.')))
    return {'schema': 'swiyu.privacy-traces.v1',
        'provider': {key: manifest[key] for key in ('id', 'title', 'kind')}, 'cases': cases}


def run_privacy(*, output: str, manifest=None, adapter=None, traces=None,
                controls=False, presentations=0):
    from privacy_campaign import analyze_campaign
    if sum(value is not None for value in (manifest, adapter, traces)) != 1:
        raise ValueError('choose exactly one manifest, adapter, or trace bundle')
    bundle = collect_provider_traces(manifest, presentations) if manifest else (
        execute_collector(adapter) if adapter else traces)
    if controls:
        from privacy_controls import control_cases
        bundle = copy.deepcopy(bundle)
        bundle['cases'].extend(control_cases())
    report = analyze_campaign(bundle)
    destination = Path(output)
    destination.mkdir(parents=True, exist_ok=True)
    (destination/'privacy-report.json').write_text(json.dumps(report, indent=2)+'\n')
    (destination/'privacy-report.html').write_text(render_privacy_report(report))
    status = report['privacy']['status']
    detector_failed = report['privacy'].get('detector_controls', {}).get('status') == 'findings'
    return (1 if status == 'findings' or detector_failed else 2 if status in {'inconclusive','not_run'} else 0), report

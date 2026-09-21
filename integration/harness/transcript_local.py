"""Own the local verifier/sidecar lifecycle for a selected transcript campaign."""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]


def require_loopback_http_url(value):
    from urllib.parse import urlsplit
    if not isinstance(value, str):
        raise ValueError('runtime URL must be an http loopback URL')
    parts = urlsplit(value)
    if parts.scheme != 'http' or parts.hostname not in {'127.0.0.1', 'localhost'} or parts.username or parts.password or parts.fragment:
        raise ValueError('runtime URL must be an http loopback URL')
    return value


def local_runtime_qualification(bundle=None):
    provider = ''
    if isinstance(bundle, dict) and bundle.get('provider') not in (None, ''):
        provider = str(bundle.get('provider'))
    sidecar = f' registered sidecar ({provider})' if provider else ' registered sidecar'
    return (
        'Local owned lifecycle: Java production controllers/services via JDK HTTP adapter, '
        'memory repository, local signed request objects, and preprovisioned issuer/status. '
        f'Provider-generated proofs via the{sidecar}. '
        'Not full Spring dispatch, BeanValidation, deployment filters, Android, TLS, or live authority.'
    )


def qualify_local_report(output, bundle):
    from transcript_report import render_transcript_report
    from transcript_runner import _atomic_write
    if not isinstance(bundle, dict):
        raise TypeError('bundle must be an object')
    qualification = local_runtime_qualification(bundle)
    bundle['qualification'] = qualification
    report_path = Path(output) / 'report.json'
    if not report_path.exists():
        return bundle
    if report_path.is_symlink() or not report_path.is_file():
        raise ValueError('report.json must be a regular file')
    data = json.loads(report_path.read_text(encoding='utf-8'))
    if not isinstance(data, dict):
        raise ValueError('sanitized report.json must be an object')
    data['qualification'] = qualification
    _atomic_write(report_path, json.dumps(data, indent=2) + '\n')
    html_path = Path(output) / 'report.html'
    if html_path.exists() and (html_path.is_symlink() or not html_path.is_file()):
        raise ValueError('report.html must be a regular file')
    _atomic_write(html_path, render_transcript_report(data))
    return bundle


def export_runtime_logs(out, logs):
    diagnostics = Path(out) / 'runtime-logs'
    if diagnostics.is_symlink() or (diagnostics.exists() and not diagnostics.is_dir()):
        raise ValueError('runtime log directory must not be a symlink')
    diagnostics.mkdir(exist_ok=True, mode=0o700)
    if diagnostics.is_symlink():
        raise ValueError('runtime log directory must not be a symlink')
    for log in logs:
        target = diagnostics / Path(log).name
        if target.is_symlink():
            raise ValueError('runtime log target must not be a symlink')
        with open(log, 'rb') as src:
            content = src.read(1_048_576)
        fd = os.open(target, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'wb') as dst:
            dst.write(content)


class OwnedJavaRuntime:
    def __init__(self, verifier_url, sidecar_url, processes, logs, log_handles):
        self.verifier_url = verifier_url
        self.sidecar_url = sidecar_url
        self.processes = processes
        self.logs = logs
        self.log_handles = log_handles

    def close(self):
        for process in reversed(self.processes):
            _stop_process(process)
        for handle in self.log_handles:
            try:
                handle.close()
            except OSError:
                pass


def start_owned_java_runtime(
    sidecar_argv,
    fixture_document,
    scratch,
    *,
    env=None,
    cwd=None,
    ready_timeout=240,
):
    fixture = Path(scratch) / 'fixture.json'
    descriptor = os.open(fixture, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, 'w') as f:
        json.dump(fixture_document, f)
    sidecar_ready = Path(scratch) / 'sidecar-ready.json'
    verifier_ready = Path(scratch) / 'verifier-ready.json'
    stop = Path(scratch) / 'verifier.stop'
    sidecar_cmd = list(sidecar_argv) + ['--fixture', str(fixture), '--ready-file', str(sidecar_ready)]
    processes = []
    logs = []
    handles = []
    sidecar_url = None
    try:
        for name, command, ready in (
            ('sidecar', sidecar_cmd, sidecar_ready),
            ('verifier', None, verifier_ready),
        ):
            if name == 'verifier':
                command = [str(ROOT / 'integration/runtime/transcript/java/run-harness.sh'),
                           '--port', '0', '--sidecar', sidecar_url, '--ready-file', str(ready),
                           '--stop-file', str(stop)]
            logfile = Path(scratch) / (name + '.log')
            handle = open(logfile, 'w')
            os.chmod(logfile, 0o600)
            handles.append(handle)
            logs.append(logfile)
            proc = subprocess.Popen(
                command,
                cwd=cwd or ROOT,
                env=env,
                stdout=handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            processes.append(proc)
            state = _wait_ready(proc, ready, timeout=ready_timeout)
            if name == 'sidecar':
                sidecar_url = require_loopback_http_url(state.get('url') or state.get('base_url'))
            else:
                verifier_url = require_loopback_http_url(state.get('base_url') or state.get('url'))
        return OwnedJavaRuntime(verifier_url, sidecar_url, processes, logs, handles)
    except Exception:
        for process in reversed(processes):
            _stop_process(process)
        for handle in handles:
            try:
                handle.close()
            except OSError:
                pass
        raise


def _wait_ready(process, path, timeout=240):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError('local runtime exited before becoming ready')
        if path.exists():
            try:
                value = json.loads(path.read_text())
                if isinstance(value, dict):
                    return value
            except (ValueError, OSError):
                pass  # writer may still be committing its readiness record
        time.sleep(.1)
    raise RuntimeError('local runtime startup deadline exceeded')


def _stop_process(process):
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)


def run_local_campaign(manifest_path, claim_path, output, **options):
    import threading
    if threading.current_thread() is not threading.main_thread():
        return _run_local_campaign(manifest_path, claim_path, output, **options)
    previous = signal.getsignal(signal.SIGTERM)
    def stop_owned_runtime(_signum, _frame):
        raise KeyboardInterrupt("local campaign stopped")
    signal.signal(signal.SIGTERM, stop_owned_runtime)
    try:
        return _run_local_campaign(manifest_path, claim_path, output, **options)
    finally:
        signal.signal(signal.SIGTERM, previous)


def _run_local_campaign(manifest_path, claim_path, output, **options):
    from manifest import load_manifest
    from transcript_runner import _load_transcript_fixture, _resolve_manifest_local_path, run_transcript_campaign
    manifest = load_manifest(manifest_path)
    source = manifest.get('source', {})
    sidecar = _resolve_manifest_local_path(manifest, source.get('transcript_sidecar', ''))
    if sidecar.suffix not in {'.mjs', '.js', '.py'}:
        raise ValueError('unsupported sidecar entry point')
    out = Path(output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    os.environ['SWIYU_TRANSCRIPT_CLAIM'] = str(Path(claim_path).resolve())
    document = _load_transcript_fixture(manifest, None)
    sidecar_argv = ['node' if sidecar.suffix in {'.mjs', '.js'} else os.sys.executable, str(sidecar)]
    with tempfile.TemporaryDirectory(prefix='.runtime-', dir=out) as temporary:
        scratch = Path(temporary)
        os.chmod(scratch, 0o700)
        runtime = start_owned_java_runtime(sidecar_argv, document, scratch)
        try:
            code, bundle = run_transcript_campaign(manifest_path, claim_path, output,
                verifier_base=runtime.verifier_url, fixture_document_path=str(scratch / 'fixture.json'), **options)
            qualify_local_report(out, bundle)
            return code, bundle
        finally:
            runtime.close()
            export_runtime_logs(out, runtime.logs)

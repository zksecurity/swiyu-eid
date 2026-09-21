# Swiyu integration harness

Bounded local evaluation harness: neutral provider contract, complete-claim campaigns, test providers and CLI runner.

The test providers included here are scaffolding. The OpenAC adapter can also execute its existing native proving artifacts. The semantic reference provider
checks real credential signatures and claim assertions, but exposes its fixture
and shares the reference oracle. It is not a ZK implementation.

## Real proof and transcript campaign

See [the provider guide](TRANSCRIPT-PROVIDERS.md) to run fresh native proofs through the selected Swiyu OID4VP flow, compare equivalent private fixtures, measure stages, and generate an HTML report. [The completed OpenAC experiment](../../docs/platform/transcript-privacy-findings.md) records a clean pair and deliberately leaking integrations that still pass proof verification.

## Complete-claim demo

Follow the environment setup in [the semantics guide](../semantics/README.md),
then run from the repository root:

```bash
integration/semantics/.venv/bin/python integration/harness/zkbench.py claims-demo \
  --claim integration/semantics/claims/composed-status.json \
  --output artifacts/platform-semantics
```

Open `artifacts/platform-semantics/report.html`. The report separates functional
outcomes from privacy observations, identifies the claim, implementation and
campaign, and reports desktop stage timings. The transparent provider should
produce privacy findings. `--inject-accept-all` demonstrates a functional failure;
`--inject-leak` adds explicit hidden fields to the presentation.

Claims and contribution rules are described in
[CONTRIBUTING.md](../semantics/CONTRIBUTING.md).

## Contract

- Manifest: `swiyu.provider-manifest.v1` with `id`, `title`, `kind` (`test-only`|`implementation`), `profiles`, `command` argv.
- Process protocol: JSONL on stdin/stdout, `swiyu.provider.v1` requests/responses.
- Operations: `initialize`, `prepare`, `present`, `verify`, `cleanup`.

## Commands

```bash
cd integration/harness

# Manifest check (absolute path works from any cwd)
python3 zkbench.py check ../providers/test-stub/manifest.json

# Demo: four cases (valid adult, underage, wrong nonce, wrong audience).
# False predicates and binding mismatches are expected rejections and count as passed.
# Exits 0 when all four pass. Does not include a crash case.
python3 zkbench.py demo --output /tmp/zk-demo-out

# Same four cases plus a failed provider; overall provider_error, exit 1
python3 zkbench.py demo --output /tmp/zk-demo-out --inject-crash

# Single operation
python3 zkbench.py call ../providers/test-stub/manifest.json initialize --input /tmp/in.json

# Manifest-level smoke/conformance report (JSON + standalone HTML)
python3 zkbench.py provider-run ../providers/test-stub/manifest.json \
  --output /tmp/swiyu-provider-report

# Full test suite (includes the complete-claim cryptography dependency)
PYTHONPATH=. ../semantics/.venv/bin/python -m unittest discover -s tests -v
```

`provider-run` creates `provider-report.json` (`swiyu.provider-report.v1`) and
`provider-report.html`. The report includes provider identity and profiles,
advertised operation readiness, lifecycle timings, presentation/proof/witness
sizes where available, and case outcomes. Its `swiyu.benchmark.v1` section always
contains startup, initialize, prepare, witness, prove, present, verify and cleanup
slots; unavailable heavy stages use `status: not_run` and `elapsed_ms: null`.

Use `--support PATH` to retain a link to a support declaration. Use
`--privacy-report PATH` with a `claims-demo` JSON report to import its privacy
summary. Leakage status is `clean`, `findings`, `inconclusive`, or `not_run`.
Provider launch and protocol failures are written as `provider_error` cases
before the command exits nonzero.

## Harness limits (desktop/test-only lifecycle hygiene)

- Bounded nonblocking pipe I/O: one deadline covers stdin write + stdout read.
- Default max request 1 MiB; stdout capped by `max_output_bytes` before a complete newline.
- stderr drained with bounded retention (8 KiB); provider session via `start_new_session`.
- Timeout/error/close sends SIGTERM/SIGKILL to the owned process group, including after the leader exits.
- Duplicate JSON keys, NaN/Infinity, unknown status, missing id, and invalid results rejected.
- `verified` must be a JSON boolean (string `"true"`/`"false"` is malformed and invalidates the client).
- EOF without bytes → `crashed`; partial bytes → `malformed`. No marker-file cleanup.

## Limitations

- `../providers/openac` runs the fixed OpenAC Swiyu age/status profile when its large local artifacts are present. It is not a generic all-circuits OpenAC adapter.
- The complete-claim oracle in `../semantics` drives `claims-demo`; the original four-case `demo` remains available for lifecycle checks.
- Relative manifest paths depend on cwd; use absolute paths from other directories.
- Demo timings are illustrative wall-clock only, not crypto benchmarks.
- Process-group cleanup is lifecycle hygiene, not a security sandbox.
- Providers must keep their children in the created process group; detached sessions are outside this cleanup mechanism.

## Integration privacy campaigns

See [PRIVACY.md](PRIVACY.md) for provider-neutral scenarios, collector contracts,
commands, observation limits, and HTML reports. `privacy-run` accepts a manifest,
a collector, or captured traces; detector controls are reported separately.

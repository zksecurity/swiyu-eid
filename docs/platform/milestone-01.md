# Milestone 01: local evaluation foundations

Implemented on 2026-09-14 in the existing checkout at
`73cd99e10284a4c8996150e2ab773fc6fee41f62`. Changes are local and uncommitted.

## What works

1. **Neutral provider process boundary.** A small manifest selects an executable
   and its claimed profiles. The Python runner exchanges versioned JSONL
   requests for initialization, preparation, presentation, verification and
   cleanup. It validates response IDs, statuses and operation result types;
   rejects ambiguous JSON; bounds requests, output and deadlines; and cleans up
   the process group it created. It imports no OpenAC code.
2. **Real OpenAC preparation through that boundary.** The adapter calls the
   existing SDK with a synthetic SD-JWT and returns an opaque prepared-state
   handle. The final cross-component smoke check used the neutral Python client
   against this Node adapter. **Correction from milestone 02 source review:**
   preparation includes issuer-signature verification under the supplied key;
   issuer trust selection and proving remain separate. Proof creation and verification explicitly report
   unavailable stages; they never manufacture a verifier verdict.
3. **Versioned predicate foundation.** `age-at-least.v1` has a fixed JSON
   descriptor, pinned digest, independent reference evaluator, public synthetic
   vectors and a small CLI. Invalid input and a false predicate are different
   outcomes. A changed definition cannot reuse the published version ID.
4. **Runnable reports.** The local demo tests an adult, an underage credential,
   a wrong nonce and a wrong audience. Expected rejections count as passing
   checks. Normal execution exits zero; optional crash injection produces a
   visible execution error and exits one. JSON and HTML include expected and
   observed results and wall-clock stage timings.

The demo provider is explicitly test-only and non-cryptographic. The age oracle
is not yet connected to profile-driven runner test selection. Neither demo
results nor preparation timings are comparative ZK benchmarks.

## Try it

Run from the repository root:

```sh
python3 integration/harness/zkbench.py demo --output artifacts/platform-demo
node integration/providers/openac/quickstart.mjs --output artifacts/platform-openac
```

Open `artifacts/platform-demo/report.html` and
`artifacts/platform-openac/quickstart-report.json`. The deliberately failing
variant is:

```sh
python3 integration/harness/zkbench.py demo --output artifacts/platform-errors --inject-crash
```

That command is expected to exit **1**. Reusing an output directory is supported.

From `integration/semantics`:

```sh
python3 -m semantics.cli check
python3 -m semantics.cli vectors
echo '{"predicate":"age-at-least.v1","private_inputs":{"birthdate":"2008-02-29"},"parameters":{"reference_date":"2026-02-28","min_age":18}}' | python3 -m semantics.cli evaluate
```

The last example returns `{"status":"ok","value":false}`: this version treats
a February 29 birthday as March 1 in a non-leap year. Future birthdates also
evaluate false, including for threshold zero. Date strings must be valid ASCII
Gregorian dates from year 0001 through 9999; the threshold is an integer from
0 through 150. These rules do not assert equivalence with OpenAC's existing
signed-cutoff and status semantics.

## Final validation

| Check | Result |
| --- | --- |
| New runner/manifest/report suite | 45 passed |
| Semantic registry/oracle/CLI suite | 56 passed |
| OpenAC adapter suite | 20 passed |
| Existing SDK runtime-contract and sidecar suite | 17 passed |
| Normal demo, including same-directory repeat | Exit 0; all four checks passed |
| Crash-injection demo | Exit 1; `provider_error` preserved |
| OpenAC quickstart and manifest check from another directory | Passed |
| Neutral client → real SDK preparation | Passed; unavailable verification produced `ARTIFACTS_MISSING` |

The **138 focused tests** ran on the local toolchain. Java, Android, real-proof
and clean-install CI-toolchain tests did not run. Existing SDK tests use test
doubles for proving. Commands and raw outputs are retained in
`/private/tmp/swiyu-platform-20260914/owned/final-validation/`; its `summary.json`
records arguments, working directories, exit codes and elapsed times.

A separate reviewer exercised the final public interfaces and cleared the
three repository components for this limited milestone. The review is
`/private/tmp/swiyu-platform-20260914/reports/milestone-review.md`.
An earlier runner repair was rejected for coercing verifier booleans and
manipulating test marker files; those workarounds were removed and replaced by
behavioral regression tests. Process cleanup covers the created session/group;
providers must not detach their children. This is not an execution sandbox.

The runner and semantic changes have recorded failing-test phases followed by
implementation and strengthened passing tests. **The OpenAC worker did not
follow the requested test-first order.** Its implementation is tested and
independently reviewed, but the trace does not support claiming TDD compliance.
Future delegated implementation will use a separate failing-test evidence gate
before permitting source changes.

HTML generation and escaping are tested. Automated visual inspection did not
run because browser policy blocked the local file preview.

## Resources and cleanup

No heavy build, key generation, real proof or emulator job ran. The supervisor
reserved 16 GiB free disk and enforced configured memory/swap limits. It paused
one worker under pressure; work resumed after measured headroom recovered.
Its final cleanup repair passed 25 tests, and the master reran the independent
orphan reproduction successfully: the child was gone without manual cleanup.
The final snapshot showed 26.69 GiB disk free and 44% free memory according to
the memory-pressure tool. No workers from this run remained active.

Obsolete demo directories and generated caches were removed. Current artifacts,
test evidence and losslessly compressed worker traces were retained. The
[worker ledger](worker-ledger.md) records model selection, observed usage,
rejected attempts, resource limits and the account-usage observations.

## Decisions and remaining work

- The provider interface wraps the existing SDK. The Android/Java transport
  refactor has not happened yet; the existing integration remains a reference.
- The first semantic version is a platform-owned definition. Contributor
  manifests declare support; they do not supply authoritative expected answers.
- OpenAC artifact paths require explicit configuration. File availability does
  not certify artifact provenance. Missing keys/backend and missing callback
  wiring are visible prerequisites.
- The intended end-to-end target is still the real Android test wallet in an
  emulator with a local host prover. No physical phone is required. No emulator
  performance, hardware-backed key behavior or physical-device timing is claimed.
- Full presentation profiles, optional-preparation orchestration, holder
  callbacks, Java dispatch, Android bridge, EPFL integration, differential
  leakage testing, reproducible benchmark campaigns and public PR automation
  remain open.

T01 is complete. This milestone supplies independently usable parts of T06,
T07, T14–T15, T17, T19–T20 and T55; their broader acceptance criteria remain
unchecked in the [backlog](../plans/zk-presentation-platform-backlog.md).
See [baseline.md](baseline.md) for prerequisites and
[architecture.md](architecture.md) for the implemented and planned boundaries.

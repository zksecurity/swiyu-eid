# M03-01 author task: OpenAC real-proof baseline

Task id: `m03-openac-baseline`

Goal: establish the smallest reproducible path toward a real OpenAC proof
baseline for profile `swiyu-age18-status-2k-v0`. Prefer evidence over edits. Do
not build large artifacts, download dependencies, start Android, or run an
emulator in this task.

Scope:

- Repository: `/Users/coding/Downloads/zkSecurity Internship/swiyu/swiyu-eid`.
- Read only the OpenAC provider package, its tests, existing SDK/circom/Rust
  profile entry points under `components/zkid/wallet-unit-poc`, and current
  milestone/backlog docs needed to identify the proof path.
- Keep scratch and logs under `/private/tmp/swiyu-milestone03/owned/scratch/m03-openac-baseline/`.
- If source edits are needed for a tiny reproducible command or report, use a
  strict RED -> GREEN loop and keep them under `integration/providers/openac/`
  or `docs/platform/`.

Required checks:

- Confirm whether `SWIYU_OPENAC_ARTIFACT_ROOT` and
  `SWIYU_OPENAC_KEYS_ROOT` point to all files needed by the provider.
- Confirm whether any existing command can produce and verify a genuine proof,
  or record the exact missing command/artifact/code path.
- If a real proof can be run without large setup, run it once, then mutate the
  verifier challenge/request context and confirm rejection.
- Confirm the run is not using `BindingTestBackend`, a fixture-only success, or
  a pre-recorded verifier result.
- Run the existing OpenAC adapter tests unless the environment is broken; report
  the exact command and outcome.

Deliverable:

- Prefer a concise report at
  `docs/platform/milestone-03-openac-baseline.md`.
- If blocked, the report must say whether the blocker is missing artifacts,
  missing proof invocation, missing verifier invocation, build failure, or
  unsupported host environment.
- Preserve raw command output only in the scratch directory.

Return only a `swiyu.worker-result.v1` JSON object in the final response. If the
task is blocked, use `status: "blocked"` and `next: "master_attention"`.

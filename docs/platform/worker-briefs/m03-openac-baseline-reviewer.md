# M03-01 reviewer task: OpenAC baseline review

Task id: `m03-openac-baseline`

Review the author result for the OpenAC real-proof baseline. Use a protocol and
security review posture. The review is about the evidence in this task, not a
formal proof-system audit.

The reviewer prompt should include:

- The complete author task from
  `docs/platform/worker-briefs/m03-openac-baseline-author.md`.
- The validated author `swiyu.worker-result.v1` JSON.
- The author-created report and any changed paths listed in that JSON.

Review checks:

- Every real-proof claim has matching command evidence, artifact/source hashes,
  and a verifier result.
- The challenge/request-context rejection was exercised independently from the
  presentation.
- The run did not silently use a test backend, stub, fixture-only success, or
  pre-recorded verifier response.
- Missing artifacts are reported as blockers instead of softened into partial
  success.
- Existing OpenAC adapter tests still pass or failures are accurately reported.
- `reviewed_paths` covers every author `changed_paths` entry before returning
  `status: "pass"`.

Return only a `swiyu.worker-result.v1` JSON object. Use `status:
"changes_requested"` and `next: "request_repair"` for any blocking or major
issue.

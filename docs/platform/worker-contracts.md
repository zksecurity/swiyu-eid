# Worker contract loop

Milestone 03 uses a small author/reviewer loop so the master can spend tokens on
decisions instead of rereading broad worker context.

The author worker returns one JSON object with
`contract_version: "swiyu.worker-result.v1"`, `role: "author"` and
`next: "start_reviewer"` when the task is ready for independent review. The
reviewer receives the original task plus that author result and returns the same
contract version with `role: "reviewer"`. A reviewer pass must list every author
`changed_paths` entry in `reviewed_paths`; requested changes must contain at
least one issue.

The helper script validates contracts and renders prompts:

```bash
python3 integration/tools/worker_contracts.py author-prompt \
  --task-id m03-openac-baseline \
  --task docs/platform/worker-briefs/m03-openac-baseline-author.md \
  --output /private/tmp/swiyu-milestone03/briefs/m03-openac-baseline-author.prompt.md

python3 integration/tools/worker_contracts.py validate \
  /private/tmp/swiyu-milestone03/results/m03-openac-baseline-author.json \
  --task-id m03-openac-baseline \
  --role author

python3 integration/tools/worker_contracts.py review-prompt \
  --task-id m03-openac-baseline \
  --task docs/platform/worker-briefs/m03-openac-baseline-author.md \
  --author-result /private/tmp/swiyu-milestone03/results/m03-openac-baseline-author.json \
  --output /private/tmp/swiyu-milestone03/briefs/m03-openac-baseline-review.prompt.md
```

The intended Cursor launch command is generated as an argument list by
`build_pi_command`. Use Composer 2.5 non-fast for bounded implementation or
mapping tasks and Grok 4.6 medium non-fast for independent protocol/security
review unless a task says otherwise. Usage fields in Cursor SDK output are
recorded when present; zero-valued SDK cost fields mean unreported cost, not
free work.

Author statuses:

- `ready_for_review`: work is complete enough to review.
- `blocked`: an external artifact, build, secret or manual decision is missing.
- `failed`: the task ran but did not satisfy its own acceptance checks.

Reviewer statuses:

- `pass`: no blocking or major issues in the named scope.
- `changes_requested`: at least one issue must be fixed before acceptance.
- `blocked`: the reviewer could not inspect enough evidence.
- `failed`: the review run itself failed.

The master only reads the full worker artifacts after a validator failure,
reviewer issue, blocked status, or when making a milestone-level architecture
decision.

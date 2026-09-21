# Worker and resource ledger

Cursor workers used explicit models with Fast disabled. Composer 2.5 handled bounded discovery/implementation; Grok 4.6 used medium effort for independent review and the final runner/supervisor repairs. No recursive delegation. Access was verified with small completed requests.

| Worker log | Model | Observed response span, s | Final reported input / output / totalTokens | Outcome |
| --- | --- | ---: | --- | --- |
| access-composer.jsonl | composer-2.5 | 0.0 | 10854 / 43 / 18139 | Completed |
| access-grok.jsonl | grok-4.6 | 0.0 | 14722 / 39 / 18473 | Completed |
| guard-final-fix.jsonl | grok-4.6 | 235.2 | 34 / 257 / 10494 | Completed |
| milestone-review.jsonl | grok-4.6 | 383.7 | 35 / 345 / 31387 | Repository components cleared; supervisor defect reproduced |
| openac-adapter.jsonl | composer-2.5 | 52.0 | 513 / 86 / 12877 | Resource stop; resumed |
| openac-fix.jsonl | composer-2.5 | 98.8 | 473 / 320 / 21528 | Reviewed/tested; test-first ordering failed |
| openac-resume.jsonl | composer-2.5 | 102.9 | 271 / 324 / 21165 | Functional draft; test-first ordering failed |
| platform-correctness.jsonl | grok-4.6 | 388.0 | 37 / 357 / 30994 | Accepted after separate public-interface review |
| platform-fix.jsonl | composer-2.5 | 464.0 | 23 / 405 / 37199 | Rejected: type coercion and test-specific cleanup; replaced |
| platform-implementation-retry.jsonl | composer-2.5 | 98.6 | 510 / 591 / 24822 | Repaired after independent review |
| platform-review.jsonl | grok-4.6 | 287.1 | 34 / 388 / 18328 | Completed |
| repo-map.jsonl | composer-2.5 | 77.8 | 33 / 332 / 23962 | Completed |
| resource-fix.jsonl | composer-2.5 | 304.7 | 38 / 327 / 15929 | Additional descendant cleanup defect found |
| resource-guard.jsonl | composer-2.5 | 177.1 | 135 / 330 / 17018 | Initial draft required repair |
| resource-review.jsonl | grok-4.6 | 144.4 | 17 / 237 / 8984 | Completed |
| semantics-fix.jsonl | composer-2.5 | 66.4 | 457 / 355 / 13926 | Completed |
| semantics.jsonl | composer-2.5 | 108.1 | 33 / 372 / 27344 | Completed |

These are the SDK's final-message fields, not an independently verified total token bill for each job. Full per-message usage is retained in `reports/worker-usage-raw.json` in the run-owned temporary directory. The SDK reported zero cost fields; those are treated as unavailable pricing evidence. Response spans omit startup/teardown and are not exact job durations. Failed launches with no model response have unknown usage.

The Composer repair was rejected on behavioral evidence; the bounded runner repair was escalated to Grok rather than repeating the same attempt. The OpenAC worker did not follow the requested test-first order. Future workers must first return a failing-test artifact before implementation is unlocked.

Run-owned logs, reports and resource telemetry are in `/private/tmp/swiyu-platform-20260914`. The final milestone describes accepted output; intermediate worker claims are not acceptance evidence.

## Resource outcome

No Android emulator, Rust release build, key generation or real proof job ran. The enforcing supervisor reserved 16 GiB free disk and used a 2 GiB owned-RSS cap and 512 MiB per-job swap-growth limit. It stopped one OpenAC worker after swap grew about 647 MiB; work resumed after measured memory headroom recovered. The final descendant-cleanup repair passed 25 supervisor tests. The master reran the independent orphan reproduction: `NO_LEAK`, child absent after cleanup without reviewer intervention.

Final snapshot: 16 GiB physical RAM, memory-pressure tool reported 44% free, 12,767.56 MiB swap used, 26.69 GiB disk free. A final process inspection found no remaining Cursor workers or guard jobs from this run. These are machine-wide measurements; they do not attribute all memory/swap changes to this task. Heavy runs still need a fresh admission check and providers must keep children in their process group.

Codex account weekly usage was observed at 41% at the start, 44% at a milestone and 46% near completion. The limit is shared across the account, so the change is not an exact task-consumption measurement. No reset credits were used.

Obsolete run-created demo directories were deleted; current artifacts and minimal failure evidence were preserved. Completed raw worker traces were compressed losslessly (`.jsonl.gz`); use the raw usage JSON for the original reported fields.


## Milestone 02 — complete claims

Run-owned evidence: `/private/tmp/swiyu-milestone02-20260914`. Composer 2.5
handled initial mapping, implementation and legacy verification. Grok 4.6 used
medium effort for crypto hardening, campaign repairs and independent reviews.
All Cursor launches explicitly disabled Fast and recursive workers. The master
owned the contract, admission decisions, coordination fixes and final evidence.

| Worker | Model / effort | Supervisor span, s | Last reported input / output / totalTokens | Assessment |
| --- | --- | ---: | --- | --- |
| campaign-green | composer-2.5 / default | 192.1 | 31 / 0 / 55386 | Initial campaign; review found substantive gaps |
| campaign-harden-green | grok-4.6 / medium | 810.6 | 31 / 0 / 56637 | Repair; independent review found remaining gaps |
| campaign-harden-red | grok-4.6 / medium | 207.9 | 702 / 346 / 25708 | Separate observed failures |
| campaign-harden | grok-4.6 / medium | 158.8 | 672 / 28 / 14470 | Interrupted before repair; required separate RED gate |
| campaign-red | composer-2.5 / default | 65.3 | 696 / 250 / 13264 | Separate failing-test gate |
| core-green | composer-2.5 / default | 163.8 | 116 / 329 / 43005 | Initial implementation; hardening followed |
| core-harden | composer-2.5 / default | 216.5 | 1130 / 418 / 45020 | Expanded validation; some edits preceded regressions |
| core-red | composer-2.5 / default | 49.2 | 575 / 219 / 18958 | Separate failing-test gate |
| core-review-close | grok-4.6 / medium | 73.5 | 299 / 197 / 10305 | Independent bypass closure; probes passed |
| core-review | grok-4.6 / medium | 297.6 | 356 / 310 / 22975 | Found forged Claim admission bypass |
| crypto-green | composer-2.5 / default | 152.1 | 144 / 483 / 46208 | Reference crypto implementation |
| crypto-harden | grok-4.6 / medium | 592.9 | 647 / 419 / 50231 | Crypto hardening; not strict test-first throughout |
| crypto-red | composer-2.5 / default | 57.4 | 618 / 286 / 25151 | Separate failing-test gate |
| final-closure | grok-4.6 / medium | 244.2 | 35 / 230 / 24997 | Found projection, public-context and malformed-wire gaps |
| final-repair-green | grok-4.6 / medium | 524.8 | 584 / 430 / 44430 | Repairs after verified RED; final closure reviewed separately |
| final-repair-red | grok-4.6 / medium | 293.3 | 664 / 280 / 25706 | Separate failing tests for support/leakage/pair wiring |
| final-review | grok-4.6 / medium | 269.4 | 2575 / 386 / 27416 | Three remaining defects plus missing pair wiring identified |
| legacy-verification | composer-2.5 / default | 61.2 | 491 / 294 / 6526 | 138 legacy checks passed (overlap with final suites) |
| projection-close | grok-4.6 / medium | 105.9 | 212 / 268 / 16890 | Independent closure of the final three findings |
| projection-fix | composer-2.5 / default | 126.1 | 35 / 296 / 23153 | Master RED regressions repaired; full suites passed |
| reviewer-access | grok-4.6 / medium | 16.3 | 16006 / 17 / 18327 | Model access verified |
| source-map | composer-2.5 / default | 74.0 | 1974 / 524 / 7673 | Bounded source map accepted |

Spans are measured from supervisor start to cleanup, including startup and
teardown. Usage columns preserve the final observed SDK message fields; they
are not a verified total bill. Full per-message observations are retained in
`reports/worker-usage-raw.json`. Zero cost fields were reported by the harness
but do not establish zero cost; actual charged usage is unknown.

Separate test-only worker invocations established RED before the core, crypto
and campaign implementations. Core/crypto intermediate hardening did not
consistently follow the requested ordering; their tests were still run and the
results independently reviewed. The master stopped the first campaign repair
attempt and required separate RED and GREEN invocations. The final repair also
used a separate failing-test gate, including the master's report/CLI regressions.
Worker self-reports are not treated as proof of test-first chronology.

No emulator, real prover build or physical device was used. The supervisor kept
the 2 GiB owned-RSS cap, 16 GiB disk reserve and 512 MiB per-job swap-growth
limit. The final resource/cleanup record and test totals are in milestone-02.md.
Codex weekly usage was observed at 49%, 53% and 58% during this milestone. This
limit is shared across the account; the change is not exact task consumption.
No reset credits were used.

## Milestone 03 — OpenAC baseline kickoff

Run-owned evidence: `/private/tmp/swiyu-milestone03-20260915`. The author task
used the worker contract loop in `integration/tools/worker_contracts.py`.
Composer 2.5 ran under the guard with Fast disabled in the launch command; the
final SDK message events reported model `composer-2.5`. The repaired author
contract self-reported `composer-2.5-fast`, so the ledger treats that field as
unreliable and uses the SDK event.

| Worker | Model / effort | Supervisor span, s | Last reported input / output / totalTokens | Assessment |
| --- | --- | ---: | --- | --- |
| m03-openac-baseline-author | composer-2.5 / default | 60.8 | 1212 / 717 / 12901 | Produced blocker report; first JSON failed schema because issues were strings |
| m03-openac-baseline-author-repair | composer-2.5 / default | 20.5 | 10351 / 964 / 18562 | Repaired contract shape only; validated as blocked |

The automation did not launch the reviewer because the validated author status
was `blocked`, not `ready_for_review`. Report:
`docs/platform/milestone-03-openac-baseline.md`. No Android emulator, Rust
release build, key generation, large artifact build or real proof run occurred.
The existing OpenAC adapter test suite was run locally and by the worker; it
passed 20 tests. Reported cost fields were zero in SDK output and remain unknown
cost, not free usage.

# Platform scope and evidence

The platform runs contributor implementations locally against shared Swiyu presentation profiles. Public registration is optional. A submission needs a reproducible adapter and a cursory maintainer review; an independent audit is optional supporting evidence.

The first execution target is one laptop: local issuer/verifier services, the Android test wallet in an emulator, and native host prover processes. No task or acceptance check requires a physical phone. The emulator should exercise the real wallet wherever practical. Device-specific test substitutions must be recorded. Host proving and emulator results do not establish physical-phone performance or hardware-backed key security.

## Ownership

The platform maintains the request/response contracts, registry, reference test expectations, local runner, protocol integration, observation capture, benchmark methodology, and reports. Contributors maintain their prover, verifier, input conversion, proof artifacts, optimizations, and audit evidence. Existing OpenAC behavior remains a regression reference during extraction.

We test declared support and look for observable counterexamples. We do not prove cryptographic security, infer semantics from arbitrary circuits, or certify that an implementation completely implements its declaration. The manifest selects a platform profile; it cannot redefine the expected answers or permitted disclosures.

## Result vocabulary

| Field or outcome | Meaning |
| --- | --- |
| Declared support | The contributor claims to implement this profile/version and input domain. |
| Passed | The identified check ran and observed its expected outcome. |
| Failed | The identified check ran and observed a counterexample. |
| Unsupported | A capability outside declared support was requested. A failed supported case cannot be relabeled unsupported. |
| Not run | The check was not attempted; it is not evidence of passing. |
| Inconclusive | The check ran but its evidence did not meet its decision requirements. |
| Execution error | Build, protocol, process, timeout, or resource failure prevented the intended check. |
| Audit evidence | An optional report, its reviewed revision and component scope, and any maintainer provenance check. |

Wallet refusal and verifier rejection are distinct observations. Functional failure cannot generate a successful competitive performance row. Test-only providers are visibly identified and excluded from rankings. Each result identifies the code/artifacts, profile, corpus, harness, execution environment, and observation stage actually used.

## Three example records

1. **Unaudited implementation:** claims age-profile support; the recorded tests pass; audit evidence is absent. It may be listed publicly, with no security certification implied.
2. **Failing implementation:** claims age-profile support; a recorded wrong-nonce case is accepted. The result is a failed binding check with reproduction evidence. Its speed is not a successful benchmark score.
3. **Newer implementation with an older audit:** tests refer to revision B; the attached report covers the proof library at revision A. The report is displayed with that scope and revision boundary. The circuit and integration are not automatically marked audited.

## Development and resource policy

For each implementation task, demonstrate a failing behavioral test first, implement the smallest useful slice, strengthen the tests with relevant adversarial/boundary cases, then rerun them. Keep red/green evidence and distinguish unavailable dependencies from passing tests. Every substantial protocol or security change receives a separate review context before acceptance.

Use explicit Cursor models through Pi with Fast disabled: Composer 2.5 for bounded implementation/discovery and Grok 4.6 for independent review. No recursive delegation without a budget. Record model, effort, elapsed time, usage when available, and outcomes; missing usage remains unknown. Keep worker summaries short and raw logs in the run-owned temporary directory.

Heavy jobs run through an enforcing resource supervisor. Reserve memory and disk for ordinary laptop use, bound workers and build parallelism, stop only owned jobs under pressure, and delete only reproducible temporary files created by this run. Preserve current results and minimal failure evidence. Public publication is a separate opt-in workflow and never happens automatically from local experiments.

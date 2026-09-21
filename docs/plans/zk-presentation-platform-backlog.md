**Swiyu ZK presentation platform: sequential implementation backlog**

Prepared 2026-09-14 from the agreed scope and inspection of the current `swiyu-eid` code. Implementation has started; only checked tasks have met their full acceptance criteria. The first implementation report is [milestone-01.md](../platform/milestone-01.md).

**What we are building**

A locally runnable evaluation framework for contributor-supplied ZK presentation implementations. Contributors declare support for platform-defined predicate/profile versions, supply their own implementation and adapter, and can test privately. An optional PR registers a public implementation; automated evaluation and cursory maintainer review support a public listing. Audit reports are optional supporting evidence.

The platform normalizes **declared semantic meaning** through versioned definitions, exact test inputs, and expected outcomes. It does not infer circuit semantics from code or prove that a provider implements its declaration. A passing result means no counterexample was found in the reported checks. Observed failures, unsupported cases, and inconclusive leakage experiments remain visible.

The platform owns the shared contracts, protocol integration, test generators/oracles, observation capture, benchmark methodology, CI, and public result presentation. Contributors own prover/verifier code, their adapters, witness construction, proof artifacts, optimizations, and independent audits. The OpenAC and EPFL adapters are the initial examples used to test the interface; they do not establish a commitment to maintain every contributor's cryptography.

**Starting point and important gaps**

- The Android wallet already parses signed `x_swiyu_zkp` policies, produces a typed runtime request, and submits an opaque result through the usual OID4VP path. Its injected runtime currently returns `RuntimeNotPackaged`.
- The verifier already has a ZK verification port and an HTTP adapter. Request validation and expected results still contain fixed OpenAC profile/circuit, birthdate, cutoff, and status assumptions.
- The OpenAC SDK has real witness/proof/verifier paths, native/WASM adapters, status handling, and benchmark scripts. Its public-value shape and SDK interfaces are implementation-specific; they should stay inside the provider.
- Cross-language fixtures and focused CI exist. The integration documentation says a complete issuer-wallet-verifier launcher is not implemented. Existing real-proof SDK tests are not evidence of a completed Android-to-verifier flow.
- EPFL is an external integration candidate, not an already imported component. Its documented full-Swiyu Noir example excludes non-revocation, whereas the existing OpenAC age path includes status checks. T05 establishes compatibility before any equal-profile comparison. See the [EPFL proof examples](https://github.com/eid-privacy/zkp-pocs).
- EPFL's [Spartan backend documentation](https://github.com/eid-privacy/spartan-backend) describes separate preparation/online work and example-specific verification helpers. T04 selects and pins the exact implementation; adapters must preserve the checks belonging to that selected path.

These are source-inspection findings, not a fresh execution of the existing test suite. T02–T04 produce that execution evidence.

**Boundaries that keep this small**

- Start with one age predicate and one shared presentation target, while retaining the existing OpenAC status profile separately. The accepted input domain and permitted disclosures are part of the profile.
- Reuse the imported wallet/verifier's experimental DCQL extension. Do not design a new credential protocol, arbitrary predicate language, or universal circuit compiler.
- Run the complete initial setup on one laptop: local issuer/verifier services, the real Android test wallet in an emulator, and native host prover/verifier processes. A physical phone is not required. Pin the emulator image and configuration alongside the other execution details.
- Use a process interface for desktop providers. Connect the emulated Android test wallet through a local test-only host bridge to avoid requiring every contributor to ship an Android library.
- Label that bridge as **host-proved wallet integration**. It sends synthetic test material to the local host and does not establish an on-device prover, a production wallet deployment, or end-to-end mobile privacy/performance.
- Measure all scoped software stages on the laptop, including the complete emulated-wallet OID4VP flow. Report native provider-stage benchmarks separately from the full integration campaign; control competing work and record emulator/service contention. These results do not measure physical-phone latency, battery, thermal behavior, or hardware-backed key protection. Emulator/test signing exercises the binding protocol, not a hardware-security claim.
- Keep the standard OID4VP path working. Keep local inputs, witnesses, prepared state, and full diagnostic logs private by default; export public results explicitly.
- Allow unaudited public submissions. Display claims, observed outcomes, and attached audit evidence separately. Maintainers check submission shape and report attribution; they do not repeat cryptographic audits.
- Defer iOS, native mobile packaging, hardware benchmark farms, general network/traffic analysis, arbitrary adaptive-query analysis, new revocation schemes, private hosted submissions, and accounts. Existing status behavior remains covered where a declared profile requires it.

**How to execute and review the list**

Follow T01–T64 in order as the recommended delivery sequence. “Blocked by” lists actual prerequisites, so independent work may continue if an upstream provider has a gap. Each task should be one independently reviewable PR or an equally small local change with a runnable demonstration.

Target **0.5–2 hours of human review per task**, including inspecting the diff, evidence, and a focused rerun. T05, T27, T31, T32, T49, T63, and T64 may use up to **3 hours**. These are review budgets, not promises that implementation or unattended builds finish in that time. Split a task further if its actual diff or checks cannot fit the review budget; do not silently weaken acceptance criteria.

**AFK** means the task can be implemented against the agreed contract without a new product/design decision. **HITL** marks a bounded semantic, compatibility, scope, or acceptance review. All public PRs still receive ordinary cursory maintainer review; these labels do not authorize automatic merging.

For every implementation task, the review packet includes the scoped diff, commands/configuration, one successful control, relevant negative or boundary cases, raw result artifacts, and all skipped/not-run checks. Documentation-only tasks use concrete example reviews rather than ceremonial tests. Platform-test expectations come from the trusted harness, not the submission under evaluation.

A provider compatibility gap can complete the *investigation* in T05, but cannot complete the *shared-profile demonstration* in T31/T64. Record any required circuit changes as separate contributor work with its own reproduction. Do not alter the common profile to conceal a bug, remove existing checks to claim equal work, or present separate profiles as an equivalent benchmark.

| Tasks | Deliverable |
| --- | --- |
| T01–T05 | Scope, reproducible baselines, and compatibility evidence |
| T06–T13 | OpenAC separated from common Swiyu integration |
| T14–T19 | Versioned predicates, profiles, manifests, and outcomes |
| T20–T27 | Local runner and first real wallet-to-verifier flow |
| T28–T32 | EPFL through the same contributor interface and wallet |
| T33–T40 | Automated correctness and adversarial integration tests |
| T41–T49 | Differential disclosure and linkability testing |
| T50–T55 | Reproducible stage benchmarks and local reports |
| T56–T62 | Simple PR workflow, optional audits, and public showcase |
| T63–T64 | Independent onboarding and release evidence |

**Sequential tasks**

<a id="t01"></a>

1. [x] **T01 — Freeze the scope and result labels**

   **Type:** HITL. **Blocked by:** None. **Human review:** 0.5–2 hours.

   **Build:** Record the agreed product: a local-first runner, optional public PR submissions with cursory maintainer review, optional audit reports, and contributor-owned cryptography. Define declared support, passed, failed, unsupported, not run, and inconclusive separately.

   **Checks:** Review sample result cards for an unaudited implementation, a failing implementation, and an audited older revision. None may imply that passing establishes soundness, zero knowledge, or complete semantic equivalence.

   **Done when:** An agreed one-page scope and three example result records; no audit requirement for submission.

   **Evidence:** [scope.md](../platform/scope.md) records the user-approved scope, laptop-only target, result vocabulary, contributor ownership, and all three examples.

<a id="t02"></a>

2. [ ] **T02 — Reproduce the existing fast integration checks**

   **Type:** AFK. **Blocked by:** T01. **Human review:** 0.5–2 hours.

   **Build:** Provide one documented invocation for the existing TypeScript runtime/sidecar tests, Android presentation tests, and Java OID4VP controller tests. Record the starting revision and distinguish real components from test doubles.

   **Checks:** Run from a clean checkout with the pinned toolchain. Deliberately break a shared request field and confirm the corresponding check fails. Report skipped checks and environment failures explicitly.

   **Done when:** A baseline report and reproducible commands; existing failures are recorded, not silently absorbed into the refactor.

<a id="t03"></a>

3. [ ] **T03 — Capture one real OpenAC proof baseline**

   **Type:** AFK. **Blocked by:** T02. **Human review:** 0.5–2 hours.

   **Build:** Run the existing fixed-profile witness, proof, and verification path with synthetic signed credentials and provisioned artifacts. Preserve the current status checks and record which parts still bypass the Android wallet or HTTP endpoint.

   **Checks:** Verify a real proof, reject its mismatched challenge, and retain the artifact/source hashes and raw measurements. Confirm the run did not select BindingTestBackend or a pre-recorded success response.

   **Done when:** One reproducible real-proof example, with its actual coverage level clearly labeled.

<a id="t04"></a>

4. [ ] **T04 — Capture one pinned EPFL proof baseline**

   **Type:** AFK. **Blocked by:** T01. **Human review:** 0.5–2 hours.

   **Build:** Select and pin one working full-Swiyu EPFL example and its exact proof backend. Start with the simplest supported path; do not assume the Noir/Barretenberg Android example and the Spartan/Vega example are interchangeable.

   **Checks:** Reproduce a proof and verification from upstream instructions and record command inputs, outputs, license, dependencies, and artifact sizes. Test one changed public challenge. Document any verifier-side helper checks required by that example.

   **Done when:** A small dependency lock and baseline reproduction note, or a precise upstream blocker with a failing reproduction.

<a id="t05"></a>

5. [ ] **T05 — Establish the overlap between the two implementations**

   **Type:** HITL. **Blocked by:** T03, T04. **Human review:** up to 3 hours.

   **Build:** Compare the exact accepted credential bytes/schema, authenticated claim path, date rule, issuer/type/expiry checks, holder binding, public disclosures, revocation, and setup assumptions of the two selected examples. Choose a common target profile only where support can be justified by documentation and exercised examples.

   **Checks:** Try the same synthetic signed credential and equivalent request on both examples. Record whether extra issuer material, canonical JSON, field order, length limits, or status inputs prevent a shared case. Keep the existing age-plus-status profile separate if it performs additional work.

   **Done when:** A compatibility matrix and common-profile target. Required circuit changes become separately scoped contributor work; they are not hidden in platform adapters.

<a id="t06"></a>

6. [ ] **T06 — Introduce the neutral provider contract with a test implementation**

   **Type:** AFK. **Blocked by:** T02. **Human review:** 0.5–2 hours.

   **Build:** Define a small versioned process interface for initialization, optional credential preparation, presentation creation, verification, and cleanup. Pass credential bytes, a profile reference/parameters, and authenticated request context; keep witness, R1CS, field-element, and compiler concepts inside providers.

   **Checks:** Drive a clearly labeled test-only provider through the lifecycle. Cover missing operations, malformed responses, process errors, and unsupported versions. A provider with no preparation stage must work without inventing a preparation cost.

   **Done when:** A runnable contract example that exercises the proposed boundary and is ineligible for performance rankings.

<a id="t07"></a>

7. [ ] **T07 — Wrap the OpenAC presentation path as the first provider**

   **Type:** AFK. **Blocked by:** T03, T06. **Human review:** 0.5–2 hours.

   **Build:** Implement preparation and presentation operations by calling the current OpenAC SDK and its existing proof artifacts. Keep its parsing, witness generation, and proof construction in the provider package.

   **Checks:** Through the new interface, reproduce the real baseline and the same rejection behavior. Confirm public envelope fields and required status inputs do not change accidentally.

   **Done when:** An OpenAC provider invoked through the neutral interface, with the old direct path available as a regression reference.

<a id="t08"></a>

8. [ ] **T08 — Wrap the OpenAC verification path as a provider**

   **Type:** AFK. **Blocked by:** T03, T06. **Human review:** 0.5–2 hours.

   **Build:** Expose the existing OpenAC verifier and required host-side checks through the neutral verification operation. Preserve authoritative issuer/status configuration and separate expected request context from values supplied in the presentation.

   **Checks:** Verify the baseline; change the expected issuer, challenge, and status snapshot independently and confirm rejection where the legacy profile requires it. A presentation-supplied expected value must not replace verifier configuration.

   **Done when:** An independently invocable verifier operation with real-proof regression evidence.

<a id="t09"></a>

9. [ ] **T09 — Expose wallet services through narrow callbacks**

   **Type:** AFK. **Blocked by:** T06, T07. **Human review:** 0.5–2 hours.

   **Build:** Provide shared callback messages for holder signing and the trust/status services needed by the legacy adapter. Pass a key handle and signing request rather than a device private key. Keep provider-specific signature formatting inside the adapter.

   **Checks:** Exercise a signer whose private key is unavailable to the provider, a missing key handle, callback failure, and issuer/status lookup failure. Confirm callbacks cannot bypass the harness's selected test configuration.

   **Done when:** OpenAC can present through the callback contract, and callback traffic is classified as private runner data.

<a id="t10"></a>

10. [ ] **T10 — Route the Java verifier through a provider registry**

   **Type:** AFK. **Blocked by:** T08. **Human review:** 0.5–2 hours.

   **Build:** Replace hard-coded OpenAC dispatch and result-shape assumptions with configured provider registrations behind the existing ZK verification port. Retain legacy policy validation until the semantic registry replaces it.

   **Checks:** Submit the legacy real proof through the normal verification endpoint. Test unknown provider IDs, mismatched response IDs, verifier crashes/timeouts, and an ordinary SD-JWT request.

   **Done when:** The Java integration can select an implementation without importing its proof-system internals.

<a id="t11"></a>

11. [ ] **T11 — Route the Android handoff through a provider registration**

   **Type:** AFK. **Blocked by:** T06, T09. **Human review:** 0.5–2 hours.

   **Build:** Generalize the existing typed runtime handoff and dependency injection so the wallet can select a configured provider. Keep authenticated request parsing, credential selection, user approval, and ordinary OID4VP submission in the wallet.

   **Checks:** Focused app tests cover provider selection, unsupported provider, cancellation, missing runtime, and successful opaque-envelope submission. Ordinary selective-disclosure behavior remains covered.

   **Done when:** A provider-neutral Android seam; a test double is acceptable here and must be labeled as such.

<a id="t12"></a>

12. [ ] **T12 — Pin shared request and response vectors across languages**

   **Type:** AFK. **Blocked by:** T10, T11. **Human review:** 0.5–2 hours.

   **Build:** Replace the single-backend golden fixture with versioned neutral examples consumed by TypeScript, Kotlin, and Java tests. Specify canonical request-context serialization and required binding inputs without dictating the backend's internal hash construction.

   **Checks:** Check nonce, full client identifier, query/profile parameters, date/time, response URI, and any required transaction fields across all consumers. Include missing fields, Unicode, number boundaries, and a context mutation.

   **Done when:** Cross-language contract tests fail on serialization drift or dropped context.

<a id="t13"></a>

13. [ ] **T13 — Remove OpenAC dependencies from the shared integration surface**

   **Type:** AFK. **Blocked by:** T07, T08, T12. **Human review:** 0.5–2 hours.

   **Build:** Finish the extraction using the new seams: shared registration, protocol handling, and runner code must not depend on OpenAC constants, ten-public-value layouts, circuit IDs, or SDK types. Preserve provider-owned legacy helpers.

   **Checks:** Build and exercise the shared transport with OpenAC disabled and the test provider installed. Run the legacy regression path with OpenAC enabled. Inspect the dependency graph for hidden imports and global initialization.

   **Done when:** A small separation diff and a before/after dependency map; no broad relocation of unrelated components.

<a id="t14"></a>

14. [ ] **T14 — Specify the bounded claim language and predicate catalog**

   **Type:** HITL. **Blocked by:** T05. **Human review:** 0.5–2 hours.

   **Build:** Define exact attribute bindings, typed verifier-given parameters, required cryptographic assertions, bounded AND/OR conditions and allowed disclosures. Start with equality, set membership and date-on-or-before predicates. Specify missing/invalid input behavior separately from a false predicate. Keep the older age oracle as a separate versioned experiment.

   **Checks:** Review type mismatches, inclusive date boundaries, missing attributes on inactive OR branches, mandatory assertions outside OR, changed given inputs and changed semantic dependencies. Include an age-free claim and a composed condition.

   **Done when:** A bounded claim specification with reviewed expected examples; no circuit compiler or unrestricted programming language. Milestone 02 provides the executable draft; exact legacy/common-profile compatibility remains tied to T05.

<a id="t15"></a>

15. [ ] **T15 — Implement the predicate reference evaluator and generators**

   **Type:** AFK. **Blocked by:** T14. **Human review:** 0.5–2 hours.

   **Build:** Implement the platform-owned claim evaluator, pinned predicate catalog and bounded generators for true, false, Boolean-branch and cryptographic-assertion cases. This evaluates test data; it does not certify the contributor's circuit.

   **Checks:** Use reviewed vectors and independently issued signed fixtures. Check that generated cases actually meet their requested category, that changing a leaf does not incorrectly assume the full tree becomes false, and that seeds reproduce the same inputs. Record unconstructible or omitted coverage.

   **Done when:** An executable oracle used by the runner, independent of provider outputs. Milestone 02 implements this for the synthetic reference package; the integration profile still needs T05/T16 compatibility evidence.

<a id="t16"></a>

16. [ ] **T16 — Register complete presentation profiles**

   **Type:** AFK. **Blocked by:** T05, T15. **Human review:** 0.5–2 hours.

   **Build:** Define immutable versioned profiles combining the predicate with its authenticated claim source, exact credential support domain, issuer/type/time rules, holder/session binding, allowed disclosures, and expected failure behavior. Preserve a distinct legacy OpenAC status profile and register the common target from T05.

   **Checks:** Validate profile definitions and show that changing binding, disclosure, status, or credential-format requirements changes the comparison identity. Unsupported mandatory requirements cannot be treated as a pass.

   **Done when:** Profile records that select concrete tests and comparison groups; publication does not claim that providers formally implement them.

<a id="t17"></a>

17. [ ] **T17 — Validate contributor manifests against the registry**

   **Type:** AFK. **Blocked by:** T06, T16. **Human review:** 0.5–2 hours.

   **Build:** Define the manifest schema for implementation identity, source/artifact pins, supported profile versions, accepted input limits, lifecycle support, execution targets, dependencies, and optional audit references. Support a private local source path as well as public pinned sources.

   **Checks:** Accept minimal valid local and public manifests. Reject unknown profile versions, ambiguous pins, conflicting IDs, malformed limits, and attempts to redefine a profile's permitted disclosures.

   **Done when:** A local manifest-check command with actionable diagnostics and no network registration requirement.

<a id="t18"></a>

18. [ ] **T18 — Map registered profiles into the existing DCQL extension**

   **Type:** AFK. **Blocked by:** T10, T11, T16. **Human review:** 0.5–2 hours.

   **Build:** Use the existing experimental x_swiyu_zkp route to request a registered profile and its permitted parameters. Generate/validate wallet and verifier policy data from the shared definitions; keep backend circuit identifiers inside implementation metadata.

   **Checks:** Round-trip legacy and common-profile requests through signed request creation, Android parsing, and Java expected-context construction. Mutated parameters, unsupported profiles, and incompatible credential queries fail predictably.

   **Done when:** One documented experimental wire mapping with a working request round trip; no claim of compatibility with unmodified official wallets.

<a id="t19"></a>

19. [ ] **T19 — Standardize execution outcomes and test selection**

   **Type:** AFK. **Blocked by:** T16, T17. **Human review:** 0.5–2 hours.

   **Build:** Select tests from the requested profile and the submission's declared support. Represent predicate false, wallet refusal, verifier rejection, unsupported capability, crash, timeout, skipped test, and inconclusive leakage analysis separately.

   **Checks:** Exercise every outcome with controlled providers. A claimed supported case that fails cannot be reclassified as unsupported to improve its score. Reports distinguish wallet-side refusal from verifier-side enforcement.

   **Done when:** A result schema and selection logic reused by local runs, CI, and the catalog.

<a id="t20"></a>

20. [ ] **T20 — Provide a single local command for a submission**

   **Type:** AFK. **Blocked by:** T13, T17, T19. **Human review:** 0.5–2 hours.

   **Build:** Discover an implementation from its directory, validate its manifest, and run a named profile/case through the neutral interface. Write a self-contained local result directory with a stable run ID and clear exit status.

   **Checks:** Run from a clean clone with a private provider directory. Test bad paths, failed builds, failed cases, and reruns. Confirm no account, PR, or automatic result upload is needed.

   **Done when:** A working local check command and one-command sample run.

<a id="t21"></a>

21. [ ] **T21 — Make provider builds and artifacts reproducible**

   **Type:** AFK. **Blocked by:** T20. **Human review:** 0.5–2 hours.

   **Build:** Build only the selected provider with locked sources/dependencies and record hashes of the executable, circuits/programs, keys, and relevant configuration. Reuse the current OpenAC build machinery within its package.

   **Checks:** Rebuild in a fresh environment, detect a changed artifact or missing download, and invalidate a mismatched cache. Do not require unrelated proof toolchains to run one provider.

   **Done when:** A build record sufficient to identify exactly what was measured, without asserting its security.

<a id="t22"></a>

22. [ ] **T22 — Exercise preparation, reuse, and cleanup through the runner**

   **Type:** AFK. **Blocked by:** T07, T20, T21. **Human review:** 0.5–2 hours.

   **Build:** Support opaque provider-owned prepared-state handles, explicit fresh/reused runs, and reset/cleanup operations. Separate setup artifacts, credential-dependent state, and session-dependent work.

   **Checks:** Run no-preparation and preparation-enabled providers. Test two credentials, multiple fresh requests, restart, cleanup, and stale-handle use. Ensure request-specific work is not accidentally reused as credential-only preparation.

   **Done when:** A repeatable lifecycle driver, with state kept in the local run workspace.

<a id="t23"></a>

23. [ ] **T23 — Separate prover and verifier execution inputs**

   **Type:** AFK. **Blocked by:** T08, T20. **Human review:** 0.5–2 hours.

   **Build:** Run verification in a separate process/workspace that receives only the public presentation and independently constructed verifier context. Keep credential plaintext, witnesses, signing handles, and prepared state on the prover side.

   **Checks:** Use a controlled verifier that attempts to read a prover-only canary and confirm it is unavailable. Verify a real proof after the proving process exits; changing expected context still changes the outcome.

   **Done when:** A verifiable integration boundary that does not accidentally make plaintext part of verification.

<a id="t24"></a>

24. [ ] **T24 — Generate real signed test credentials**

   **Type:** AFK. **Blocked by:** T03, T15, T16. **Human review:** 0.5–2 hours.

   **Build:** Create a platform-owned synthetic credential factory with test issuer keys, holder-key handles, realistic SD-JWT disclosures, and profile-specific formats. Preserve exact signed bytes for providers rather than letting adapters silently reissue or rewrite credentials.

   **Checks:** Generate valid credentials and individually controlled signature, disclosure, date, type, and status defects. Independently check the valid fixtures and their expected semantics. Reproduce a credential corpus from its seed.

   **Done when:** A shared fixture corpus accepted by the compatible providers, with legacy-only formats clearly identified.

<a id="t25"></a>

25. [ ] **T25 — Launch the local issuer/verifier environment**

   **Type:** AFK. **Blocked by:** T18, T20, T24. **Human review:** 0.5–2 hours.

   **Build:** Add a reproducible launcher around the imported issuer/verifier and their required storage/trust configuration. Establish a normal SD-JWT control flow and create fresh signed ZK requests using the actual verifier endpoints.

   **Checks:** Start from empty local state, issue a synthetic credential, create/fetch a request, and submit a baseline response. Test health-check failure, restart, and teardown. Keep this distinct from SDK-only proof tests.

   **Done when:** A local integration environment and captured ordinary-protocol control run.

<a id="t26"></a>

26. [ ] **T26 — Run the Android wallet in a laptop emulator with the host provider bridge**

   **Type:** AFK. **Blocked by:** T09, T11, T20, T25. **Human review:** 0.5–2 hours.

   **Build:** Launch a pinned Android emulator on the laptop and replace the unpackaged runtime in a dedicated wallet test build with a bridge to the runner on that same machine. Use existing wallet credential/key callbacks and the actual request/response flow so process-based contributors can be exercised without writing Kotlin, porting their prover to Android, or owning a phone. Document any test substitutions for device-specific services.

   **Checks:** Run a controlled provider from the emulator with synthetic credentials and no connected physical device. Exercise cancellation, disconnect, signing callback, and cleanup. Confirm the bridge is absent from release builds and cannot publish private test inputs. Label emulator/test key behavior without asserting hardware-backed protection.

   **Done when:** A reproducible laptop-only Android integration route explicitly labeled host-proved, with the emulator configuration and any device-service substitutions recorded; it supplies no physical-phone performance or security claim.

<a id="t27"></a>

27. [ ] **T27 — Complete the OpenAC wallet-to-verifier round trip**

   **Type:** AFK. **Blocked by:** T07, T08, T23, T24, T25, T26. **Human review:** up to 3 hours.

   **Build:** Use a credential held by the real test wallet, a fresh signed verifier request, the OpenAC provider, and the ordinary vp_token submission endpoint. Retain the legacy profile's required status/trust behavior.

   **Checks:** Complete one real accepted presentation and one mismatched/replayed request rejection. Capture evidence of actual wallet selection, holder signing, proof creation, HTTP submission, and final verifier state.

   **Done when:** The first complete wallet integration baseline, with compute placement and any test trust services identified.

<a id="t28"></a>

28. [ ] **T28 — Adapt EPFL initialization and credential preparation**

   **Type:** AFK. **Blocked by:** T04, T06, T09, T21, T22, T24. **Human review:** 0.5–2 hours.

   **Build:** Inside its own provider directory, wrap the selected EPFL implementation's setup and preparation using the shared credential input. Expose no-preparation if that path has no separate reusable stage; keep any offline proof artifacts private.

   **Checks:** Prepare two different supplied credentials and repeat with the same input. Detect unsupported format/length and stale artifacts. Confirm the wrapper does not keep using a bundled fixed credential.

   **Done when:** A working EPFL preparation operation and declared limits, without modifications to shared protocol code.

<a id="t29"></a>

29. [ ] **T29 — Adapt EPFL presentation creation to live requests**

   **Type:** AFK. **Blocked by:** T28, T18. **Human review:** 0.5–2 hours.

   **Build:** Construct the selected EPFL witness/input format from the provided credential and fresh authenticated request context. Obtain holder signatures through the shared callback rather than a bundled private key.

   **Checks:** Generate presentations for two newly issued credentials and two distinct verifier requests. Check input mappings against upstream requirements and confirm each presentation is associated with the intended session.

   **Done when:** An EPFL presentation operation using live test inputs; circuit changes, if required, remain a separate contributor patch.

<a id="t30"></a>

30. [ ] **T30 — Adapt EPFL verification with all required checks**

   **Type:** AFK. **Blocked by:** T04, T23, T28, T29. **Human review:** 0.5–2 hours.

   **Build:** Wrap its real verifier and any required external checks, supplying expected public values from the runner's verifier context. Map its result to the common outcome schema without accepting public values merely because the proof supplies them.

   **Checks:** Accept a matching real presentation and test a changed nonce, issuer context, and public input. Where relevant, demonstrate that omitted expected values are rejected by the adapter instead of being filled from the proof.

   **Done when:** An independently executable EPFL verifier with its full documented verification path represented.

<a id="t31"></a>

31. [ ] **T31 — Run both providers through the same host integration scenario**

   **Type:** AFK. **Blocked by:** T27, T29, T30, T19. **Human review:** up to 3 hours.

   **Build:** Execute the shared target profile with the same signed input corpus and request semantics, selecting each provider only through configuration. Keep extra requirements or unsupported domains in separate result groups.

   **Checks:** Compare expected outcomes, supported input domains, declared public context, and actual endpoint results. No shared Java/Kotlin code changes may be needed merely to select EPFL. An unresolved T05 compatibility gap prevents claiming this shared-profile milestone.

   **Done when:** A side-by-side integration report grounded in the same challenge, plus explicit differences rather than an artificial combined score.

<a id="t32"></a>

32. [ ] **T32 — Complete the EPFL round trip in the same Android test wallet**

   **Type:** AFK. **Blocked by:** T26, T31. **Human review:** up to 3 hours.

   **Build:** Use the existing host bridge and provider registration to present through EPFL from the real wallet. Reuse the same credential selection, consent, request authentication, and OID4VP submission path as OpenAC.

   **Checks:** Complete accepted and rejected sessions with the second provider. Switch implementations through registration/configuration and confirm no provider-specific wallet-screen or transport edits are necessary.

   **Done when:** Two real wallet integrations demonstrating the contributor seam; both host-proved results are labeled accurately.

<a id="t33"></a>

33. [ ] **T33 — Add issuer-authenticity and trust adversarial cases**

   **Type:** AFK. **Blocked by:** T24, T31. **Human review:** 0.5–2 hours.

   **Build:** Test the complete flow with invalid signatures, wrong issuer keys, unaccepted issuers, wrong credential type, and altered signed payloads. Use actual proofs where the provider can produce them; otherwise record its refusal point.

   **Checks:** Each corrupted case must have a valid neighboring control. Capture whether rejection occurs before proving or during verification. Report a provider that unexpectedly accepts as a finding, without claiming exhaustive soundness testing.

   **Done when:** A provider-independent authenticity/trust suite and endpoint-level outcome report.

<a id="t34"></a>

34. [ ] **T34 — Add authenticated-claim and encoding cases**

   **Type:** AFK. **Blocked by:** T24, T31. **Human review:** 0.5–2 hours.

   **Build:** Exercise swapped/missing disclosures, altered disclosure hashes, duplicate or ambiguous claim locations, JSON ordering/encoding variations, and documented credential-size boundaries. Derive validity from the registered profile's accepted domain.

   **Checks:** Demonstrate that a date from another credential cannot substitute unnoticed in covered cases. Separate valid alternative encodings from deliberately malformed credentials and distinguish unsupported declared domains.

   **Done when:** A shared parsing/provenance corpus that catches observed host/circuit integration disagreements.

<a id="t35"></a>

35. [ ] **T35 — Add age and credential-time boundary cases**

   **Type:** AFK. **Blocked by:** T15, T24, T31. **Human review:** 0.5–2 hours.

   **Build:** Run the predicate oracle's boundary corpus through each claimed profile. Include expiry/not-before checks only where the profile specifies them, and inject a controlled verifier clock.

   **Checks:** Cover before/on/after birthday, leap-day rules, invalid/future dates, threshold limits, and before/at/after time boundaries. Confirm both positive and negative outcomes match the reviewed oracle.

   **Done when:** A repeatable time-boundary integration suite independent of wall-clock calendar changes.

<a id="t36"></a>

36. [ ] **T36 — Add holder-binding adversarial cases**

   **Type:** AFK. **Blocked by:** T09, T31, T32. **Human review:** 0.5–2 hours.

   **Build:** Exercise wrong credential key, wrong signing handle, absent signature, changed signed context, and a signature copied from another presentation. Keep software-key and hardware-backed signing capability labels distinct.

   **Checks:** Use fresh valid controls alongside each mutation. Capture wallet refusal versus verifier rejection, and ensure the signing callback was invoked with the expected context in successful cases.

   **Done when:** A bounded holder-binding suite for the declared profile, without claims about biometric identity or hardware attestation.

<a id="t37"></a>

37. [ ] **T37 — Add request-binding and replay cases**

   **Type:** AFK. **Blocked by:** T31, T32. **Human review:** 0.5–2 hours.

   **Build:** Test changed nonce, audience/full client identifier, query ID, profile/parameters, response target where required, and duplicate submission after success. Include concurrent attempts to consume the same session.

   **Checks:** Verify that context mutations covered by the profile are rejected and that session-state replay behavior matches the verifier contract. A nonce-bound proof alone must not be reported as evidence of one-time session consumption.

   **Done when:** Tests that cover both proof-context integration and the actual verifier session lifecycle.

<a id="t38"></a>

38. [ ] **T38 — Test unsupported requests, cancellation, and disclosure fallback**

   **Type:** AFK. **Blocked by:** T19, T32. **Human review:** 0.5–2 hours.

   **Build:** Exercise unsupported profiles, missing claims, predicate false, runtime failure, cancellation, oversized responses, and timeouts through the wallet/verifier flow. Require the selected privacy profile's defined failure behavior.

   **Checks:** Confirm ZK failure does not silently send the raw credential or an ordinary SD-JWT presentation. Keep local diagnostic details separate from verifier-visible errors and inspect the actual submitted response.

   **Done when:** A failure-path suite with captured transcripts and explicit no-disclosure expectations.

<a id="t39"></a>

39. [ ] **T39 — Test prepared-state freshness and cross-credential mixing**

   **Type:** AFK. **Blocked by:** T22, T31. **Human review:** 0.5–2 hours.

   **Build:** Exercise fresh/reused prepared state across requests, credentials, provider versions, and profile versions. Add legacy status-snapshot changes where applicable.

   **Checks:** Swap prepared handles between two credentials, update an input assumed invariant, restart a process, and change the session. Check declared invalidation behavior and ensure warm-state tests are not simply replaying stored proofs.

   **Done when:** A lifecycle regression suite for both preparation-enabled and no-preparation implementations.

<a id="t40"></a>

40. [ ] **T40 — Generate and replay a bounded adversarial campaign**

   **Type:** AFK. **Blocked by:** T33, T34, T35, T36, T37, T38, T39. **Human review:** 0.5–2 hours.

   **Build:** Combine the existing categories into deterministic profile-specific test generation with logged seeds and a simple one-field-at-a-time reducer for failures. Dispatch through the actual integration path.

   **Checks:** Reproduce a seeded failure from its saved case; reduce it without changing the failing outcome. Distinguish test-generator defects, environmental failures, and submission failures.

   **Done when:** One command that creates a reproducible observed counterexample report rather than an unexplained red CI job.

<a id="t41"></a>

41. [ ] **T41 — Capture verifier-visible observations before normalization**

   **Type:** AFK. **Blocked by:** T25, T27. **Human review:** 0.5–2 hours.

   **Build:** Record raw vp_token bytes, parsed envelopes, public inputs available at the verifier, transport fields, error/status behavior, presentation count, sizes, and timing boundaries. Label internal callback/debug traffic separately from what the verifier can observe.

   **Checks:** Compare capture output with a controlled endpoint's received bytes. Verify that success and failure paths are both recorded, and that private runner diagnostics are not accidentally treated as protocol disclosure.

   **Done when:** A versioned observation format with raw evidence retained locally.

<a id="t42"></a>

42. [ ] **T42 — Check public outputs against profile disclosure rules**

   **Type:** AFK. **Blocked by:** T16, T41. **Human review:** 0.5–2 hours.

   **Build:** Validate structured observations against the profile's allowed fields and values, including documented implementation metadata. Create a normalized comparison view while preserving raw observations and their sizes.

   **Checks:** Inject an extra holder key, credential ID, unexpected claim, and a permitted public field. Confirm forbidden disclosures fail and permitted variation does not. A provider cannot add an exemption through its manifest.

   **Done when:** A deterministic disclosure check and a report pointing to the offending observable field.

<a id="t43"></a>

43. [ ] **T43 — Detect recognizable secrets in serialized observations**

   **Type:** AFK. **Blocked by:** T24, T41. **Human review:** 0.5–2 hours.

   **Build:** Generate synthetic canary claims and search verifier-visible representations for exact values and a small documented set of encodings/digests. Decode known JSON/base64/byte fields with bounded parsing.

   **Checks:** Detect deliberately exposed birth dates, identifiers, holder keys, and hashed canaries. Include public-value overlaps and unrelated random-byte controls; describe these as bounded detectors, not generic decryption or proof inspection.

   **Done when:** A reproducible canary detector with locations, matched representation, and false-positive controls.

<a id="t44"></a>

44. [ ] **T44 — Generate semantically equivalent credential pairs**

   **Type:** AFK. **Blocked by:** T15, T24, T31. **Human review:** 0.5–2 hours.

   **Build:** Use the oracle and profile disclosure rules to create pairs/groups with identical permitted results but varied hidden values. Keep request/public context controlled and re-sign each changed credential legitimately.

   **Checks:** Confirm both members are valid and satisfy the same profile. Vary birth date, hidden claims, holder key, and credential identity independently where allowed; verify that public issuer/type differences do not accidentally contaminate a comparison.

   **Done when:** A seeded equivalence-case generator that supplies the next differential tests.

<a id="t45"></a>

45. [ ] **T45 — Compare structures, public values, and failure behavior**

   **Type:** AFK. **Blocked by:** T38, T41, T42, T44. **Human review:** 0.5–2 hours.

   **Build:** Run equivalent pairs repeatedly through the full integration and compare normalized field structure, permitted/public values, response count, and error classes. Normalize only explicitly justified session/random fields.

   **Checks:** Detect seeded secret-dependent fields, ordering/structure, and failure messages. Include non-equivalent inputs as excluded controls and produce a paired reproduction for each finding.

   **Done when:** An automatic differential leakage suite with inspectable evidence and explicit comparison assumptions.

<a id="t46"></a>

46. [ ] **T46 — Detect repeated identifiers across sessions and verifiers**

   **Type:** AFK. **Blocked by:** T22, T41, T44. **Human review:** 0.5–2 hours.

   **Build:** Compare repeated presentations of one credential with presentations of different credentials across fresh requests and verifier identities. Include fresh and reused preparation state.

   **Checks:** Detect seeded stable holder keys, identifiers, and commitments while excluding public constants and profile-permitted linkability. Verify that fresh randomness and independent credentials provide negative controls.

   **Done when:** A same-credential versus different-credential linkability test with field-level evidence.

<a id="t47"></a>

47. [ ] **T47 — Check opaque proof material for observable repetition**

   **Type:** AFK. **Blocked by:** T41, T44, T46. **Human review:** 0.5–2 hours.

   **Build:** Retain proof bytes in the observation model and add bounded repeated-value/chunk analysis for opaque data. Treat format headers and other shared constants separately; allow contributor decoders as extra diagnostics, never as the sole evidence source.

   **Checks:** Detect a stable credential-specific chunk embedded in otherwise changing proof bytes. Test random proofs, common prefixes, and constant format/version fields to assess false positives.

   **Done when:** A limited opaque-byte correlation detector that does not erase the proof during normalization or claim cryptographic analysis.

<a id="t48"></a>

48. [ ] **T48 — Add size and coarse timing differential experiments**

   **Type:** AFK. **Blocked by:** T41, T44. **Human review:** 0.5–2 hours.

   **Build:** Compare equivalent input classes using response size and repeated end-to-end timing samples on a controlled runner. Randomize/interleave cases, record cold/warm state, and predefine the statistical decision and minimum sample requirements.

   **Checks:** Detect injected padding and delay channels and avoid flagging clean controls under the chosen rule. Label low-sample/noisy environments inconclusive; do not infer indistinguishability from a non-significant result.

   **Done when:** Automatic size analysis and a repeatable coarse timing experiment with raw samples and stated limits.

<a id="t49"></a>

49. [ ] **T49 — Measure the leakage suite against a seeded defect corpus**

   **Type:** AFK. **Blocked by:** T42, T43, T45, T46, T47, T48. **Human review:** up to 3 hours.

   **Build:** Package deliberately leaking test providers/wrappers for the previously covered channels, alongside clean controls. Record detector coverage, false positives, and channels explicitly outside the suite.

   **Checks:** Run the complete corpus through the shared integration. Each expected finding has a saved reproduction, and an unknown/uncovered channel cannot appear as a passed check.

   **Done when:** A small empirical evaluation of the testing framework itself, suitable for substantiating the research contribution.

<a id="t50"></a>

50. [ ] **T50 — Measure lifecycle stages at runner-owned boundaries**

   **Type:** AFK. **Blocked by:** T22, T23, T31, T41. **Human review:** 0.5–2 hours.

   **Build:** Measure build/setup, credential preparation, artifact loading, online presentation, backend verification, and the whole OID4VP round trip at defined boundaries. Mark provider-reported internal breakdowns separately.

   **Checks:** Use controlled providers with known stage delays to verify attribution. Ensure witness generation, callback waits, encoding, and loading appear in their documented stage; avoid adding overlapping timers into a misleading total.

   **Done when:** Stage metrics for both real providers, including zero/not-applicable distinctions and host-proved compute placement.

<a id="t51"></a>

51. [ ] **T51 — Measure proof and presentation sizes consistently**

   **Type:** AFK. **Blocked by:** T41, T50. **Human review:** 0.5–2 hours.

   **Build:** Record raw proof bytes, encoded proof bytes, full vp_token bytes, and complete relevant response size. Count setup keys/artifacts separately.

   **Checks:** Check known-sized fixtures with base64 and JSON overhead, multiple transport wrappers, and failures. Cross-check counts against captured endpoint bytes rather than contributor-reported lengths.

   **Done when:** A documented size comparison that shows both cryptographic payload and integration overhead.

<a id="t52"></a>

52. [ ] **T52 — Measure process memory and persistent preparation storage**

   **Type:** AFK. **Blocked by:** T21, T22, T50. **Human review:** 0.5–2 hours.

   **Build:** Measure peak memory for the selected provider process tree or isolated execution unit and size of setup/prepared artifacts. Record method, platform, and unavailable metrics explicitly.

   **Checks:** Use a controlled allocation and child process to check coverage, and known-size files to check storage counting. Distinguish disk-backed preparation from memory reuse and never report unavailable data as zero.

   **Done when:** Resource measurements with limitations visible in the report.

<a id="t53"></a>

53. [ ] **T53 — Benchmark cold, warm, and amortized workflows**

   **Type:** AFK. **Blocked by:** T39, T50, T52. **Human review:** 0.5–2 hours.

   **Build:** Define fixed workloads for fresh setup, new credentials, repeated requests, and prepared-state reuse. Include artifact-loading costs and report preparation amortization over stated presentation counts.

   **Checks:** Confirm every online run uses a fresh request and produces a verified result. Compare a no-preparation provider with a prepared provider using the same workload and show that restart/cache behavior changes the appropriate measurements.

   **Done when:** A lifecycle comparison with explicit workload assumptions rather than a single unexplained proving-time number.

<a id="t54"></a>

54. [ ] **T54 — Make benchmark campaigns reproducible and statistically readable**

   **Type:** AFK. **Blocked by:** T40, T49, T50, T51, T52, T53. **Human review:** 0.5–2 hours.

   **Build:** Record host/container/emulator configuration, toolchain and artifact pins, profile/corpus versions, order, repetitions, warmups, raw samples, and summary statistics. Run providers sequentially under the same resource policy. Keep native stage campaigns separate from full integration campaigns with the emulator/services running; retain loading and bridge overhead in the latter. Keep quick CI smoke results separate from controlled benchmark campaigns.

   **Checks:** Re-run a saved campaign configuration and regenerate summaries from its raw data. Detect environment/profile mismatch, preserve outliers and failures, and avoid strict speed-regression gates on noisy shared runners.

   **Done when:** Reproducible reports grouped by equal profile, input domain, workload, and execution target.

<a id="t55"></a>

55. [ ] **T55 — Combine correctness, leakage, and performance into a local report**

   **Type:** AFK. **Blocked by:** T19, T40, T49, T54. **Human review:** 0.5–2 hours.

   **Build:** Generate a human-readable report plus machine-readable results from the common result schema. Display declared capabilities, observed failures, coverage gaps, compute placement, and measured stages together.

   **Checks:** Render passing, failing, unsupported, timed-out, and inconclusive submissions. Failed functional cases must not appear as successful competitive benchmark rows; completed but failed submissions may still be shown with their findings.

   **Done when:** A local report that accurately separates empirical evidence from contributor claims.

<a id="t56"></a>

56. [ ] **T56 — Publish a minimal contributor template and local walkthrough**

   **Type:** AFK. **Blocked by:** T17, T20, T21, T55. **Human review:** 0.5–2 hours.

   **Build:** Provide a copyable implementation directory with manifest, adapter entrypoint, dependency/build lock, and a short README. Document how to wrap an existing external project and run private tests without copying its whole repository.

   **Checks:** On a clean clone, register the test provider and one real provider using only the dedicated directory/configuration path. Check that a missing operation produces an actionable error and that local results remain untracked/unpublished by default.

   **Done when:** A short newcomer workflow using exactly the same contract as the two reference providers.

<a id="t57"></a>

57. [ ] **T57 — Isolate public submission execution**

   **Type:** AFK. **Blocked by:** T21, T23. **Human review:** 0.5–2 hours.

   **Build:** Run submitted build/prover/verifier code in disposable, resource-limited workers without publication credentials or access to other submissions/private local fixtures. Keep the evaluation harness and benchmark definitions from a trusted platform revision.

   **Checks:** Use controlled submissions that try to alter the scorer, read another workspace, exceed time/memory/output budgets, or leave background processes. Confirm the run fails safely and publishes no credentials.

   **Done when:** A bounded execution policy appropriate for arbitrary contributor PRs, without adding a cryptographic review requirement.

<a id="t58"></a>

58. [ ] **T58 — Recognize implementation PRs and restrict evaluation changes**

   **Type:** AFK. **Blocked by:** T17, T56, T57. **Human review:** 0.5–2 hours.

   **Build:** Classify dedicated implementation-directory changes separately from platform/predicate/profile/test changes. Validate manifests and compute which submissions need re-evaluation.

   **Checks:** Exercise new implementation, version update, deletion, audit-only change, and a PR that attempts to edit test expectations. Changes to shared definitions go through normal maintainer review and cannot weaken the suite used to score that PR.

   **Done when:** Automatic PR classification and affected-submission selection with a cursory-review checklist.

<a id="t59"></a>

59. [ ] **T59 — Run PR checks and queue full integration campaigns**

   **Type:** AFK. **Blocked by:** T40, T49, T54, T55, T57, T58. **Human review:** 0.5–2 hours.

   **Build:** Add CI that uses the same local runner: inexpensive manifest/build/contract checks first, then bounded real integration, correctness, leakage, and benchmark smoke runs. Produce downloadable reports without executing untrusted code in a privileged publishing job.

   **Checks:** Test a passing sample PR, malformed manifest, timeout, observed leak, and provider failure. Re-run only affected submissions; cancellation and duplicate updates clean up workers. Expose not-run cases instead of a misleading green summary.

   **Done when:** An automatic PR evaluation path; controlled full benchmarks may use a separate queued worker.

<a id="t60"></a>

60. [ ] **T60 — Display optional audit evidence with manual provenance notes**

   **Type:** AFK. **Blocked by:** T17, T55. **Human review:** 0.5–2 hours.

   **Build:** Accept audit links/metadata covering reviewer, date, reviewed revision, components, and scope. Let maintainers mark that the report/reference was manually checked; absence of an audit does not block submission.

   **Checks:** Render unaudited, report-attached, manually-checked, and newer-than-audited-revision examples. A library audit must not automatically label the circuit or integration audited, and the platform must not imply endorsement of security.

   **Done when:** Optional audit information ready for the catalog, with a small manual check and no certification program.

<a id="t61"></a>

61. [ ] **T61 — Create an explicit public result bundle and publishing path**

   **Type:** AFK. **Blocked by:** T55, T57, T59, T60. **Human review:** 0.5–2 hours.

   **Build:** Export public metadata, synthetic test evidence, benchmark samples, and summaries as an explicit operation. Publish only platform-generated results for the accepted submission revision after cursory review/merge; retain local-only runs independently.

   **Checks:** Use private-path, credential, witness, log, and prepared-state canaries to check the exported bundle. Test that source changes invalidate result attribution and that publication never needs to execute submitted code with publishing credentials.

   **Done when:** An opt-in publication bundle and a trusted publishing workflow; no private-result hosting service.

<a id="t62"></a>

62. [ ] **T62 — Generate the public implementation catalog**

   **Type:** AFK. **Blocked by:** T61. **Human review:** 0.5–2 hours.

   **Build:** Extend the existing static project overview with generated implementation pages and comparable result tables. Show supported profiles, source/artifact pins, stage metrics, findings, coverage, audit evidence, and execution target.

   **Checks:** Inspect sample pages for a fast-but-failing provider, two incomparable profiles, an unaudited entry, and an old audit. Ensure sorting/filtering respects comparison groups and clearly labels experimental evidence.

   **Done when:** A static showcase generated from results, without accounts, a custom backend, or a global security score.

<a id="t63"></a>

63. [ ] **T63 — Rehearse a new contributor's submission without shared-code edits**

   **Type:** HITL. **Blocked by:** T32, T56, T59, T62. **Human review:** up to 3 hours.

   **Build:** Have a reviewer unfamiliar with the integration follow the template, wrap a small existing provider or repackage a reference provider independently, run it locally, and prepare a representative implementation-only PR. Log every undocumented platform dependency.

   **Checks:** Complete the walkthrough using only contributor-owned files, within a few hours of hands-on review once the upstream implementation already works. Verify the local and CI runners select the same tests and produce the same result categories.

   **Done when:** A newcomer usability report and small fixes to the contract/docs; no requirement for the reviewer to invent a new ZK system.

<a id="t64"></a>

64. [ ] **T64 — Assemble the release evidence and close the scope**

   **Type:** HITL. **Blocked by:** T31, T32, T40, T49, T54, T60, T62, T63. **Human review:** up to 3 hours.

   **Build:** Collect the two real provider integrations, compatibility matrix, versioned semantics, adversarial/differential test reports, reproducible stage benchmarks, and optional-public-submission demo. Add a concise comparison with prior art that identifies the tested integration contribution and its limits.

   **Checks:** From the documented revision, a reviewer can reproduce a successful integration, an observed broken integration, a seeded leakage finding, and a public result page. List untested channels and contributor gaps; unresolved shared-profile support cannot be marked complete.

   **Done when:** A release checklist and evidence bundle for the agreed scope, with no assertion that passing proves cryptographic security or semantic equivalence.

**Useful completion points**

- **T13:** the common integration can be exercised without importing OpenAC.
- **T27:** one real provider works from the actual Android test wallet through the actual verifier endpoint.
- **T32:** the second provider follows that same path; contributor work is isolated from shared wallet/verifier code.
- **T49:** the framework demonstrably detects its documented seeded integration leaks and reports its detection limits.
- **T55:** the local evaluation product is usable independently of any public platform.
- **T64:** the optional public submission/catalog workflow and the evidence for the scoped contribution are complete.

**Existing code to start from**

These are navigation aids for the initial extraction, not a requirement to preserve the current layout.

| Area | Existing source |
| --- | --- |
| Imported revisions and existing ports | [UPSTREAM.lock.yaml](../../UPSTREAM.lock.yaml), [LOCAL_CHANGES.lock.yaml](../../LOCAL_CHANGES.lock.yaml) |
| Current integration contract | [Contract notes](../../integration/contracts/README.md), [shared runtime fixture](../../integration/contracts/fixtures/mobile-runtime-v1.json) |
| Existing coverage and environment gaps | [Test notes](../../integration/tests/README.md), [environment notes](../../integration/runtime/docker/README.md), [launcher notes](../../integration/tools/README.md) |
| Existing CI | [Mobile ZK hardening workflow](../../.github/workflows/mobile-zk-hardening.yml) |
| Android handoff | [Runtime request and policy models](../../components/eidch-android-wallet/app/src/main/java/ch/admin/foitt/wallet/platform/credentialPresentation/domain/model/ZkPresentation.kt) |
| Android runtime gap | [Unpackaged runtime](../../components/eidch-android-wallet/app/src/main/java/ch/admin/foitt/wallet/platform/credentialPresentation/domain/usecase/implementation/UnpackagedZkPresentationRuntime.kt) |
| Java request policy coupling | [Request validator](../../components/swiyu-verifier/verifier-service/src/main/java/ch/admin/bj/swiyu/verifier/service/management/CreateVerificationManagementValidator.java) |
| Java verifier boundary | [ZK verification port](../../components/swiyu-verifier/verifier-service/src/main/java/ch/admin/bj/swiyu/verifier/service/oid4vp/ports/ZkPresentationVerifier.java), [HTTP adapter](../../components/swiyu-verifier/verifier-service/src/main/java/ch/admin/bj/swiyu/verifier/service/oid4vp/adapters/HttpZkPresentationVerifier.java) |
| OpenAC proof/backend coupling | [Backend bindings](../../components/zkid/wallet-unit-poc/openac-sdk/src/swiyu-zkp/backend.ts), [wallet/verifier SDK](../../components/zkid/wallet-unit-poc/openac-sdk/src/swiyu-zkp/wallet.ts) |
| OpenAC expected context and verification policy | [Sidecar](../../components/zkid/wallet-unit-poc/openac-sdk/src/swiyu-zkp/sidecar.ts) |
| Callback contract to preserve | [Runtime contract](../../components/zkid/wallet-unit-poc/openac-sdk/src/swiyu-zkp/mobile-runtime-contract.ts) |
| Existing real-proof baseline | [Real proof integration test](../../components/zkid/wallet-unit-poc/openac-sdk/tests/swiyu-zkp/real-e2e.test.ts) |
| Existing benchmark campaign | [Campaign script](../../components/zkid/wallet-unit-poc/benchmark/docker/run-final-benchmarks.sh), [benchmark overview](../../benchmark/README.md) |
| Existing public overview | [Static overview](../../website/index.html) |

**External reference starting points**

- [EPFL full credential examples](https://github.com/eid-privacy/zkp-pocs): candidate circuits and example reproduction.
- [EPFL Spartan/Noir backend](https://github.com/eid-privacy/spartan-backend): alternative backend, preparation lifecycle, and verification helpers.
- [EPFL Android example](https://github.com/eid-privacy/zkp-android): reference for later native packaging; it is not assumed to already be a Swiyu wallet integration.
- [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html): protocol vocabulary and standard behavior. The project extension must remain clearly identified as experimental.

**Release claim**

The demonstrated contribution is a locally usable, contribution-driven framework that exercises different implementations of declared Swiyu ZK presentation profiles through a shared OID4VP integration, compares their measured lifecycle costs, and automatically detects a documented set of unintended disclosures and linkability signals. The evidence consists of reproducible integrations and observed test behavior; security audits and proofs of complete semantic correctness remain outside the platform's responsibility.

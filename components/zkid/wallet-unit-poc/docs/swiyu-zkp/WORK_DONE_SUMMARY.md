# Swiyu ZK prototype work summary

Date: 2026-07-23

This file explains, in plain language, what was built and audited in this
prototype branch. The short version is:

> We did not rewrite swiyu or OpenAC. We built a small opt-in ZK presentation
> path on top of the existing swiyu flow.

The prototype lets a wallet prove a fixed statement:

- the holder has a swiyu-shaped SD-JWT VC signed by an accepted issuer;
- the credential is still within its validity window;
- the wallet controls the holder key in the credential;
- the hidden `birthdate` satisfies an age cutoff;
- the hidden credential status entry is valid in a locally provisioned signed
  status-list snapshot.

The verifier learns the predicate result and policy metadata, not the raw
birthdate, holder key, disclosures, credential status URI, status index, or
Merkle path.

## Starting point and intent

The project started from the existing swiyu verifier/wallet shape and the
OpenAC/zkID codebase. OpenAC gave us useful SD-JWT/P-256/ZK building blocks,
but the goal here was not to replace swiyu's verifier or turn OpenAC into a new
swiyu stack.

The intended shape stayed deliberately small:

1. Keep ordinary swiyu issuance and ordinary DCQL presentation working.
2. Add one fixed ZK profile for an age-over-cutoff proof with status validity.
3. Let the verifier opt in with `x_swiyu_zkp`.
4. Verify the proof through a local loopback sidecar.
5. Keep registry/status reads out of the presentation-time proof path.

## Prototype A: SD-JWT-to-ZK overlay

Prototype A is the main age proof. It connects these layers:

### Circom proof relation

The Circom work added a fixed swiyu profile circuit:

- [main/swiyu_age18_statuzs_2k.circom](../../circom/circuits/main/swiyu_age18_status_2k.circom)
- [swiyu-age18-status.circom](../../circom/circuits/swiyu-age18-status.circom)

The circuit proves issuer signature validity, disclosure binding, holder-key
possession, date validity, age comparison, and status-list membership. Helper
circuits live here:

- [swiyu/json.circom](../../circom/circuits/swiyu/json.circom)
- [swiyu/date.circom](../../circom/circuits/swiyu/date.circom)
- [swiyu/disclosure.circom](../../circom/circuits/swiyu/disclosure.circom)
- [swiyu/metadata.circom](../../circom/circuits/swiyu/metadata.circom)
- [swiyu/status-merkle.circom](../../circom/circuits/swiyu/status-merkle.circom)
- [swiyu/p256.circom](../../circom/circuits/swiyu/p256.circom)

We also tightened inherited P-256 helper behavior and added focused tests:

- [ecdsa/p256/add.circom](../../circom/circuits/ecdsa/p256/add.circom)
- [p256-add-complete.test.ts](../../circom/tests/circuits/p256-add-complete.test.ts)
- [k_add.test.ts](../../circom/tests/circuits/k_add.test.ts)
- [swiyu-profile-components.test.ts](../../circom/tests/circuits/swiyu-profile-components.test.ts)

The public proof statement is intentionally small: predicate result, issuer
public key, session challenge, cutoff date, frozen verifier time, metadata
commitment, and status-snapshot commitment. The full signal list and public
context are documented in [PROFILE.md](PROFILE.md).

### TypeScript wallet and verifier SDK

The SDK work added a swiyu-specific ZK module:

- [openac-sdk/src/swiyu-zkp](../../openac-sdk/src/swiyu-zkp)

The most important files are:

- [wallet.ts](../../openac-sdk/src/swiyu-zkp/wallet.ts): wallet `prepare`,
  status provisioning, `show`, and verifier `verify`.
- [parser.ts](../../openac-sdk/src/swiyu-zkp/parser.ts): strict SD-JWT VC
  parsing for the fixed profile.
- [challenge.ts](../../openac-sdk/src/swiyu-zkp/challenge.ts): canonical
  session challenge hashing.
- [public-context.ts](../../openac-sdk/src/swiyu-zkp/public-context.ts): public
  proof input encoding.
- [status-list-resolver.ts](../../openac-sdk/src/swiyu-zkp/status-list-resolver.ts):
  signed status-list JWT resolution.
- [sidecar.ts](../../openac-sdk/src/swiyu-zkp/sidecar.ts): pure sidecar
  verification contract.
- [sidecar-node.ts](../../openac-sdk/src/swiyu-zkp/sidecar-node.ts): local
  HTTP sidecar server/config loader.
- [native-backend-node.ts](../../openac-sdk/src/swiyu-zkp/native-backend-node.ts):
  Node adapter around the native Spartan prover/verifier.

The SDK exports the ZK module through the existing package entry points:

- [openac-sdk/src/index.ts](../../openac-sdk/src/index.ts)

### Native Spartan proof path

The Rust work added a native fixed-profile command path so the large proving
and verifying keys do not need to move through browser/WASM memory:

- [ecdsa-spartan2/src/swiyu.rs](../../ecdsa-spartan2/src/swiyu.rs)
- [ecdsa-spartan2/src/circuits/swiyu_circuit.rs](../../ecdsa-spartan2/src/circuits/swiyu_circuit.rs)
- [ecdsa-spartan2/src/bin/swiyu-profile.rs](../../ecdsa-spartan2/src/bin/swiyu-profile.rs)

This is what the Node SDK sidecar calls for real proof verification. It is a
desktop/native prototype path, not a browser deployment path.

## Prototype B: status privacy experiments

Prototype B explored the status-list privacy problem: ordinary swiyu status
checks expose a stable status URI and index to the verifier.

The work added fixed-index and sparse status proof harnesses:

- [status-designs](../../openac-sdk/src/status-designs)
- [status-designs.fixed-index.test.ts](../../openac-sdk/tests/status-designs.fixed-index.test.ts)
- [status-designs.comparison.test.ts](../../openac-sdk/tests/status-designs.comparison.test.ts)
- [status-designs.benchmark.test.ts](../../openac-sdk/tests/status-designs.benchmark.test.ts)
- [swiyu/status-proof-benchmark.circom](../../circom/circuits/swiyu/status-proof-benchmark.circom)
- [status-proof-benchmark.test.ts](../../circom/tests/circuits/status-proof-benchmark.test.ts)
- [status-proof-benchmark-results.json](status-proof-benchmark-results.json)
- [STATUS-DESIGNS.md](STATUS-DESIGNS.md)

The important result is mixed:

- The prototype can hide the credential-specific status URI/index/path from the
  verifier presentation.
- The verifier operator still knows the configured signed-list cohort.
- The measured desktop path works.
- The measured browser/mobile direction is not practical as-is.

This is why the requirements matrix calls the mobile result a measured no-go,
not a deployment success.

## Java swiyu-verifier integration

The Java verifier work added an opt-in path inside existing DCQL handling. It
does not replace the ordinary SD-JWT verifier.

Main Java files:

- [DcqlCredential.java](../../../../swiyu-verifier/verifier-service/src/main/java/ch/admin/bj/swiyu/verifier/domain/management/dcql/DcqlCredential.java)
- [ZkPresentationPolicy.java](../../../../swiyu-verifier/verifier-service/src/main/java/ch/admin/bj/swiyu/verifier/domain/management/dcql/ZkPresentationPolicy.java)
- [DcqlCredentialDto.java](../../../../swiyu-verifier/verifier-service/src/main/java/ch/admin/bj/swiyu/verifier/dto/management/dcql/DcqlCredentialDto.java)
- [ZkPresentationPolicyDto.java](../../../../swiyu-verifier/verifier-service/src/main/java/ch/admin/bj/swiyu/verifier/dto/management/dcql/ZkPresentationPolicyDto.java)
- [DcqlMapper.java](../../../../swiyu-verifier/verifier-service/src/main/java/ch/admin/bj/swiyu/verifier/service/management/DcqlMapper.java)
- [CreateVerificationManagementValidator.java](../../../../swiyu-verifier/verifier-service/src/main/java/ch/admin/bj/swiyu/verifier/service/management/CreateVerificationManagementValidator.java)
- [DcqlPresentationVerificationService.java](../../../../swiyu-verifier/verifier-service/src/main/java/ch/admin/bj/swiyu/verifier/service/oid4vp/DcqlPresentationVerificationService.java)
- [HttpZkPresentationVerifier.java](../../../../swiyu-verifier/verifier-service/src/main/java/ch/admin/bj/swiyu/verifier/service/oid4vp/adapters/HttpZkPresentationVerifier.java)
- [ZkPresentationVerifier.java](../../../../swiyu-verifier/verifier-service/src/main/java/ch/admin/bj/swiyu/verifier/service/oid4vp/ports/ZkPresentationVerifier.java)
- [ZkPresentationVerificationResult.java](../../../../swiyu-verifier/verifier-service/src/main/java/ch/admin/bj/swiyu/verifier/service/oid4vp/ports/ZkPresentationVerificationResult.java)
- [openapi.yaml](../../../../swiyu-verifier/openapi.yaml)

The Java side does these things:

- accepts `x_swiyu_zkp` only on the fixed `dc+sd-jwt` profile;
- validates one birthdate claim, one presentation, explicit holder binding,
  fixed profile ID, fixed circuit ID, cutoff date, snapshot ID, and fresh
  `current_time`;
- persists the policy inside the existing `dcql_query`;
- includes the policy in the signed request object through normal DCQL mapping;
- routes only opt-in ZK credentials to the sidecar;
- fails closed if sidecar verification is unavailable or returns a mismatch;
- keeps ordinary DCQL credentials on the existing SD-JWT verifier path.

The sidecar contract is documented here:

- [swiyu-verifier/documentation/zk_presentation_sidecar.md](../../../../swiyu-verifier/documentation/zk_presentation_sidecar.md)
- [SIDECAR.md](SIDECAR.md)

## Documents and audit evidence

The main local docs are:

- [README.md](README.md)
- [PROFILE.md](PROFILE.md)
- [SIDECAR.md](SIDECAR.md)
- [STATUS-DESIGNS.md](STATUS-DESIGNS.md)
- [REQUIREMENTS-MATRIX.md](REQUIREMENTS-MATRIX.md)
- [ACCEPTANCE.md](ACCEPTANCE.md)

Audit notes are in:

- [audits/spec-round-1.md](audits/spec-round-1.md)
- [audits/spec-round-2.md](audits/spec-round-2.md)
- [audits/circuit-soundness-initial.md](audits/circuit-soundness-initial.md)
- [audits/deep-implementation-audit-2026-07-15.md](audits/deep-implementation-audit-2026-07-15.md)

Important caveat: the deep implementation audit file is now stale. It still
describes some P1 issues that later auditors confirmed were fixed in the
current code. It should be marked superseded or amended before this branch is
presented as cleanly audited.

## Deviations from the original plan

The original plan was aspirational: build Prototype A and Prototype B and make
them work. The implementation stayed smaller and more honest in a few places:

1. We built one fixed profile, not a generic predicate framework.
2. We added a local sidecar instead of embedding proof verification directly
   into the Java verifier.
3. We did not rewrite issuer behavior.
4. We did not rewrite ordinary swiyu presentation behavior.
5. We did not solve one-credential/one-signup nullifiers.
6. Prototype B did not become a mobile-ready status privacy system; it became
   a measured experiment with a desktop path and a browser/mobile no-go.
7. Real E2E proof coverage exists, but the joined signed-status E2E path still
   needs to be added.

These deviations are consistent with the smallest-build goal: build on top of
swiyu, prove the narrow profile, and avoid pretending we finished a full
anonymous-credential system.

## Results we have

### Passing results

- Circom focused tests for swiyu components/P-256/K-add passed:
  `51 passing`.
- P-256 add regression passed:
  `3 passing`.
- Native Rust swiyu tests passed from a no-space temp path:
  `9 passed`.
- Real proof E2E passed when explicitly enabled with
  `SWIYU_REAL_E2E_MODE=proof`:
  `2 passed`.
- The real proof E2E produced a witness of `199,663,884` bytes.
- The real proof E2E verified successfully, rejected a tampered challenge, and
  verified the sidecar contract.
- SDK lint and build passed.
- Java focused verifier tests passed from a no-space temp path:
  `40 tests passed`.

### Failing or incomplete results

- The focused SDK/sidecar test slice is not green under the normal runner:
  `70 passing, 3 failing` in one audit run.
- The sidecar timeout regression test uses `verificationTimeoutMs: 50`, but
  production validation requires at least `100`.
- Some sidecar config tests need an explicit longer Vitest timeout.
- Real proof E2E still uses `makeStatus()` fixture status instead of the full
  signed status-list provisioning path.
- Rust native build/tests fail from the current workspace path because the path
  contains a space; the same tests pass from `/tmp`.

## Current audit conclusion

The latest subagent audits found no current P0/P1 proof-soundness blocker and
no current P0/P1 Java verifier-adapter bypass.

The real blockers are acceptance and evidence blockers:

1. Make the SDK/sidecar focused tests green under normal commands.
2. Add a real joined E2E test for signed status-list provisioning.
3. Update or supersede stale audit docs.
4. Decide whether `show()` should accept only opaque provisioned status
   material.
5. Split credential issuer keys from status-list signing keys, or explicitly
   mark key purposes.
6. Preflight the sidecar native binary, working directory, and temp directory.
7. Add a Java request-object regression test proving the signed request object
   contains `x_swiyu_zkp`.

## Recommended next steps

The smallest clean path from here is:

1. Fix the red SDK tests without changing the architecture.
2. Add the signed-status real E2E test.
3. Add the Java request-object test.
4. Update the stale audit report and requirements matrix to reflect current
   evidence.
5. Then run the same audit rounds again.

Do not start by redesigning swiyu or OpenAC. The remaining work is mostly about
making the current thin overlay internally consistent and auditable.

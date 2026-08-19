# Deep implementation audit: thin swiyu ZKP overlay

Date: 2026-07-15

Scope: only the Prototype A/B overlay on top of swiyu. This is not a broad
OpenAC implementation review. Findings are in scope only when they affect the
fixed swiyu age/status proof relation, wallet provisioning/show flow, local
proof sidecar, or the opt-in Java `x_swiyu_zkp` route.

## Summary

Status: FAIL for completion.

The implementation is correctly shaped as a small opt-in profile rather than a
rewrite: one fixed relation, one local sidecar call, signed status-list startup
provisioning, and an opt-in Java DCQL extension. The Java adapter slice is
currently the strongest part of the implementation. The current blocker is the
proof boundary: the P-256 complete-addition gadget has an unconstrained inactive
slope that can alter the doubling branch while satisfying constraints.

There are also two verifier-side sidecar boundary issues that should be fixed
before calling the prototype complete: status snapshot authority drops signer
identity after startup provisioning, and HTTP verification timeout releases the
concurrency slot before the underlying verification finishes.

## P0/P1 findings

### P1: P-256 complete addition leaves the inactive slope unconstrained

In scope: yes, this is inside the issuer and holder ECDSA proof relation.

Evidence:

- `wallet-unit-poc/circom/circuits/ecdsa/p256/add.circom:74-87`
- Focused regression:
  `npm test -- --grep Secp256r1AddComplete`
  returned 2 passing, 1 failing. The failing test is
  `binds the inactive addition slope to zero in the doubling branch` and reports
  `Expected constraints to not match.`

When `xP == xQ`, `dy` is forced to zero, so `dx * lambdaA === dy` does not bind
`lambdaA`. The branch then computes:

```circom
lambda <== (lambdaB * isXEqual.out) + lambdaA;
```

That lets a forged witness add an arbitrary inactive-slope value into the
doubling slope. Because `Secp256r1AddComplete` is used in scalar multiplication
and ECDSA verification, this is a real proof-soundness blocker, not an OpenAC
surface concern.

Smallest fix: constrain the inactive branch directly, for example
`isXEqual.out * lambdaA === 0`, and keep the focused adversarial regression.

### P1: authoritative status snapshots do not retain status-list signer identity

In scope: yes, this is the verifier-side authority boundary for Prototype B.

Evidence:

- `wallet-unit-poc/openac-sdk/src/swiyu-zkp/types.ts:29-40`
- `wallet-unit-poc/openac-sdk/src/swiyu-zkp/status-list-resolver.ts:244-252`
- `wallet-unit-poc/openac-sdk/src/swiyu-zkp/sidecar.ts:176-198`
- `wallet-unit-poc/openac-sdk/src/swiyu-zkp/sidecar-node.ts:398-420`

Startup provisioning verifies the signed `statuslist+jwt` against a configured
issuer/kid/subject, but the resulting `SwiyuAuthoritativeStatusSnapshot` keeps
only id, commitment, epoch/list length, freshness, and provenance. Presentation
verification later selects the credential issuer from the proof envelope and the
status snapshot from the signed Java policy, but it cannot compare the snapshot
signer/subject binding to the credential issuer because that signer identity has
been discarded.

This does not mean raw roots are accepted: the current config path does derive
snapshots from bounded signed local JWT files. The gap is narrower: after
derivation, the sidecar has no runtime invariant saying "this credential issuer
is allowed to use this status snapshot."

Smallest fix: include the status-list issuer, kid, and subject/audience binding
in the authoritative snapshot or a parallel immutable registry record, then
reject before backend verification when the credential issuer is not bound to the
selected snapshot. If same-entity status signing may use a separate key, model
that as an explicit allowed status-signing key for the credential issuer rather
than as a global snapshot pool.

### P1: sidecar timeout releases concurrency while verification can keep running

In scope: yes, this is the local verifier sidecar availability boundary.

Evidence:

- `wallet-unit-poc/openac-sdk/src/swiyu-zkp/sidecar-node.ts:155-175`
- `wallet-unit-poc/openac-sdk/src/swiyu-zkp/sidecar-node.ts:291-304`
- Existing test only covers the pre-timeout case:
  `wallet-unit-poc/openac-sdk/tests/swiyu-zkp/sidecar-node.test.ts:192-221`

`handleRequest` races `options.service.verifyJson(requestJson)` against
`withTimeout`. When the timeout branch wins, `finally` immediately calls
`concurrency.leave()`, but the original verification promise is not cancelled or
awaited. Repeated timeout-triggering requests can therefore exceed the intended
native verifier concurrency cap even with `maxConcurrentRequests: 1`.

Smallest fix: hold the concurrency slot until the underlying verification promise
settles, and reject configurations where the outer HTTP verification timeout is
shorter than the native verifier timeout. Abort propagation to the backend would
be better, but the minimal sound cap is "do not release the slot while the work
still runs."

## P2 findings

### P2: wallet `show` still accepts structural raw status evidence

In scope: yes, but not a verifier-soundness blocker by itself.

Evidence:

- `wallet-unit-poc/openac-sdk/src/swiyu-zkp/types.ts:139-145`
- `wallet-unit-poc/openac-sdk/src/swiyu-zkp/wallet.ts:156-179`
- Tests commonly use raw fixture status material:
  `wallet-unit-poc/openac-sdk/tests/swiyu-zkp/fixture.ts:140-167`

`provisionSwiyuCredentialStatus()` verifies a signed status-list JWT and derives
the private witness, but `SwiyuShowRequest` still accepts `statusSnapshot` and
`statusWitness` as structural inputs. A malicious wallet cannot use this alone
to convince an honest verifier of a different root, because verifier-side proof
verification recomputes the expected public status commitment. Still, the public
wallet API makes the intended provisioning path optional, so integration code can
skip the signed-status step without noticing.

Smallest fix: make `show` consume an opaque provisioned status object minted by
`provisionSwiyuCredentialStatus()` for the exact prepared credential. Keep the
raw lower-level type only for tests/internal helpers if needed.

### P2: real E2E proof path still uses the synthetic raw status fixture

In scope: yes, because acceptance evidence should exercise the signed status-list
path.

Evidence:

- `wallet-unit-poc/openac-sdk/tests/swiyu-zkp/real-e2e.test.ts:80-97`
- `wallet-unit-poc/openac-sdk/tests/swiyu-zkp/real-e2e.test.ts:199-219`

The real proof test uses `makeStatus()` rather than a signed `statuslist+jwt`
resolver. Focused status-list tests cover the resolver separately, but final
acceptance should join them: signed status JWT -> provisioned wallet witness ->
real witness/proof -> sidecar verification.

## Non-blockers / passed checks

- Public input binding is correctly structured: the wallet and verifier both
  recompute the ten expected public values and reject backend outputs that do
  not match.
- Status membership is appropriately fixed and small: the relation binds
  signed private URI/index, VALID two-bit value, list length, epoch, Merkle root,
  and public status commitment.
- Credential JSON parsing is intentionally a compact subset. Host credential
  parsing rejects duplicate keys, escapes, non-canonical unsigned integers, and
  unsupported profile/header fields before generating witness inputs.
- ECDSA `r == R.x` is a known rare completeness limitation rather than a
  false-positive path: standard verification reduces `x` modulo the P-256 order,
  while this relation compares the affine x-coordinate directly.
- Java `x_swiyu_zkp` wiring is opt-in and narrow. Focused Java tests passed from
  a temporary path without spaces:
  `./mvnw -pl verifier-service -Dmaven.compiler.proc=full -Dtest=HttpZkPresentationVerifierTest,DcqlPresentationVerificationServiceTest,PresentationVerificationUsecaseTest test`
  produced 30 tests, 0 failures.
- Focused SDK tests passed:
  `sidecar.test.ts`, `sidecar-node.test.ts`, and `status-list-resolver.test.ts`
  produced 19 tests, 0 failures.
- Focused wallet/backend profile tests passed:
  `profile.test.ts` and `backend.test.ts` produced 37 tests, 0 failures.

## Verification notes

Direct Java Maven execution from the workspace path fails before tests because
the OpenAPI generator does not escape the space in
`/Users/coding/Downloads/zkSecurity Internship/...`. The same focused Java test
slice passes from `/tmp/swiyu-verifier-audit` with Lombok annotation processing
enabled via `-Dmaven.compiler.proc=full`.

## Completion gate

Do not mark the prototypes complete until:

1. the P-256 complete-addition regression fails before the fix and passes after
   constraining the inactive slope;
2. the sidecar rejects credential-issuer/status-snapshot authority mismatches
   before backend verification;
3. sidecar concurrency remains occupied until timed-out verification work
   actually settles;
4. real E2E proof evidence uses the signed status-list provisioning path; and
5. exact circuit/proof artifact counts are regenerated after the circuit change.

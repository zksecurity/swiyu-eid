# Initial baseline and reproduction gaps

Inspected on 2026-09-14 at repository revision
`73cd99e10284a4c8996150e2ab773fc6fee41f62`, branch
`agent/mobile-zk-integration`. This records the existing checkout. It is not
evidence of a clean installation with the CI toolchain.

## Fast existing SDK checks

From `components/zkid/wallet-unit-poc/openac-sdk`:

```sh
npm test -- tests/swiyu-zkp/mobile-runtime-contract.test.ts tests/swiyu-zkp/sidecar.test.ts
```

The initial discovery run passed 8 runtime-contract tests and 9 sidecar tests.
These checks exercise serialization, runtime contracts and verification-service
behavior using test doubles. They do not generate a real Swiyu proof or exercise
the Android wallet over OID4VP.

The relevant CI workflow is `.github/workflows/mobile-zk-hardening.yml`. Android
presentation tests and Java controller tests still need a baseline run. Local
Node is 25.6.1 and Java is 24.0.2; the inspected CI configuration uses Node 22 and
Java 21. T02 remains incomplete until its toolchain and negative-control checks
are reproduced.

## Real OpenAC proof prerequisites

The legacy profile is `swiyu-age18-status-2k-v0`, circuit
`swiyu_age18_status_2k`. Keep its status checks when wrapping it.

The SDK's existing `dist` and dependencies are present. Its generic JWT/show
WASM files are also present, but they do not substitute for the Swiyu circuit.
Initial inspection did not find the following required artifacts in the
provider's expected checkout locations:

- `openac-sdk/assets/swiyu_age18_status_2k.wasm`
- `ecdsa-spartan2/target/release/swiyu-profile`
- Spartan proving and verifying keys for the Swiyu profile

These paths are relative to
`components/zkid/wallet-unit-poc`. The existing gated test is
`openac-sdk/tests/swiyu-zkp/real-e2e.test.ts`; its witness/proof modes can require
long builds and proof generation. A working preparation call is not evidence
that these prerequisites exist, that a signature was authenticated, or that a
proof was verified. T03 remains incomplete.

## Android and comparison baseline

Android SDK tools are not configured in this environment. The wallet's
`UnpackagedZkPresentationRuntime` currently returns `RuntimeNotPackaged`.
No emulator or physical-device measurements have been produced by this work.
The intended acceptance target remains the real Android test wallet in an
emulator with a local host-prover bridge; a physical phone is never required.

EPFL has not yet been pinned or reproduced. Its documented example without
revocation cannot be ranked against the legacy OpenAC age-plus-status profile
as though both perform the same work. T04 and T05 remain open.

## Reproduction evidence

The implementation milestone records new test runs separately in
`milestone-01.md`. Discovery logs and the full inventory are retained in this
run's temporary evidence directory:
`/private/tmp/swiyu-platform-20260914/reports/`.

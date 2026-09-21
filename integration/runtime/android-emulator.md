# Android emulator plan

## Prerequisites

- The wallet's supported JDK and Gradle wrapper.
- Android command-line tools, platform tools, emulator, and one pinned system image/API level compatible with the wallet.
- Hardware virtualization on developer machines or a KVM-capable CI runner.
- An AVD created from the pinned image, plus enough disk for its SDK and data image.
- A small Android adapter that serializes `swiyu.mobile-runtime-facade.v1` and returns `swiyu.mobile-runtime-result.v1` without inspecting the opaque presentation.

No SDK, image, or emulator is installed or launched by this integration step.

## Stages

1. **Laptop contract:** keep request validation, provider lifecycle, challenge binding, error mapping, and the golden test-stub vector green through `mobile_runtime.py`.
2. **Android contract adapter:** add the facade request/result models to the wallet, load the same golden vector as an instrumentation-test asset, and connect the result's presentation to the normal OID4VP `vp_token` path.
3. **Provider bridge:** choose either a provider compiled into Android or a narrow test transport to a host provider. For an initial emulator test, expose only the facade over a loopback endpoint and use `adb reverse`; do not expose provider internals to wallet code.
4. **Emulator verification:** boot the pinned AVD, install the test APK, run the golden success and challenge-mismatch instrumentation tests, and confirm provider-unavailable errors remain stable.
5. **CI hardening:** cache the pinned SDK image, add boot-health checks and artifact capture, then gate emulator runs separately from fast laptop tests.

## What runs now without Android

The laptop runner validates the JSON boundary, starts a manifest-selected provider, prepares and presents a credential, treats the presentation as opaque, asks the provider to verify it, rejects a changed challenge, and maps an unavailable provider to a stable facade error. The test-stub output is pinned by `contracts/fixtures/local-mobile-runtime-v1.json`.

## Checks once an emulator is available

- Kotlin/Java request and result serialization matches the golden JSON byte-for-byte where canonical output is required.
- Wallet-selected profile, credential, nonce, audience, and policy inputs reach the provider unchanged.
- The returned presentation flows through the wallet's existing OID4VP response path as an opaque token.
- A verifier-side nonce or audience change produces `verified: false`.
- App lifecycle events, process death, cancellation, and provider unavailability surface bounded, actionable errors.
- The real target provider works on the emulator ABI and meets latency and memory budgets; the test stub remains clearly labeled as non-cryptographic.

## Resource controls

Pin one API level and ABI. Start with 2 virtual CPUs, 2 GB RAM, a 512 MB heap, no camera/audio, animations disabled, and a small writable data image. Use headless/no-window mode in CI, one emulator per runner, a 120-second boot deadline, a per-test timeout, and unconditional process cleanup. Reuse a clean snapshot only after measuring reliability; cap retained logs/screenshots and keep heavyweight emulator jobs out of the default laptop test command.

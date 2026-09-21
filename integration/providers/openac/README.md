# OpenAC provider adapter

Target profile: `swiyu-age18-status-2k-v0` using circuit `swiyu_age18_status_2k`.

A second profile, `openac-age25-jwt-v0` / `swiyu_age25_jwt`, implements the shared claim `swiyu.shared.age25-holder-challenge.v0` (same statement as EPFL d10: issuer + `birth_date` age ≥ 25 + holder/challenge, no status). See [age25-jwt.md](age25-jwt.md). Proving artifacts for that profile are not packaged; `provider.mjs` `prepare`/`present`/`verify` return `unsupported_profile`. The shared-claim OID4VP campaign drives the profile through the Java harness with a session-bound OpenAC-shaped envelope (`openac-age25-synthetic-envelope`), not a Spartan proof.

This provider now runs the fixed OpenAC Swiyu profile through the SDK wallet/verifier APIs and the native `swiyu-profile` backend. It keeps issuer trust, status snapshot selection and verifier policy outside the provider. The provider checks the manifest, prepares the credential, generates a challenge-bound proof envelope and verifies the envelope against verifier-supplied public inputs.

## Coverage

| Operation | Status |
|-----------|--------|
| `initialize` | Reports profile support and artifact readiness |
| `prepare` | Parses and precomputes the SD-JWT with the OpenAC SDK under the supplied issuer key |
| `present` | Generates a real `swiyu_age18_status_2k` proof with the SDK wallet and native backend when artifacts are configured |
| `verify` | Verifies the proof envelope with verifier-supplied challenge, issuer key, status snapshot and verifying key |
| `cleanup` | Clears prepared handles |

## Artifact contract

`present` and `verify` require explicit local artifact roots. Set these to absolute paths in normal use; the provider normalizes relative values before passing paths to the native backend.

```bash
export SWIYU_OPENAC_ARTIFACT_ROOT="$PWD/components/zkid/wallet-unit-poc/openac-sdk"
export SWIYU_OPENAC_KEYS_ROOT="$PWD/components/zkid/wallet-unit-poc/ecdsa-spartan2"
```

The provider resolves these files:

| Env root | Relative path | Purpose |
|----------|---------------|---------|
| `SWIYU_OPENAC_ARTIFACT_ROOT` | `assets/swiyu_age18_status_2k.wasm` | Circom witness calculator |
| `SWIYU_OPENAC_KEYS_ROOT` | `keys/swiyu_age18_status_2k_proving.key` | Spartan proving key |
| `SWIYU_OPENAC_KEYS_ROOT` | `keys/swiyu_age18_status_2k_verifying.key` | Spartan verifying key |
| `SWIYU_OPENAC_KEYS_ROOT` | `target/release/swiyu-profile` | Native prove/verify CLI |

`present` currently signs the challenge with `inputs.holderPrivateKeyHex`. This is a local host-prover milestone path. A wallet callback or key-handle signer belongs in a later wallet integration milestone.

## Build artifacts

From the repository root:

```bash
cd components/zkid/wallet-unit-poc/circom
yarn install
yarn compile:swiyu

cd ../openac-sdk
npm run build:wasm
npm run build

cd ../ecdsa-spartan2
cargo build --release --no-default-features --bin swiyu-profile
cargo run --release --no-default-features --bin swiyu-profile -- setup keys
```

Use `--no-default-features` for `swiyu-profile` in this path. The default `native-witness` feature expects a generated C++ witness directory; this provider generates `.wtns` through the SDK WASM witness calculator and gives that witness to the native prover.

## Test

Fast provider tests:

```bash
cd integration/providers/openac
node --test tests/provider.test.mjs
```

Heavy provider proof test, gated so normal CI stays fast:

```bash
cd integration/providers/openac
SWIYU_OPENAC_REAL_E2E=proof node --test --test-name-pattern 'presents and verifies through the real OpenAC circuit artifacts' tests/provider.test.mjs
```

SDK proof smoke:

```bash
cd components/zkid/wallet-unit-poc/openac-sdk
SWIYU_REAL_E2E_MODE=proof npm test -- tests/swiyu-zkp/real-e2e.test.ts --reporter=verbose
```

The heavy tests generate a real witness, prove, verify, and reject a tampered challenge nonce.

## Quickstart

```bash
cd integration/providers/openac
node quickstart.mjs
node quickstart.mjs --output /tmp/my-openac-out
```

Default output: `artifacts/platform-openac/` at repo root.

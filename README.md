# swiyu-eid

One repository for the swiyu issuer, Android wallet, verifier, and the zkID
work used to add optional zero-knowledge presentation profiles.

## Source map

| Area | Upstream basis | Added in this project |
|---|---|---|
| `components/swiyu-issuer` | Official swiyu issuer | No functional changes |
| `components/eidch-android-wallet` | Official swiyu Android wallet | No ZK integration yet |
| `components/swiyu-verifier` | Official swiyu verifier | Opt-in `x_swiyu_zkp` DCQL policy and loopback proof-verifier sidecar |
| `components/zkid` | zkID v5.0.0 | swiyu circuits, TypeScript wallet/verifier APIs, native Spartan path, tests, and benchmarks |
| `integration` | New | Short indexes for cross-component contracts, profiles, and integration status |
| `benchmark` | New | Entry point for matched SD-JWT versus ZK results and reproducibility data |

Exact upstream revisions are pinned in [`UPSTREAM.lock.yaml`](UPSTREAM.lock.yaml).
The imported project-specific commit lineage is recorded in
[`LOCAL_CHANGES.lock.yaml`](LOCAL_CHANGES.lock.yaml).

## Added ZK work

- Age and private-status proof, plus an optimized Prepare/Show variant.
- Private canton membership against a verifier-selected allow-list.
- Residence eligibility over a hidden municipality and residence-start date.
- Credential-scoped nullifier for one accepted claim per credential and scope.
- Matched no-ZK controls, pinned container runs, raw samples, artifact sizes,
  memory measurements, and per-stage timing.

The working proof code is under
[`components/zkid/wallet-unit-poc`](components/zkid/wallet-unit-poc). The concise
profile registry is in [`integration/profiles`](integration/profiles/README.md),
and benchmark headlines are in [`benchmark`](benchmark/README.md).

## Current integration boundary

The Java verifier can route the original monolithic age profile to a local ZK
sidecar while leaving ordinary SD-JWT verification unchanged. The optimized
Prepare/Show age, canton, residence, and nullifier profiles are implemented and
benchmarked in the zkID component, but are not yet wired into the Android
wallet or the Java verifier contract. The issuer remains unchanged and issues
ordinary ES256 SD-JWT credentials.

## Repository layout

```text
components/   Upstream projects plus component-local additions
integration/  Cross-component profile, contract, and test indexes
benchmark/    Reproducibility and result index
```

# swiyu e-ID ZK integration

This monorepo is an integration workspace for running the public swiyu issuer,
wallet, and verifier with opt-in zero-knowledge presentation profiles supplied
by zkID.

The initial import contains unmodified snapshots of the official upstream
repositories. Project-specific protocol contracts, profiles, orchestration,
cross-component tests, and benchmarks will be added separately so upstream
code remains easy to identify and synchronize.

## Structure

```text
components/
  swiyu-issuer/          Official generic issuer
  swiyu-verifier/        Official generic verifier
  eidch-android-wallet/  Official Android wallet
  zkid/                  zkID proof-system and circuit research
integration/
  contracts/             Cross-component wire contracts and fixtures
  profiles/              Versioned ZK profile manifests
  docker/                End-to-end development environment
  scripts/               Build and orchestration entry points
  tests/                 Cross-component and end-to-end tests
benchmark/               Reproducible baseline and ZK measurements
```

`UPSTREAM.lock.yaml` records the exact upstream revisions imported into this
repository. Each component retains its own upstream license and notices.

## Initial scope

No local ZK implementation has been ported in the initial scaffold. The first
milestone is an unchanged swiyu issuance and presentation flow. ZK support will
then be introduced as an opt-in branch without replacing ordinary SD-JWT
behavior.

# Benchmark

Medians from the pinned seven-run campaign. ZK lifecycle totals are sums of
separately timed components. Sizes are exact bytes converted to decimal MB.

| Profile | Constraints | R1CS | Proving keys | Verifying keys | Setup | Reusable per credential | Wallet per presentation | Verifier per presentation |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Age over 18 | 3,085,711 | 672.4 MB | 805.4 MB | 805.4 MB | 52.971 s | 16.424 s | 13.872 s | 1.730 s |
| Residence eligibility | 2,995,049 | 650.6 MB | 783.1 MB | 783.1 MB | 51.807 s | 15.488 s | 14.770 s | 1.698 s |
| One claim per credential scope | 3,316,270 | 729.0 MB | 863.2 MB | 863.2 MB | 61.039 s | 17.742 s | 15.729 s | 1.798 s |

Matched first-operation no-ZK controls:

| Profile | Trust setup | Reusable per credential | Wallet per presentation | Verifier per presentation |
|---|---:|---:|---:|---:|
| Age over 18 | 0.345 ms | 10.512 ms | 4.408 ms | 15.513 ms |
| Residence eligibility | 0.557 ms | 10.441 ms | 5.125 ms | 15.901 ms |
| One claim per credential scope | 0.325 ms | 9.501 ms | 5.282 ms | 13.133 ms |

## Reproduce and inspect

- Runner: [`run-final-benchmarks.sh`](../components/zkid/wallet-unit-poc/benchmark/docker/run-final-benchmarks.sh)
- Image definition: [`Dockerfile`](../components/zkid/wallet-unit-poc/benchmark/docker/Dockerfile)
- Final container aggregate: [`final-container.json`](../components/zkid/wallet-unit-poc/benchmark/results/final-container.json)
- Age optimization: [`age-optimization.json`](../components/zkid/wallet-unit-poc/benchmark/results/age-optimization.json)
- Canton profile: [`canton.json`](../components/zkid/wallet-unit-poc/benchmark/results/canton.json)
- Residence and nullifier profiles: [`residence-nullifier.json`](../components/zkid/wallet-unit-poc/benchmark/results/residence-nullifier.json)

The authoritative container used Linux/ARM64, CPU set `0-3`, a four-CPU quota,
12 GiB memory, no network, no swap expansion, and a 4,096-task limit. Stages
ran serially in fresh processes. The adaptive rule expanded every final
profile to seven retained samples; none were discarded.

# Pinned ARM64 benchmark environment

This environment produces final, isolated measurements. It is separate from
`zk-overhead-pilot-results.json`, whose shared-host numbers remain labelled
pilot-only.

## Pins and isolation

- platform: `linux/arm64`;
- Node: `22.14.0`, from a pinned multi-architecture image-index digest;
- Rust: `1.91.0`, from a pinned multi-architecture image-index digest;
- Maven `3.9.11` and Eclipse Temurin JDK 21, from a pinned
  multi-architecture image-index digest;
- Circom: `2.2.3`, installed from commit
  `ad44e915a12bb047b05745c2884aad9cc8326bc6`;
- default runtime allocation: CPUs `0-3`, four-CPU CFS limit, 12 GiB memory,
  12 GiB memory+swap ceiling, and 4,096 PID ceiling;
- all dependencies, circuits, and native binaries are built into one immutable
  image while networking is available;
- the timed container runs with `--network none` and no source-tree bind mount;
- every command is serialized by one entrypoint; no benchmark process overlaps
  another.

Before any timed command, the container verifies that cgroup v2 exposes the
requested CPU quota, exact CPU set, memory ceiling, and PID ceiling. It also
requires no active non-loopback interface, no IPv4 route, and no non-loopback
IPv6 address; dormant addressless tunnel devices exposed by the Linux kernel
are recorded but do not count as connectivity. A mismatch aborts the run
instead of silently recording measurements under a different resource
envelope.

The Docker build is intentionally expensive. Do not start it while another
compiler or benchmark is active.

## Review, then run

From `wallet-unit-poc`:

```sh
./benchmark/docker/run-pinned-benchmarks.sh
```

Optional fixed limits:

```sh
BENCH_CPUSET=0-3 BENCH_CPUS=4 BENCH_MEMORY=12g \
  ./benchmark/docker/run-pinned-benchmarks.sh
```

The wrapper refuses overlapping invocations through a run lock. It fingerprints
the complete `wallet-unit-poc` source set—including untracked files—before the
build. It also requires a clean sibling `swiyu-verifier` checkout and
fingerprints all of its tracked source. Both fingerprints are checked again
after the build, before the wrapper records the local image config digest and
starts the offline timed container.

## Run structure

Each standard-control worker records one first operation before warm-up, then
100 warm-ups and 1,000 steady-state operations. Headline overhead uses the
fresh-process first-operation medians; steady-state results remain a separate
sensitivity view. After two workers, any cold or steady-state principal-stage
delta over 15% relative to the pair's mean expands that profile to seven runs;
otherwise it runs three.

Age additionally has an actual production `swiyu-verifier` control. A fresh
JVM runs 100 warm-ups and 1,000 timed verifications through the production
SD-JWT and DCQL classes. The first two wall/CPU samples select three or seven
fresh JVMs using the same 15% rule. Preloaded issuer-key and VALID-status
adapters remove I/O while retaining presentation parsing, issuer and holder
signature verification, disclosure resolution, status-reference checking,
issuer/VCT policy, and the `age_over_18=true` DCQL evaluation. This remains a
separate production verifier-core baseline shown beside the matched modeled
wallet full-path baseline; the two are never pooled because their boundaries
differ.

ZK age baseline, authoritative-residence, and age-plus-scoped-nullifier
profiles each run witness generation and native
setup/serialize/prove/deserialize/verify in fresh processes. Every round first
runs the matched no-ZK workers, then witnesses, a recorded 30-second idle
interval, and native jobs in reverse order. A second recorded idle interval
separates the preceding heavy native work from the next control phase. Each profile independently
expands to three or seven runs based on its declared measured witness, handoff, setup,
key/state serialization, assignment, link-randomness, proof,
proof-serialization/deserialization, and verification components. Subsequent
rounds rotate positions to reduce fixed order and thermal bias.

Separate adaptive 3/7-worker SDK microbenchmarks measure work outside Circom and
Spartan. Age covers the current full wallet path around fake crypto boundaries.
Residence and scoped nullifier cover their exact profile-specific split
adapter policy/context/dispatch/framing paths; those adapter timings remain
partial because the low-level adapters do not own all private-input,
holder-signing, and status-witness orchestration. Each profile uses its exact native Prepare/Show
proof sizes. Aggregated SDK totals are therefore boundary-qualified component
estimates, never labelled end-to-end measurements.

The new residence controls are reported separately: the primary control
discloses BFS municipality and Gregorian residence-since claims so the verifier
evaluates the exact policy, while the secondary issuer-derived Boolean is a
privacy/trust sensitivity case. Scoped-nullifier state uses one common SQLite
WAL/`synchronous=FULL` harness for both no-ZK and ZK. It transactionally pairs
each spent key with an accepted-claim row, proves injected failures roll both
back, and records lookup, successful claim transaction, replay conflict,
physical growth, and synchronized same/distinct-key races at concurrency
2/4/8 with exact outcomes, final cardinalities, worker PRAGMAs, and overlap.

## Retained evidence

Each UTC-named result directory contains:

- `source-fingerprint.json`: commit, dirty flag, tracked diff hash, status hash,
  and full source-tree hash;
- `swiyu-verifier-source-fingerprint.json`: the production verifier commit,
  clean status, and complete tracked-source SHA-256;
- `image-iid.txt` and `image-inspect.json`;
- `metadata.json`: image/base digests, Docker/OS/CPU/memory/tool versions,
  effective cgroup limits, R1CS/WASM SHA-256s, UTC boundaries, and every exact
  benchmark argv/cwd/environment override;
- `command-log.jsonl`: raw start/end/status record for every command;
- `raw/controls`, `raw/production-control`, `raw/sdk-host`,
  `raw/nullifier-state`, and one raw
  directory per ZK profile;
- `zk-overhead-results.json`, the aggregate for the completed age baseline,
  residence, and scoped-nullifier ZK profiles plus their
  control/state studies, including semantic-parity assertions, adaptive-run evidence,
  standard-control, production-verifier baseline, SDK-host, Circom/Spartan
  lifecycle, exact artifact sizes, direct overhead ratios, and the separate
  age-verifier baseline-sensitivity ratios.

No proving or verifying key file is persisted merely for measurement. Their
exact in-memory serialized sizes remain in the native JSON reports.

## Interpretation boundary

Container output is a final-result candidate only if `metadata.json` reports
`completed: true`, all expected raw runs exist, hashes match the built
artifacts, and no external workload competed for the pinned Docker CPUs. Pilot
host data must never be pooled with container samples.

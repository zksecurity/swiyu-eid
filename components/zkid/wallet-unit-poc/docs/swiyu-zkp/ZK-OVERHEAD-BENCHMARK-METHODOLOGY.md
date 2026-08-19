# Measuring the cost of ZK over standard swiyu SD-JWT

This benchmark answers one narrow question: on the same isolated host, how much
compute, memory, storage, artifact size, and network payload does the ZK path
add over a conventional swiyu-style SD-JWT presentation with the same issuer,
holder binding, validity interval, and status decision?

The earlier host measurements are retained as **pilot data**, not performance
claims. The final result below comes from the pinned, offline container run and
keeps the pilot separate.

## Compared statements

| Profile | Standard SD-JWT control | ZK statement |
|---|---|---|
| age | selectively disclose `age_over_18=true` | prove an authenticated birthdate is on or before the verifier's cutoff |
| authoritative residence | primary control discloses the exact signed object `residence={municipality_bfs,since}`; secondary control discloses issuer-derived `residence_eligible=true` | authenticate that byte-identical object and prove its BFS municipality belongs to the verifier's at-most-16-code directory snapshot and its strict Gregorian date satisfies a minimum number of whole UTC days, hiding both fields |
| age plus scoped nullifier | disclose `age_over_18=true` and a random issuer-authenticated `credential_uid`, derive a scope-specific spent key | prove age eligibility plus an issuer-authenticated UID/wallet-secret commitment and reveal only the scope-specific nullifier |

The age statements are intentionally not cryptographically identical. In the
standard control, the issuer attests the already-derived Boolean. In the ZK
profile, the issuer attests a birthdate and the holder proves the verifier's
current cutoff predicate. This is the privacy and policy-flexibility benefit
for which the overhead is paid.

The two residence controls answer different questions and are never pooled.
The exact-policy control is the direct performance denominator because the
verifier evaluates the same municipality-list and duration policy, but it
reveals the raw signed claims. The derived Boolean is an age-style sensitivity
control with closer disclosure privacy, but delegates policy evaluation and
freshness to the issuer. Its credential VCT is
`urn:ch:swiyu-lab:residence-eligibility:v1`; the policy records the municipality
directory's `directoryAsOf`, a maximum of 16 BFS codes in the range 1..6999,
and an integer number of elapsed whole UTC days. Host-side date conversion
rejects anything other than a real Gregorian `YYYY-MM-DD` value.

The scoped-nullifier control is functionally, not cryptographically,
equivalent. Ordinary SD-JWT reveals its random credential UID so the verifier
can derive a spent key. The ZK profile binds the UID to a wallet-generated
secret commitment and derives a hidden credential seed. Both paths use the
same canonical verifier scope and the identical post-verification atomic state
transition. The final report must include both total ZK-versus-SD-JWT overhead
and the marginal difference between age ZK with and without the nullifier.

## Common and different work

Both paths use P-256 issuer signatures, P-256 holder possession, a validity
interval, a verifier nonce/context, and a status decision. DID documents,
issuer keys, and the status object/root are preloaded so neither path includes
network latency.

The standard control follows the swiyu verifier semantics:

1. parse the compact SD-JWT and protected header;
2. require the verifier's exact accepted issuer, protected `kid`, VCT, and
   signed status-list URI/index, then verify issuer ES256 and
   `nbf <= now < exp`;
3. authenticate and resolve selective disclosures;
4. verify an ES256 `kb+jwt` over nonce, audience, `iat`, and `sd_hash`;
5. read the credential's entry from a preloaded status list;
6. evaluate the requested disclosed claim or cleartext VCT/expiry policy.

For age verification, the final container also runs a supplementary control
against the actual `swiyu-verifier` Java implementation. Its timed loop invokes
the production `SdJwtVpTokenVerifier`, `DcqlVpTokenVerifier`, and `DcqlUtil`
classes over a real ES256 `dc+sd-jwt` presentation with disclosure, holder
binding, accepted issuer/VCT, signed status URI/index, and the
`age_over_18=true` DCQL claim. Issuer-key lookup and the VALID status decision
are preloaded adapters, matching the offline cryptographic boundary; network,
database, controller, and wallet-construction work remain outside the loop.
This production measurement is an independent verifier-core baseline shown
beside the modeled full-path baseline. It is never pooled with or substituted
for the modeled control because the lifecycle boundaries differ.

The ZK path instead proves issuer verification, parsing, disclosures, and
stable credential fields in Prepare. Show proves the holder signature,
challenge binding, freshness, status Merkle path, and predicate. The two
proofs are linked by their proof-embedded shared commitment. Holder binding is
semantically comparable but not byte-for-byte identical: the control signs a
standard key-binding JWT, while Show signs the canonical challenge digest.

Status is also intentionally asymmetric. The standard verifier performs an
O(1) byte lookup after loading the status list. Show verifies a Merkle path and
VALID value against a public fresh-root commitment. Fetching and authenticating
the upstream list/root is excluded from both paths.

## Lifecycle buckets

Measurements must not collapse unrelated deployment costs into one number.

| Bucket | Standard control | ZK |
|---|---|---|
| developer/build time | normal application build; not timed | Circom compilation; not timed, artifact bytes reported |
| one time per circuit version | load/validate cached trust keys | Spartan setup plus proving/verifying-key serialization-to-sink for Prepare and Show |
| per credential, reusable | wallet parses/authenticates credential and selects policy data | Prepare witness generation, WTNS read/parse, and committed assignment; optional prepared-state serialization-to-sink is separate |
| per presentation, wallet | construct and sign key-binding JWT | one shared link-randomness draw, fresh linked Prepare proof, Show witness generation/read/parse/assignment, Show proof, and both native proof serializations |
| per presentation, verifier | issuer/disclosure/status/key-binding/policy verification | deserialize and verify both proofs and compare proof-embedded shared commitments |
| first scoped claim, state | indexed lookup miss followed by an atomic unique insert | identical state operation, performed only after successful proof verification |
| replay/conflict | lookup hit or failed unique insert; reject | identical rejection; invalid proofs never consume a nullifier |
| transmitted | compact SD-JWT presentation | serialized linked Prepare and Show proof pair |

Every ZK lifecycle total is explicitly a sum of separately timed components,
not a true end-to-end latency sample. `first presentation wallet` is also
reported as per-credential reusable work plus per-presentation wallet work. It
is not added to the one-time circuit setup cost.

## Repetition and isolation protocol

Final results should be produced serially in a pinned container or VM:

- record image digest, OS, architecture, CPU model and allocated cores, memory,
  Node, Rust, Circom, optimization level, and curve;
- abort before timing unless cgroup v2 confirms the requested CPU quota, exact
  CPU set, memory ceiling, and PID ceiling, and the offline container exposes
  only the loopback interface;
- allow no concurrent circuit compiler, prover, test runner, or control worker;
- prebuild the native executable before timing cryptographic stages;
- run each standard control in a fresh process, recording one first operation
  before warm-up and 1,000 steady-state operations after 100 warm-ups;
- run the production Java verifier supplement in a fresh JVM for each raw run,
  with the same 1,000 operations and 100 warm-ups, recording both wall and
  current-thread CPU time;
- run each ZK repetition in a fresh native process and measure Circom witness
  generation separately from native setup/assignment/prove/verify;
- interleave fresh standard-control workers with matched ZK rounds; separate
  the control, witness, and native phases, insert recorded 30-second idle
  intervals before controls and after witnesses, and rotate/reverse profile
  order across rounds;
- start with two repetitions. Each profile declares its principal-stage
  manifest. If any declared cold/steady control, witness, handoff,
  setup, key/state serialization, assignment, randomness, proof,
  proof-serialization/deserialization, or verification wall-time components
  differs by more than 15% relative to the pair's mean, retain seven total raw
  runs; otherwise retain three;
- never discard an outlier after the run-count decision; retain every raw run;
- report samples, minimum, median, maximum, arithmetic mean, sample variance,
  standard deviation, and coefficient of variation;
- report witness-process RSS, production native-process RSS, their
  conservative per-run maximum (never their sum), exact serialized bytes, and
  exact artifact bytes.

The state supplement uses SQLite WAL mode, `synchronous=FULL`, and paired
`WITHOUT ROWID` spent-nullifier and accepted-claim tables keyed by
`(namespace, scope_hash, nullifier)`. Every acceptance runs `BEGIN IMMEDIATE`,
inserts the unique spent key, inserts its claim row, and commits both together.
Each timed success iteration uses a distinct pre-generated nullifier and every
raw run starts from the same state outside the timer. This avoids misreporting
one accepted insertion followed by 999 replay rejections. Lookup miss,
successful atomic claim transaction, lookup hit, conflict, and the complete
first-claim transition are separate wall/CPU stages. An injected failure after
the spent-key insert must roll back both tables with no orphan row. Sequential
replay and synchronized same-key races at concurrency 2, 4, and 8 must have one
winner, `workers - 1` clean conflicts, zero errors, and paired final
cardinality of one. Every race records monotonic worker operation intervals,
pairwise overlap, and maximum observed concurrency. A declared race-only
25 ms accepted-writer lock hold makes actual overlap observable and asserted;
serial latency excludes this correctness-test instrumentation. Distinct-key races must
have zero errors and one paired row per worker. Each worker sets and reports
effective WAL, `synchronous=FULL`, busy-timeout, and foreign-key settings.
Concurrency is a correctness and operational supplement and is not pooled with
serial presentation latency.

The standard controls record both wall and process CPU time. The current native
ZK harness records wall-clock time only; it must be labelled as wall-clock and
must not be presented as CPU time. Peak RSS is measured independently for each
fresh process.

The production verifier baseline applies the same first-two/15% rule to its
wall and CPU measurements: it retains three fresh-JVM samples when both are
stable and seven when either exceeds the threshold. The aggregate exposes a
separate age-verifier view against both the modeled control and production
verifier; the primary full-path denominator remains the lifecycle-matched
modeled control.

## Exact size inventory

For every ZK profile, record constraints, wires, R1CS, witness WASM, fixture
WTNS, proving key, verifying key, final proof, reusable instance, and reusable
assignment bytes. Keys are serialized in memory for sizing and are not copied
to the results directory. This avoids consuming disk merely to measure the
nearly-gigabyte key material.

For each standard control, record stored credential, prepared wallet state,
transmitted presentation, issuer public JWK, and holder public JWK bytes.
For scoped-nullifier state, additionally report scope/nullifier/key bytes,
logical rows, database/WAL files, initial/final cardinality, and per-worker RSS.
Do not compute a storage overhead ratio until both paths serialize the same
wallet-state boundary. The current aggregate publishes the two inventories but
marks them non-comparable because the ZK figure covers only Prepare
instance/assignment while the ordinary figure also includes credential and key
metadata.

## Final pinned-container result

The final run used image digest
`sha256:c201b0ab1a15ee35eb195d0959f6fbbada6d5f849da9f780cfd8cdca1673f488`
on Linux/ARM64 with an enforced four-CPU `0-3` cpuset, 12 GiB memory ceiling,
4,096-PID/task ceiling, and no effective non-loopback network path. The measured
tree was clean commit `6e2464dcee8ee3129737694ddda2681e8fef09e3`.

All three native ZK profiles and all four standard controls expanded to seven
runs under the predeclared 15% first-two rule. The residence and nullifier SDK
hosts also expanded to seven; the age SDK sensitivity and production Java
verifier retained three. Every sample is present in the result bundle.

| Median component sum | packed age reference | residence eligibility | one claim per credential |
|---|---:|---:|---:|
| one-time setup + key serialization | 52.971 s | 51.807 s | 61.039 s |
| reusable Prepare work per credential | 16.359 s | 15.432 s | 17.684 s |
| per-presentation wallet work | 13.872 s | 14.770 s | 15.729 s |
| per-presentation verifier work | 1.730 s | 1.698 s | 1.798 s |
| first-presentation wallet work | 30.914 s | 30.438 s | 32.526 s |

These rows are sums of individually timed boundaries, not end-to-end request
latencies. The matched no-ZK first-operation medians were:

| No-ZK lifecycle bucket | age | residence | credential nullifier |
|---|---:|---:|---:|
| one-time trust setup | 0.345 ms | 0.557 ms | 0.325 ms |
| reusable credential work | 10.512 ms | 10.441 ms | 9.501 ms |
| presentation wallet | 4.408 ms | 5.125 ms | 5.282 ms |
| presentation verifier | 15.513 ms | 15.901 ms | 13.133 ms |
| transmitted presentation | 1,271 B | 1,339 B | 1,818 B |

The first-operation control is the first measured operation in a fresh worker
with artifacts already materialized and potentially page-cached. The separate
100-warm-up/1,000-operation steady-state verifier medians were 9.618 ms,
9.193 ms, and 9.475 ms. The exact residence and nullifier SDK adapters add only
milliseconds around the native seconds-long path; their composed verifier
estimates are 1.718 s and 1.841 s. Against the matched first-operation controls,
those are 108.0× and 140.2× respectively. The actual `swiyu-verifier` Java age
core measured 2.469 ms per presentation across three fresh JVMs, making the
1.730-second native age verifier component about 700.6× that narrower
production boundary. It remains a sensitivity result, not the primary matched
lifecycle denominator.

| Exact combined artifact | packed age | residence | credential nullifier |
|---|---:|---:|---:|
| constraints | 3,085,711 | 2,995,049 | 3,316,270 |
| R1CS | 672,361,820 B | 650,552,532 B | 728,951,156 B |
| witness WASM | 13,029,931 B | 12,725,727 B | 13,984,238 B |
| proving keys | 805,380,052 B | 783,118,532 B | 863,161,292 B |
| verifying keys | 805,379,988 B | 783,118,468 B | 863,161,228 B |
| raw linked proof pair | 257,902 B | 258,446 B | 258,030 B |
| reusable Prepare state | 134,484,288 B | 134,484,288 B | 134,484,288 B |
| median native peak RSS | 4,197,986,304 B | 4,103,446,528 B | 4,382,019,584 B |

Packed status cuts the already-optimized age pair from 3,726,935 to 3,085,711
constraints (17.21%) and from 830,800,624 to 672,361,820 R1CS bytes (19.07%).
The combined-disclosure plus packed-status residence pair cuts its controlled
3,597,121-constraint predecessor to 2,995,049 (16.74%) and its R1CS by 17.41%.
The nullifier pair cuts its optimized legacy-status form from 3,957,494 to
3,316,270 constraints (16.20%) and its R1CS by 17.85%. Relative to packed age,
the integrated one-claim property costs 230,559 constraints (7.47%),
56,589,336 R1CS bytes (8.42%), and only 128 additional raw proof bytes.

All three profiles start from the same preauthenticated packed status boundary.
The additional packed-chunk tree cost is about 20 ms once per snapshot and the
credential path is about 0.2–0.3 ms. The complete raw bundle is
`docs/swiyu-zkp/container-results/20260818T090021Z/`; its aggregate is
`zk-overhead-results.json`.

## Reproduction

The pinned offline ARM64 harness for all three profiles and controls is run
with:

```sh
cd wallet-unit-poc
./benchmark/docker/run-pinned-benchmarks.sh
```

The harness never persists proving or verifying keys merely for measurement.
It retains every raw run, applies the 15% adaptive run rule, asserts semantic
parity and proof/linkage invariants, and refuses aggregation without completed
pinned-image/source provenance. The actual `swiyu-verifier` source is
independently required to be clean, fingerprinted before and after the image
build, and recorded by commit and full tracked-source SHA-256.

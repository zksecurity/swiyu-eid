# Residence eligibility benchmark results

## Result

The optimized relation proves, without disclosing either input, that an
issuer-signed residence object names a BFS municipality in the verifier's
accepted set and a canonical start date at least the required number of whole
UTC days before `currentTime`. The proof also binds the accepted issuer key and
VCT, holder P-256 possession, credential validity, fresh verifier challenge,
and VALID status from an authenticated status snapshot.

The direct no-ZK control uses the same credential, issuer and holder
signatures, status URI/index/value, snapshot, time, and policy. It discloses the
exact signed `{municipality_bfs,since}` object and evaluates the same set and
duration predicates in ordinary TypeScript. It is not a no-op or a precomputed
eligibility Boolean.

## Scientific setup

The authoritative campaign ran from clean commit
`6e2464dcee8ee3129737694ddda2681e8fef09e3` in image
`sha256:c201b0ab1a15ee35eb195d0959f6fbbada6d5f849da9f780cfd8cdca1673f488`
on Linux/ARM64. The container enforced CPU set `0-3`, a four-CPU quota, 12 GiB
memory with no swap expansion, 4,096 processes/tasks, and no network. Node was
22.14.0, Rust 1.91.0, Circom 2.2.3, optimization `--O2`, and the curve was
`secq256r1`.

Control, witness, and native proving processes were fresh and strictly serial.
Profiles were interleaved in rotating order with recorded 30-second idle
intervals around heavy phases. The predeclared rule retained three samples
unless any principal first-two stage differed by more than 15% relative to
their mean; residence crossed that threshold, so every control, witness,
native, and SDK-host sample expanded to seven. No sample was discarded.

The first-operation control numbers below are the first measured operation in
each fresh worker with fixtures already materialized and potentially
page-cached. The warmed sensitivity uses 100 warm-ups and 1,000 timed
operations. Neither is presented as a cold filesystem or network measurement.

## Compiled optimization

| relation | constraints | R1CS bytes | witness WASM bytes |
|---|---:|---:|---:|
| combined-disclosure Prepare | 2,364,636 | 495,486,680 | 9,839,681 |
| packed-status-v2 Show | 630,413 | 155,065,852 | 2,886,046 |
| optimized linked pair | 2,995,049 | 650,552,532 | 12,725,727 |
| two-disclosure + legacy-status pair | 3,597,121 | 787,664,004 | 15,084,373 |
| reduction | 602,072 (16.74%) | 137,111,472 (17.41%) | 2,358,646 (15.64%) |

Prepare holds 78.95% of the optimized pair's constraints and Show 21.05%.
Combining the two residence fields into one canonical object disclosure removes
328,476 Prepare constraints. Replacing the 11-level per-status ternary path
with a six-level path over authenticated 64-byte packed-status chunks removes a
further 273,596 Show constraints: Show falls from 904,009 to 630,413
(30.26%), its R1CS from 222,474,728 to 155,065,852 bytes (30.30%), and its WASM
from 3,972,029 to 2,886,046 bytes (27.34%).

## Measured lifecycle

Times are wall-clock medians across seven fresh processes; brackets are the
retained minimum and maximum. Totals are sums of explicitly timed components,
not simulated end-to-end request samples.

| ZK lifecycle bucket | median | retained range |
|---|---:|---:|
| one time per circuit version: setup + key serialization | 51.807 s | 49.551–60.247 s |
| reusable once per credential: Prepare witness + handoff + assignment | 15.432 s | 15.179–17.025 s |
| each presentation, wallet: linked Prepare proof + Show witness/proof | 14.770 s | 13.483–15.307 s |
| each presentation, verifier: deserialize + verify both proofs | 1.698 s | 1.438–2.264 s |
| first-presentation wallet work: reusable + presentation work | 30.438 s | 29.210–31.326 s |

Mean-based component shares make the bottlenecks explicit:

| bucket | measured component shares |
|---|---|
| one-time setup | Prepare setup 82.6%; Show setup 16.3%; key serialization 1.1% |
| reusable Prepare | assignment 55.5%; witness generation 43.5%; witness handoff 1.0% |
| presentation wallet | Prepare proof 53.3%; Show witness 22.5%; Show assignment 12.8%; Show proof 10.2%; handoff/serialization/randomness 1.1% |
| presentation verifier | Prepare verification 75.8%; Show verification 16.3%; Prepare deserialization 6.1%; Show deserialization 1.9% |

The first-presentation wallet total is 52.1% reusable Prepare work and 47.9%
presentation work. After Prepare is cached, the recurring wallet cost is the
14.770-second presentation row, not the 30.438-second first-presentation sum.

The exact profile-specific SDK adapter adds a 5.426 ms median to reusable
Prepare orchestration, 17.351 ms to presentation construction/framing, and
19.246 ms to verifier dispatch. With those measured components included, the
estimates are 15.437 s reusable, 14.787 s presentation-wallet, and 1.718 s
presentation-verifier.

## Matched no-ZK comparison

| lifecycle bucket | first operation in fresh worker | warmed steady-state sensitivity | ZK + measured SDK estimate |
|---|---:|---:|---:|
| trust/circuit setup | 0.557 ms | 0.0097 ms | 51.807 s |
| reusable per credential | 10.441 ms | 4.814 ms | 15.437 s |
| presentation wallet | 5.125 ms | 0.618 ms | 14.787 s |
| presentation verifier | 15.901 ms | 9.193 ms | 1.718 s |
| transmitted presentation | 1,339 B | 1,339 B | 345,051 B |

Using the predeclared fresh-worker denominator, the SDK-composed ZK estimate is
93,025× the setup time, 1,478.5× the reusable wallet time, 2,885.3× the
presentation-wallet time, 108.0× the verifier time, and 257.7× the transmitted
bytes. These large ratios are expected because the control verifies ordinary
signatures and hashes while the ZK path constructs and proves two large R1CS
relations. Absolute times are the more useful deployment quantities.

## Status preprocessing, artifacts, and memory

Both primary paths begin with the same authenticated packed status bytes. An
ordinary verifier performs an O(1) two-bit lookup. ZK additionally built the
packed-chunk ternary tree once per snapshot in a 20.151 ms median
(18.811–22.218 ms) and selected a credential path in 0.246 ms
(0.215–0.319 ms). The tree cost is reusable across credentials under the same
snapshot; the path cost is charged per credential.

| exact artifact | Prepare | Show | linked pair |
|---|---:|---:|---:|
| proving key(s) | 599,566,722 B | 183,551,810 B | 783,118,532 B |
| verifying key(s) | 599,566,690 B | 183,551,778 B | 783,118,468 B |
| native proof | 180,055 B | 78,391 B | 258,446 B |
| R1CS | 495,486,680 B | 155,065,852 B | 650,552,532 B |
| witness file | 72,514,988 B | 19,937,164 B | 92,452,152 B |

The native process peak RSS median was 4,103,446,528 bytes, with a retained
range of 4,103,258,112–4,106,051,584 bytes. The witness-process median was
1,130,450,944 bytes. These processes run separately, so their RSS values must
not be added. The exact raw proof pair is 258,446 bytes; JSON/base64url SDK
framing expands it to 345,051 bytes.

## Interpretation boundary

Under a verifier-pinned issuer key/VCT and a fresh authenticated status
snapshot, the relation establishes what the issuer signed about the private
residence object. It does not independently establish physical presence,
official directory correctness, or uninterrupted residence beyond the
issuer's statement. The benchmark directory is a frozen two-entry parity
fixture, not a complete official BFS register. A one-element public allow-list
reveals the municipality by inference, and repeated duration thresholds can
narrow the hidden date.

All raw samples, process metadata, command records, correctness assertions, and
the aggregate are retained under
`container-results/20260818T090021Z/`; the machine-readable headline is
`zk-overhead-results.json` in that directory.

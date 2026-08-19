# Swiss canton eligibility predicate

## Business question

Prove that the holder's issuer-authenticated `resident_canton` belongs to a
verifier-published allow-list without disclosing which eligible canton it is.
This supports geographically restricted public services, insurance products,
tax workflows, and regulated offers. The current profile deliberately limits a
policy to four cantons so the public policy remains transparent and the online
relation stays small.

## Sound Prepare/Show boundary

Prepare verifies the issuer's ES256 signature, canonical compact SD-JWT and
JSON structure, exact top-level disclosure digest membership, the exact
`[salt,"resident_canton","ZH"]` disclosure shape, one of the 26 official
two-letter canton codes, the holder P-256 key, validity bounds, status index,
and stable lookup/status-URI hashes. Its eleven outputs are hidden Spartan
shared rows.

Show reuses those exact rows. It verifies holder possession, credential time
bounds, the fresh status-list Merkle path, verifier-session commitments, and
membership in the one-to-four-canton public allow-list. Prepare and Show proofs
are reblinded with the same randomness and accepted together only if their
proof-embedded shared commitments match.

The profile adapter consumes a verifier-selected issuer key, status URI, and
snapshot root; it does not itself resolve DID keys or authenticate/freshness-
check the upstream status-list object. A production caller must perform those
trust checks before constructing `SwiyuCantonVerifierPolicy`, as the existing
age-profile sidecar does for its authoritative snapshot registry.

The negative linkage fixture changes `ZH` to `BE`. Both are canonical and both
are included in the verifier policy, so the altered Show remains independently
valid; its shared commitment nevertheless differs from the `ZH` Prepare proof
and the pair is rejected. A second negative fixture proves that an allow-list
which excludes `ZH` cannot produce a witness.

## Optimizations

Reusable across predicates:

- The compact 896-byte issuer envelope and credential-time Prepare stage are
  reused from the optimized age profile.
- Stable credential lookup and status URI are hashed once in Prepare; Show
  hashes only the fresh challenge/status bindings.
- The 17-level binary status proof, direct shared-row synthesis, and final-proof
  path avoid generic policy machinery and the discarded initial-proof pass.

Predicate-specific:

- A canton is a single 16-bit `ASCII[0] * 256 + ASCII[1]` scalar, not a private
  string carried through Show.
- Canonicality is checked once in Prepare against 26 constants.
- Show performs at most four gated field equalities. Unused public slots must be
  zero, and duplicate allow-list entries are rejected by the host API.
- No JSON, SHA-256, string comparison, or general set-membership gadget is added
  to the online predicate.

## Benchmark method

Artifact sizes come from Circom `--O2 --prime secq256r1` R1CS/WASM output and
in-memory bincode serialization. Proving and verifying keys are never written
to disk. Witness generation, per-circuit setup, assignment construction, final
linked proof generation, and verification are measured separately. The first
two complete native runs determine repetition count: three total when every
principal stage differs by at most 15%, otherwise seven. Raw runs and
min/median/max/coefficient-of-variation statistics are retained in
`canton-benchmark-results.json`.

## Exact circuit and artifact sizes

These values are deterministic for the checked-in sources and compiler flags;
they are not host-timing estimates.

| Measure | Prepare | Show | Combined |
|---|---:|---:|---:|
| Constraints | 2,462,518 | 1,271,288 | 3,733,806 |
| Wires | 2,359,062 | 1,256,324 | 3,615,386 |
| R1CS bytes | 518,376,940 | 313,437,776 | 831,814,716 |
| WASM bytes | 10,194,876 | 5,404,260 | 15,599,136 |
| Witness bytes | 75,490,060 | 40,202,444 | — |
| Proving-key bytes | 622,868,842 | 370,512,194 | 993,381,036 |
| Verifying-key bytes | 622,868,810 | 370,512,162 | 993,380,972 |
| Final proof bytes | 180,055 | 112,263 | 292,318 |
| Reusable assignment bytes | 134,348,817 | 67,174,417 | — |

Compared with the age Prepare/Show profile, canton eligibility adds 6,871
constraints (+0.184%), 1,014,092 combined R1CS bytes (+0.122%), and 973,840
combined proving-key bytes (+0.098%). Prepare is 6,895 constraints larger
because it validates one of 26 canonical canton codes. Show is 24 constraints
smaller than age despite supporting four public policy slots. Its proof is 128
bytes larger because the transparent policy adds four public field elements.

## Cost phases

| Frequency | Work | Stored/reused result |
|---|---|---|
| Once per compiled Prepare circuit | Spartan setup | 622,868,842-byte proving key and 622,868,810-byte verifying key |
| Once per compiled Show circuit | Spartan setup | 370,512,194-byte proving key and 370,512,162-byte verifying key |
| Once per credential | Prepare witness and assignment construction | 134,348,817-byte assignment plus its 135,471-byte committed instance |
| Every presentation | Fresh linked Prepare proof from the reusable assignment; Show witness, assignment, and proof | 180,055-byte Prepare proof plus 112,263-byte Show proof |
| Every verification | Verify both proofs and compare their embedded shared commitments | One linked proof pair accepted or rejected |

Setup is therefore not part of presentation latency. Prepare witness generation
and assignment construction are amortized over presentations, but the Prepare
final-proof step is not: each presentation must reblind a fresh Prepare proof
with the same fresh randomness as Show. Presentation latency and transmitted
bytes must include both proofs, and verifier latency must include both proof
verifications plus the commitment comparison.

## Local correctness/sizing pilot

The local host pilot expanded to seven native runs because a first-two
principal-stage delta exceeded 15%. Every proof verified and every negative
linkage check behaved as expected. These timings demonstrate operability and
give sizing guidance, but are **not** the final no-ZK/age/canton latency
comparison: that comparison must use the serial pinned-Docker run described in
the project-wide benchmark report.

| Pilot timing (ms) | Min | Median | Max | CV |
|---|---:|---:|---:|---:|
| Prepare setup | 19,238 | 23,826 | 27,070 | 9.48% |
| Prepare assignment | 6,296 | 7,129 | 9,571 | 13.36% |
| Prepare final proof | 4,834 | 6,202 | 9,950 | 22.49% |
| Prepare verify | 762 | 969 | 1,047 | 11.01% |
| Show setup | 10,213 | 11,322 | 11,667 | 4.67% |
| Show assignment | 2,547 | 2,793 | 3,039 | 5.87% |
| Show final proof | 2,352 | 2,828 | 3,186 | 10.14% |
| Show verify | 353 | 416 | 527 | 13.23% |

Witness generation did not trigger expansion: three Prepare runs were
9,031.450, 9,358.928, and 7,960.308 ms (median 9,031.450 ms, CV 6.80%); three
Show runs were 7,312.293, 8,224.216, and 6,138.244 ms (median 7,312.293 ms,
CV 11.82%). Peak native resident memory was 3,646,423,040 bytes.

All seven raw native records are retained in
`canton-eligibility-native-pilot-results.json`; raw witness records are in
`canton-eligibility-witness-pilot-results.json`.

Reproduce the artifacts with the two `compile:swiyu:canton-*` Circom scripts,
the SDK's `benchmark:swiyu-canton-witness` script, and the
`swiyu-canton-benchmark` Rust release binary. The witness and native harnesses
apply the adaptive repetition rule themselves.

## Scope and next step

This is an experimental but complete vertical slice. It intentionally clones
the authenticated disclosure parser because the original profile hard-codes
`birthdate`. A production follow-up should factor a reviewed generic
authenticated-disclosure extractor; it must not make disclosure names or
parsing structure unconstrained witness hints.

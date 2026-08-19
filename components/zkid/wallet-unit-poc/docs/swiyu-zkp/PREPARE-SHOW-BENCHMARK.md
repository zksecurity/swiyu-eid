# Prepare/Show circuit split

The zkID idea is viable for this swiyu profile, but its benefit is
amortization rather than a smaller total relation. Credential authentication
and parsing move into a reusable **Prepare** assignment; verifier-session,
fresh status, holder-signature, and age checks remain in **Show**. The two
final Spartan proofs are reblinded with the same randomness and accepted as a
pair only when their proof-embedded shared commitments are identical.

## What each stage proves

| Prepare: credential-bound and reusable | Show: fresh per presentation |
|---|---|
| Issuer P-256 signature | Holder P-256 signature over challenge |
| Protected-header and Swiss-profile fields | `nbf <= current_time < exp` |
| Compact JWS base64 and JSON structure | Age cutoff comparison |
| SD-JWT disclosure digest and birthdate extraction | Status Merkle path and `VALID` value |
| Holder key, validity interval, status URI/index | Challenge-bound metadata commitment |
| Stable lookup and status-URI hashes | Fresh status-snapshot binding |

The hidden shared vector contains the holder P-256 coordinates, numeric
birthdate, `nbf`, `exp`, status index, two lookup-hash limbs, two status-URI
hash limbs, and the successful result bit. Prepare authenticates those values;
Show consumes the same values. They are not public inputs.

## Exact circuit and artifact measurements

Circom 2.2.3, `--O2`, `secq256r1`, local arm64 macOS run on 2026-08-17.
Byte counts are exact uncompressed serialized sizes; times are one local run
and should be treated as machine-dependent.

| Measurement | Prepare | Show | Combined | Compact monolith |
|---|---:|---:|---:|---:|
| constraints | 2,455,623 | 1,271,312 | 3,726,935 | 3,727,383 |
| share of monolithic constraints | 65.88% | 34.11% | 99.99% | 100% |
| R1CS | 517,356,964 B | 313,443,660 B | 830,800,624 B | 831,970,724 B |
| witness WASM | 10,167,017 B | 5,399,160 B | 15,566,177 B | — |
| fixture WTNS | 75,268,396 B | 40,203,372 B | 115,471,768 B | — |
| proving key | 621,889,042 B | 370,518,154 B | 992,407,196 B | — |
| verifying key | 621,889,010 B | 370,518,122 B | 992,407,132 B | — |
| final proof | 180,055 B | 112,135 B | 292,190 B | — |

The split removes only 448 constraints and 1,170,100 R1CS bytes in total. It
does not explain away the large keys: Spartan serializes relation-sized data in
both keys. The practical change is that the 2.46M-constraint credential stage
can be prepared once while the 1.27M-constraint Show relation changes with each
verifier request.

## Exact lifecycle timings

| Operation | Prepare | Show |
|---|---:|---:|
| witness generation | 7,633 ms | 7,659 ms |
| circuit setup, once per circuit version | 22,870 ms | 12,033 ms |
| build committed assignment | 7,108 ms | 3,440 ms |
| emit final linked proof | 9,445 ms | 2,644 ms |
| verify final proof | 1,327 ms | 420 ms |

Setup is a release/build cost, not a per-credential operation. Prepare witness
generation and assignment construction are per credential. Each presentation
still needs a fresh Show witness and assignment, one final Prepare proof, one
final Show proof, and verification of both. The reusable Prepare state in this
run is also large: its serialized instance plus assignment is 134,484,288
bytes.

The inherited helper constructed a complete unlinked proof and then discarded
it before constructing the transmitted reblinded proof. The measured control
costs were 12,767 + 4,979 ms for Prepare and 8,064 + 2,779 ms for Show. The new
`prepare_circuit_assignment_in_memory` path builds the instance/assignment
directly and emits only the final linked proof.

## Amortization

At the relation level, `m` monolithic presentations cost
`m * 3,727,383` constraints. The split costs
`2,455,623 + m * 1,271,312` constraints before the cryptographic cost of
re-emitting the linked Prepare proof is considered. Two presentations reduce
that relation work by 32.95%; three reduce it by 43.93%; the marginal Show
relation is 34.11% of the compact monolith.

This is most useful when one authenticated credential supports several
presentations or parallel predicates. The composition mechanism and constrained
shared-output wrapper are predicate-independent. The current Prepare artifact
is not fully predicate-independent because its shared schema specifically
extracts birthdate and status fields; another claim requires a versioned shared
schema and, when necessary, another authenticated extraction rule.

## Binding test

The benchmark proves three properties:

1. Prepare and Show expose the same eleven constrained hidden outputs.
2. Reblinding both proofs with the same randomness produces identical embedded
   shared commitments, and both proofs verify under their own keys.
3. A second Show witness with a different but still valid birthdate also
   verifies individually, but its reblinded commitment differs and the pair is
   rejected.

This last control matters. Comparing caller-supplied instances is insufficient;
the verifier must compare `prepare_proof.comm_W_shared()` directly with
`show_proof.comm_W_shared()` after verifying both proofs.

## Reproduction

```sh
cd wallet-unit-poc/circom
npm run compile:swiyu:prepare
npm run compile:swiyu:show-split

cd ../openac-sdk
SWIYU_SPLIT_BENCHMARK=1 npx vitest run \
  tests/swiyu-zkp/split-benchmark-witness.test.ts

cd ../ecdsa-spartan2
cargo run --release --no-default-features --bin swiyu-split-benchmark
```

Machine-readable results are in
`docs/swiyu-zkp/prepare-show-benchmark-results.json`.

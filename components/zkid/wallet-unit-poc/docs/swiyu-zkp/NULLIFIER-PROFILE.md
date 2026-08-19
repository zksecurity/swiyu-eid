# Credential-scoped one-claim nullifier

## Exact guarantee

The profile permits at most one accepted claim for the same issuer-authenticated
credential/nullifier attestation in one registry namespace, verifier domain,
program, claim type, eligibility policy, and epoch. It does **not** prove one
natural person, one claim. The credential seed is also bound to the exact JWS
signing-input digest, so an ordinary reissue changes the nullifier even if the
issuer preserves the UID and wallet-secret commitment. Reissuance-stable
one-per-person semantics would require a separate issuer-authenticated,
reissuance-stable pseudonym and its own governance and recovery rules.

The wallet creates a non-zero random 32-byte secret `s` with the platform
CSPRNG and stores it as protected credential-bound key material. The issuer
authenticates a random 32-byte `credential_uid` and
`SHA256(u16be(13) || "swy-nf-sec-v1" || s)`. Prepare proves the secret opening
and derives a hidden credential seed. Show publishes only

```text
SHA256(u16be(13) || "swy-nf-val-v1" || credential_seed || scope_digest)
```

as two 128-bit limbs. The verifier derives `scope_digest` from fixed-width
registry, origin, program, claim-type, epoch, and eligibility-policy values.
The fresh session nonce and claim payload are challenge-bound separately. The
holder-authorized challenge also domain-separates this profile and binds the
canonical scope digest. The nonce must not enter the scope itself, or every
retry would obtain a different nullifier.

## Integrated credential experiment

`swiyu_nullifier_age18_prepare` and
`swiyu_nullifier_age18_show_packed_chunk_v2` put age eligibility, issuer
signature, holder possession, validity, live status, session binding, and
nullifier derivation into one linked Prepare/Show pair. The two hidden
credential-seed limbs extend the base age relation's shared values.

The current synthetic age credential does not contain nullifier attributes.
The experiment therefore uses a second ES256 issuer attestation over:

```text
credential_uid || secret_commitment || age_credential_binding
```

`age_credential_binding` is the exact SHA-256 digest of the original protected
JWS signing input, reused from the issuer ES256 relation. Consequently an
attestation cannot be mixed with a differently encoded same-issuer credential,
even if selected parsed fields happen to match. A production VCT should carry
the UID and commitment inside the original issuer-signed compact JWS, removing
this auxiliary integration signature while retaining the same secret-opening,
scope, and registry construction.

## Compiled optimization

Circom 2.2.3, `--O2`, `secq256r1`:

| relation | constraints | delta from packed age |
|---|---:|---:|
| packed age Prepare | 2,455,623 | — |
| age + nullifier Prepare | 2,624,076 | +168,453 |
| packed-v2 age Show | 630,088 | — |
| packed-v2 age + nullifier Show | 692,194 | +62,106 |
| packed-v2 age linked pair | 3,085,711 | — |
| packed-v2 age + nullifier pair | 3,316,270 | +230,559 (+7.47%) |

The first integrated draft was 4,145,010 constraints. Reusing the exact JWS
digest already computed for issuer verification reduced the legacy-status pair
to 3,957,494 constraints, saving 187,516. Replacing the per-status path with
packed-status chunks reduced the deployable pair to 3,316,270 constraints,
728,951,156 R1CS bytes, and 13,984,238 witness-WASM bytes. Relative to the
optimized legacy-status pair, that removes 641,224 constraints (16.20%),
158,438,804 R1CS bytes (17.85%), and 2,536,200 WASM bytes (15.35%). Show itself
falls from 1,333,418 to 692,194 constraints (48.09%).

The matching packed age pair is 3,085,711 constraints, 672,361,820 R1CS bytes,
and 13,029,931 WASM bytes. The nullifier therefore adds 230,559 constraints
(7.47%), 56,589,336 R1CS bytes (8.42%), and 954,307 WASM bytes (7.32%). The
isolated nullifier core and standalone Show decorator are diagnostic only; a
deployable profile must also prove issuer, holder, status, validity, predicate,
and Prepare/Show linkage.

## Pinned lifecycle benchmark

The authoritative run used clean commit
`6e2464dcee8ee3129737694ddda2681e8fef09e3` and pinned Linux/ARM64 image
`sha256:c201b0ab1a15ee35eb195d0959f6fbbada6d5f849da9f780cfd8cdca1673f488`.
The container enforced CPU set `0-3`, four CPUs, 12 GiB memory, no network, and
strictly serial fresh workers. The predeclared first-two/15% rule expanded the
circuit, no-ZK control, SDK host, and durable-state studies to seven retained
samples; no sample was discarded.

Times are wall-clock medians; brackets contain the retained minimum and
maximum. Lifecycle totals are sums of separately timed components.

| ZK lifecycle bucket | median | retained range |
|---|---:|---:|
| one time per circuit version: setup + key serialization | 61.039 s | 55.251–76.847 s |
| reusable once per credential: Prepare witness + handoff + assignment | 17.684 s | 16.362–18.727 s |
| each presentation, wallet: linked Prepare proof + Show witness/proof | 15.729 s | 14.540–17.119 s |
| each presentation, verifier: deserialize + verify both proofs | 1.798 s | 1.683–2.781 s |
| first-presentation wallet work: reusable + presentation work | 32.526 s | 31.862–35.394 s |

Mean-based shares locate the cost:

| bucket | measured component shares |
|---|---|
| one-time setup | Prepare setup 84.1%; Show setup 14.8%; key serialization 1.1% |
| reusable Prepare | assignment 54.8%; witness generation 44.0%; handoff 1.3% |
| presentation wallet | Prepare proof 53.3%; Show witness 23.3%; Show assignment 12.2%; Show proof 10.0%; handoff/serialization/randomness 1.2% |
| presentation verifier | Prepare verification 77.8%; Show verification 15.4%; Prepare deserialization 5.2%; Show deserialization 1.7% |

The first presentation is 52.4% reusable preparation and 47.6% presentation
work. The exact profile SDK adapter adds 5.322 ms to preparation, 16.484 ms to
Show orchestration/framing, and 43.361 ms to verification and
verify-before-claim dispatch. The composed estimates are therefore 17.690 s,
15.746 s, and 1.841 s respectively.

### Exact no-ZK control

The ordinary control authenticates the same SD-JWT, holder proof, status,
validity, and `age_over_18=true`, discloses the issuer-authenticated random
credential UID, derives the same canonical scope, and performs the identical
atomic spent-key/claim transition. Its privacy cost is revealing a stable UID
within the credential's lifetime. It does not skip the uniqueness policy.

| lifecycle bucket | first operation in fresh worker | warmed steady-state sensitivity | ZK + measured SDK estimate |
|---|---:|---:|---:|
| trust/circuit setup | 0.325 ms | 0.0086 ms | 61.039 s |
| reusable per credential | 9.501 ms | 4.520 ms | 17.690 s |
| presentation wallet | 5.282 ms | 0.636 ms | 15.746 s |
| stateless presentation verifier | 13.133 ms | 9.475 ms | 1.841 s |
| transmitted presentation | 1,818 B | 1,818 B | 344,524 B |

Using the fresh-worker denominator, the composed ZK estimate is 187,620×
setup, 1,861.8× reusable wallet work, 2,981.2× presentation-wallet work,
140.2× stateless verification, and 189.5× transmission. The fair marginal
comparison is much smaller because both ZK profiles already pay for the base
age/status relation: the nullifier adds 15.2% to median setup, 8.1% to reusable
work, 13.4% to presentation-wallet work, and 4.0% to verifier work. The raw
proof pair grows by only 128 bytes.

### Exact artifacts and memory

| exact artifact | Prepare | Show | linked pair |
|---|---:|---:|---:|
| proving key(s) | 663,863,002 B | 199,298,290 B | 863,161,292 B |
| verifying key(s) | 663,862,970 B | 199,298,258 B | 863,161,228 B |
| native proof | 180,055 B | 77,975 B | 258,030 B |
| R1CS | 558,483,908 B | 170,467,248 B | 728,951,156 B |
| witness file | 80,584,172 B | 21,889,932 B | 102,474,104 B |

The native process peak RSS median was 4,382,019,584 bytes
(4,144,771,072–4,384,141,312 bytes); the separate witness-process median was
1,378,672,640 bytes. JSON/base64url framing expands the 258,030-byte native
proof pair to 344,524 transmitted bytes.

## Registry acceptance

Proof validation alone does not prevent two concurrent claims. After both
proofs verify and their embedded shared commitments match, a production
verifier must atomically insert a unique spent key and create the claim, or a
transactional outbox entry, in the same database transaction. `SELECT`
followed by `INSERT` is not sufficient.

The reference durable store uses the full unique key
`(registry_namespace, scope_digest, nullifier)`. The default scope includes the
verifier origin, so it is one claim per credential per verifier. A consortium
can share the guarantee only by agreeing on one canonical scope and one atomic
registry. Independently operating or offline replicas can both accept before
reconciliation.

The ordinary no-ZK path and the ZK path pay the same durable transition. The
reference SQLite implementation uses WAL, `synchronous=FULL`,
`BEGIN IMMEDIATE`, and paired spent-key/accepted-claim tables. Across seven
runs, store setup was 12.554 ms median (11.255–13.994 ms), the complete first
claim transition 0.454 ms (0.420–0.580 ms), a successful atomic transaction
0.540 ms, and an already-spent conflict 0.0068 ms. Adding this common state to
both paths changes the composed first-claim verifier ratio from 140.2× to
135.6×.

Offline verifiers can detect duplicates after synchronization but cannot
prevent two concurrent acceptances. ZK hides the stable UID and replaces it
with unlinkable values across different scopes; it does not create the
underlying uniqueness policy.

## Security and concurrency tests

The host suite checks deterministic reuse, independent scope dimensions,
credential and secret separation, fixed issuer-record encoding, limb/epoch
range rejection, all-zero secret rejection, exact-JWS binding, and concurrent
registry insertion. The file-backed suite checks genuinely overlapping 2/4/8
worker races, FULL-sync WAL, paired claim rows, and rollback after an injected
mid-transaction failure. Each same-nullifier race produced exactly one winner;
every distinct-nullifier worker succeeded; no run produced an orphan row.

Circuit compilation range-constrains every byte and digest limb. Backend tests
also reject independently valid but unlinked Prepare/Show halves, altered
public scope/nullifier limbs, ineligible/expired/revoked credentials, and
transactional claim duplication.

All samples, command records, concurrency traces, and the aggregate report are
retained under `container-results/20260818T090021Z/`.

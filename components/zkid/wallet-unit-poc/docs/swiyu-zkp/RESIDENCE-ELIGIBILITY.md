# Residence eligibility predicate

## Proven statement

For credential type `urn:ch:swiyu-lab:residence-eligibility:v1`, prove that an
accepted Swiss residence authority signed one object-valued SD-JWT disclosure
stating:

1. the holder's current main-residence municipality is in a verifier-selected
   set of 1–16 official BFS municipality identifiers; and
2. uninterrupted main residence began at least the verifier-selected number of
   whole UTC days ago.

The proof does not reveal the exact municipality, exact arrival date, address,
holder key, credential status index, or status-list URI. The parity fixture is
issued by `did:example:issuer`; production deployments must pin the
real trusted issuer key and credential type outside the circuit.

The date is the eCH-0011 `arrivalDate` of `mainResidence`, not a dwelling or
address `movingDate`. The municipality identifier is the BFS identifier from a
specific edition of the eCH-0007-compatible official municipality directory.

## Exact authenticated disclosures

The optimized Prepare profile accepts exactly this compact JSON tuple shape:

```json
["<22-char salt>","residence",{"municipality_bfs":261,"since":"2023-01-01"}]
```

Its encoded disclosure digest must appear in the issuer-signed top-level `_sd`
array. The clear payload is forbidden from also containing the claim. The
field order, punctuation, and lack of insignificant whitespace shown above are
part of this experimental VCT's canonical wire grammar.
Municipality identifiers are integers in `1..6999`, without leading zeros.
Dates use canonical `YYYY-MM-DD`, validate Gregorian month/leap-day boundaries,
and are limited to `1900-01-01..2199-12-31`.

The salt is constrained to the canonical unpadded base64url spelling of exactly
16 bytes. In particular, the unused low four bits of its final base64url
character must be zero. This establishes format, not randomness: the issuer or
wallet must generate it with a CSPRNG and must not use the deterministic test
salt in production.

Combining the two values is the principal size optimization and a deliberate
selective-disclosure tradeoff: municipality and arrival date cannot later be
released independently. The original two-disclosure circuit remains as the
controlled A/B relation. This representation should only be adopted in a VCT
whose data model treats the pair as one claim.

## Prepare and Show split

Prepare is performed once for a credential and is reusable across presentations.
It performs the expensive issuer-side authentication work:

- strict compact JWS/base64url and JSON structure validation;
- accepted JOSE/profile fields and P-256 issuer-signature verification;
- holder-key, validity interval, status coordinates, issuer/kid/VCT, and status
  URI extraction;
- one exact object-valued SD-JWT disclosure parse, SHA-256 digest
  recomputation, signed `_sd` membership, and canonical salt checks;
- Gregorian date-to-day conversion; and
- preparation of ten hidden shared values for linkage to Show.

The two private claims occupy one 30-bit shared scalar:

```text
packedResidence = municipalityBfs + 8192 * residenceSinceDay1900
```

This is a representation optimization, not a weakening: Show bit-decomposes it
into an independently range-checked 13-bit municipality and 17-bit day index.

Show is performed for each verifier presentation. It proves a fresh holder
P-256 signature, credential validity at `currentTime`, membership in the public
municipality allow-list, the minimum-duration inequality, and VALID status from
one authenticated 64-byte packed-status chunk. The primary packed-v2 relation
uses a six-level ternary path over at most 512 chunks (131,072 two-bit status
entries); the selected chunk is unpacked in-circuit and the selected two-bit
status must be zero. Commitments bind the accepted lookup, status URI/snapshot,
and fresh verifier challenge. The native split-proof layer must enforce
equality of all ten hidden shared values between the two proofs. The older
11-level per-status ternary relation remains only as the controlled A/B.

The production residence status adapter does not accept a raw URI/root pair.
It verifies the issuer-signed `statuslist+jwt`, protected profile fields,
issuer/subject binding, freshness, bounded zlib output, 2-bit packing, selected
credential index, and VALID value. It then builds the ternary tree directly
from those authenticated packed statuses. The wallet retains the private URI,
root, tree, and path; the verifier receives a class instance containing only
the prepared `H(uri, root)` commitment and non-private provenance metadata.

Duration uses elapsed whole UTC days:

```text
currentDay1900 = floor(currentTime / 86400) + 25567
residenceSinceDay1900 + minimumResidenceDays <= currentDay1900
```

Thus the boundary is inclusive and does not depend on local time zones or
daylight-saving transitions. The supported public duration is `1..3650` days.

## Verifier-owned directory provenance

The verifier policy carries both `municipalityDirectoryAsOf` and the lowercase
SHA-256 of the canonical pinned directory artifact. The 16 BFS codes only have
meaning relative to that snapshot. The API requires the caller-provided
`challengeHash` to be computed over a challenge containing both provenance
fields; the circuit exposes that hash as a public session binding. A production
challenge constructor should make this serialization a versioned profile rule.

The circuit proves membership in the pinned numeric set. It does not prove that
the verifier downloaded the artifact from BFS, interpreted mergers correctly,
or selected a sensible policy. Those are verifier governance responsibilities.

## Exact non-ZK control

The defensible control is the same signed credential, issuer, holder binding,
preauthenticated status snapshot, times, VCT, and the same object-valued
disclosure. An ordinary
SD-JWT presentation sends that encoded disclosure to the verifier. The
verifier:

1. verifies the issuer JWS and holder proof;
2. hashes the supplied disclosure and checks its digest in signed `_sd`;
3. validates time and the URI/index/VALID value under the same snapshot;
4. reads municipality `261` and arrival date `2023-01-01` in the clear; and
5. runs the same allow-list and whole-day inequality in ordinary application
   code.

That is the no-ZK baseline—not a synthetic no-op and not a credential with a
precomputed `residence_eligible` boolean. Its privacy cost is revealing both
fields of the predicate input. The directory provenance and policy remain
verifier-owned; they must not be added as unsigned or issuer-controlled
credential claims merely to make the control look similar.

Status-list fetch, JWS authentication, freshness checks, and bounded
decompression are upstream common work and are excluded from both benchmark
paths. Starting from the same authenticated packed bytes, the ordinary control
performs an O(1) two-bit lookup. The benchmark separately measures the ZK-only
packed-chunk tree construction once per status snapshot and path selection per
credential. Production code still performs the full resolver checks described
above.

## Benchmark interpretation

Report the following stages separately:

- no-ZK SD-JWT parse/signature/disclosure/status/policy verification;
- per-status-snapshot packed-chunk ternary tree construction;
- per-credential packed-chunk path generation;
- one-time Prepare witness generation, setup/key generation, proving, and
  verification;
- reusable Show witness generation, setup/key generation, proving, and
  verification; and
- proof/witness/key/artifact byte sizes.

Circuit compilation is a development artifact-generation cost and must not be
reported as a wallet or verifier runtime. Ternary tree construction is also not
free fixture setup: it is an amortizable status-snapshot stage and is recorded
separately from path and circuit-witness generation.

The residence witness benchmark uses two initial samples. If either principal
stage differs by more than 15% relative to the pair mean, it expands to seven
runs; otherwise it records three. A fixed-run environment override exists only
for relation smoke tests. For scientific comparisons, run all controls and ZK
stages inside the same pinned container/cpuset, preserve raw samples, identify
warmups explicitly, and report median, mean, standard deviation, coefficient of
variation, peak RSS, and toolchain/image identity.

## Trust and privacy boundaries

- Issuer/key trust, VCT acceptance, and directory provenance remain verifier
  inputs. Status signature, freshness, URI binding, root derivation, and index
  validity are enforced by the authenticated ternary resolver rather than
  accepted as caller-supplied URI/root values.
- A public allow-list can itself identify a municipality when it has one entry.
  With multiple entries, the proof hides which accepted entry matched but leaks
  membership in that set.
- The exact date remains hidden, but a very demanding duration threshold and
  repeated adaptive queries can narrow it. Policy profiles should rate-limit or
  coarsen thresholds where this matters.
- Prepare/Show privacy and soundness depend on the native backend proving the
  complete R1CS relations and enforcing hidden-row linkage; witness generation
  alone is not a production proof.

## Primary references

- Swiss e-ID overview (including residence certificates):
  <https://www.eid.admin.ch/en/e-id-e>
- eCH-0011 person-data standard:
  <https://www.ech.ch/sites/default/files/dosvers/hauptdokument/STAN_d_DEF_2014-06-06_eCH-0011_V8.1_Datenstandard%20Personendaten.pdf>
- eCH-0007 municipality-data standard:
  <https://www.ech.ch/sites/default/files/dosvers/hauptdokument/STAN_d_DEF_2022-10-10_eCH-0007_V6.0_Datenstandard%20Gemeinden.pdf>
- Official BFS municipality directory application:
  <https://www.agvchapp.bfs.admin.ch/de>
- SD-JWT RFC 9901: <https://www.rfc-editor.org/rfc/rfc9901.html>

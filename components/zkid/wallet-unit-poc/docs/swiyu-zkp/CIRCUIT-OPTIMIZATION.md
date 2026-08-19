# Circuit optimization study

Measured on 2026-08-17 with Circom 2.2.3, `--O2`, and the `secq256r1`
field. The baseline is tag `swiyu-zkp-baseline-v1` (`edd16d4`). Artifact
bytes are the exact uncompressed R1CS file sizes.

## Results

| Optimization | Scope | Baseline | Optimized | Change |
|---|---|---:|---:|---:|
| Shared ECDSA scalar decomposition | relation-preserving, reusable | 12,892 constraints / 2,560,072 B | 11,592 / 2,300,512 B | -10.1% / -10.1% |
| Compact credential envelope | age/status issuer profile | 6,461,360 constraints / 1,389,199,932 B | 3,727,383 / 831,970,724 B | -42.3% / -40.1% |
| Ternary status tree core | reusable status design | 1,136,267 constraints / 280,458,936 B | 768,607 / 189,422,760 B | -32.4% / -32.5% |

The compact circuit accepts a 256-byte base64url protected header and a
600-byte base64url payload. Together with the separator, the signed input and
SHA-256 padding fit in 896 bytes (14 compression blocks). The checked fixture
uses 246 header bytes, 555 payload bytes, and 802 signed bytes. The existing
2k profile remains available for larger credentials.

The ternary tree uses 11 levels and has 177,147 slots, compared with 131,072
slots for the depth-17 binary tree. Each versioned ternary internal node hashes
three children using standard SHA-256. Its 21-byte domain makes the complete
119-byte preimage fit in exactly two SHA-256 blocks. Eleven ternary levels
therefore need 22 internal compression blocks; seventeen binary levels need
34. The leaf and snapshot commitments remain SHA-256.

## What changed

### Shared scalar decomposition

`ECDSA` multiplies both the public key and the P-256 generator by the same
`s^-1` scalar. Previously each multiplication instantiated `K_add`, decomposing
and range-checking that scalar twice. `Secp256r1MulBits` now accepts already
constrained bits, while `Secp256r1Mul` remains as a compatibility wrapper.

This optimization is predicate-independent and applies to both issuer and
holder signature verification in the swiyu relation.

### Compact issuer profile

The dominant full-circuit cost scales with maximum input dimensions, not with
the age comparison. A large payload envelope is scanned repeatedly by the
base64 decoder, JSON structure checks, field selectors, uniqueness checks, and
the issuer SHA-256 circuit. The separate
`swiyu_age18_status_compact` entry point tightens those compile-time bounds
without changing the proof statements inside the relation.

This is a profile optimization: another predicate can reuse it whenever its
credential schema fits the same envelope. It is not a drop-in artifact for
issuers that need the 2k profile's larger payload capacity.

### Ternary status authentication

`SwiyuTernaryStatusMerkle` derives constrained base-3 path digits from the
private status index and authenticates all three possible child positions.
Sibling ordering, the valid-status requirement, list bounds, epoch, and
snapshot binding are enforced in circuit. The design has a distinct
`swiyu-status-node3-v1` domain, so binary and ternary roots cannot be confused.

The ternary tree is reusable by age, residency, licence, membership, or any
other predicate that consumes the same status-list profile. Issuers and wallets
must generate the versioned ternary tree and path; this changes the status
commitment format rather than merely recompiling an old binary root.

## zk.golf techniques evaluated

The work follows [zk.golf](https://zk.golf/)'s useful discipline: preserve the statement when
claiming equivalence, specialize around known invariants, and measure both
constraints and serialized artifacts.

- Reusing the scalar decomposition is directly analogous to sharing reductions
  or canonicality work across repeated elliptic-curve operations.
- Tight compile-time envelopes specialize the circuit around protocol-level
  invariants, so inactive capacity is never allocated.
- A fixed-block SHA specialization using known padding and zero words was
  implemented and measured. It removed 199 constraints from the dense status
  benchmark but increased the R1CS by 373,784 bytes, so it was rejected. R1CS
  byte size, not constraint count alone, is the target.
- RSA addition chains and secp256k1 GLV decompositions do not transfer directly:
  this circuit uses P-256 ECDSA and SHA-256. Their broader ideas—fixed-base
  tables, fused curve operations, shared range checks, grouped carries, and
  constant-aware scheduling—remain applicable to a deeper P-256 arithmetic
  pass.

## Next optimization lanes

### Reusable across predicates

1. Implement a windowed fixed-base multiplier for `s^-1 G`. The generator is
   constant, so precomputed points can replace much of the generic
   variable-base double-and-add path.
2. Fuse adjacent P-256 additions and share modular-reduction/carry checks.
   This is the closest P-256 analogue to the strongest zk.golf EC entries.
3. Make the credential envelope an explicit family of versioned profiles
   selected from observed issuer distributions instead of one worst-case size.
4. Evaluate a field-native, audit-ready status hash in a new commitment version.
   It can be substantially smaller than SHA-256 but requires ecosystem-wide
   commitment migration and cryptographic review.
5. Separate credential-authenticity proof preparation from small predicate
   proofs. The measured Prepare/Show experiment now implements this with
   constrained shared Spartan rows; see
   [PREPARE-SHOW-BENCHMARK.md](PREPARE-SHOW-BENCHMARK.md).
6. If verifier-key download is the primary target, benchmark another proving
   system. The current Spartan2 serialization embeds the large relation in both
   key artifacts; circuit improvements reduce both, but a succinct-verifier-key
   system changes the asymptotic result.

### Specific to age verification

1. Define a canonical age-credential JSON layout and replace general JSON key
   search/uniqueness machinery with fixed-position, fully constrained parsing.
   This gives the largest likely age-specific reduction, at the cost of a
   narrower issuer format.
2. Define an age-only disclosure encoding with a fixed birthdate position and
   fixed salt policy. The current generic SD-JWT disclosure parser handles more
   shapes than this predicate needs.
3. Compile issuer-specific status depth or ternary depth from the maximum list
   size when a universal 177k-entry profile is unnecessary.

These lanes can be benchmarked independently. Generic arithmetic and status
work stays usable by every predicate; age-layout changes remain isolated in a
separate circuit/profile identifier.

## Reproduction

From `wallet-unit-poc/circom`:

```sh
npm run compile:ecdsa
npm run compile:swiyu:compact
npm run compile:status:binary-core
npm run compile:status:ternary-core
npm test -- --grep "ternary status Merkle"
```

Machine-readable measurements are in
`docs/swiyu-zkp/circuit-optimization-results.json`.

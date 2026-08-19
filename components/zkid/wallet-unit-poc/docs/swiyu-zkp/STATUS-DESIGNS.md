# Prototype B status-design comparison

Prototype B asks a narrow question: what is the smallest status-privacy layer
that can sit on the existing swiyu SD-JWT and Token Status List flow? The answer
implemented by the fixed proof profile is the **dense fixed-index overlay**.
The other four designs below are executable comparison harnesses, not
production integrations. A same-Spartan status-only benchmark proves the
selected dense relation and the slide's depth-64 sparse alternative; LeanIMT+
and TS13 remain lookup/issuance-change experiments and are not claimed ZK
proofs.

## Decision

| Design | Executable here | Current profile | Issuance change | Status-publisher change | Presentation-time lookup |
| --- | --- | --- | --- | --- | --- |
| Dense fixed-index SHA tree | yes | selected and circuit-bound | none | derive an authenticated root from the existing verified `statuslist+jwt` | none |
| Ternary fixed-index SHA tree | yes | optimized comparison | none | derive a versioned ternary root from the existing verified `statuslist+jwt` | none |
| Depth-64 sparse revoked set | yes | comparison only | none if the signed private TSL index is reused as the identifier | publish and authenticate a sparse root | none after wallet caching |
| zkID LeanIMT+ revoked set | yes | comparison only | none if the signed private TSL index is reused as the identifier | publish and authenticate a LeanIMT+ root/set | none after wallet caching |
| EUDI TS13-style adjacent pairs | yes | comparison only | **required:** bind a hidden unique uint64 identifier into the credential | publish signed neighboring revoked-ID pairs each epoch | none after wallet caching the relevant pair |

The selected overlay is the only candidate that preserves both current
issuance and the current signed two-bit list. After credential preparation, the
wallet's explicit status-provisioning helper verifies and expands a locally
fetched signed list, builds the fixed tree, and selects the private witness at
the index already authenticated in the credential. During show there is no
issuer or registry request. Independently, the verifier sidecar derives the
matching authoritative snapshot at startup from a bounded local signed JWT and
its provisioned issuer key. The presentation-time HTTP path receives only the
opaque snapshot ID/commitment and never the credential-specific URI or index.
The verifier operator necessarily knows the configured signed-list subject and
therefore the allowed list cohort.

This is intentionally a one-list policy. Hiding which arbitrary list a
credential belongs to would require private discovery or a larger aggregated
registry and is not solved by this prototype.

## Executable constructions

### Selected dense fixed-index tree

`FixedIndexStatusTree.buildSwiyuProfile` commits every exact two-bit Token
Status List entry at its signed index and pads to the profile's fixed depth 17.
Leaves, padding leaves, internal nodes, and the epoch/entry-count snapshot are
SHA-256 domain-separated. An update structurally shares the untouched tree and
rehashes only 17 ancestors. The circuit proves status value `0`; values `1`,
`2`, and `3` are distinct and fail the profile rather than being collapsed to
a boolean.

This tree is an overlay, not a new issuer format. Snapshot authority still
comes from verifying the issuer's ES256 `statuslist+jwt`, its time bounds,
`bits == 2`, issuer/subject binding, and policy provenance before deriving the
tree. The production sidecar configuration therefore names local signed JWT
files plus exact issuer/kid/subject expectations; it does not accept raw roots,
commitments, epochs, or freshness values authored by an operator.

### Ternary fixed-index tree

`TernaryFixedIndexStatusTree` and `SwiyuTernaryStatusMerkle` preserve the dense
fixed-index model while grouping three children per internal node. Eleven
levels cover 177,147 entries. The short `swiyu-status-node3-v1` domain and
three child hashes form a 119-byte SHA-256 preimage, so each level needs two
compression blocks. The measured core is 768,607 constraints and 189,422,760
R1CS bytes, 32% below the equivalent depth-17 binary core while offering more
capacity. This is a versioned root format and is not mixed with the selected
v0 binary snapshot.

### Sparse revoked set

`SparseStatusTree` is a depth-64 SHA-256 tree keyed by an unsigned 64-bit
identifier. The canonical empty leaf means **valid/not revoked**; a populated
leaf commits the identifier and value `revoked`. A witness therefore supports
both revoked membership and valid non-membership. Updating one identifier
touches one leaf and exactly 64 ancestors, independent of issued or revoked-set
size. The snapshot additionally commits the epoch.

The harness does not sign or distribute roots. A real deployment must
authenticate a fresh root and define rollback/fork handling. Default-valid
semantics are safe only relative to that authenticated current root. A root
alone is also insufficient to construct a witness: the wallet must prefetch
the relevant nodes or public revoked set before presentation.

### zkID LeanIMT+

`LeanImtPlusTree` follows the repository's
`revocation/LeanIMTPlus-Membership-NonMembership-Proofs.md` model:

- physical slot zero is the `{ value: 0, nextValue: first-or-zero }` sentinel;
- active leaves link sorted values through `nextValue`;
- insertion appends a new physical leaf and rewires its predecessor;
- removal repairs the link and leaves an authenticated `{0, 0}` tombstone;
- tombstone slots are never reused;
- an AVL index finds predecessors in `O(log n)`;
- Merkle updates touch only affected paths; and
- an unpaired odd node is promoted unchanged, with no zero hash.

Leaves and internal nodes have separate SHA-256 domains, and the snapshot
commits epoch and physical leaf count. Membership authenticates an exact active
leaf. Non-membership authenticates the predecessor and checks
`low < query < next`, or `next == 0` for the tail. A zero-valued low leaf is
accepted only at physical slot zero, preventing tombstone replay.

An empty set is represented by the sentinel `{0, 0}`. This is a small explicit
extension of the local write-up, which introduces the sentinel together with
the first insertion; it gives the empty registry a useful non-membership root
without changing later semantics.

### EUDI TS13-style signed adjacent pairs

`Ts13AdjacentPairRegistry` signs consecutive revoked-ID endpoints with P-256.
The exact signed message is:

```text
uint64_le(left) || uint64_le(right) || uint32_le(epoch)
```

ECDSA hashes that 20-byte message with SHA-256. Signatures are the 64-byte raw
ES256/JOSE form `r || s`, not DER. A valid witness verifies the revoker key and
proves the credential's hidden identifier satisfies `left < id < right`.

The TS13 draft example signs only pairs inside a nonempty revoked list, which
does not cover identifiers below the first or above the last entry. This
harness reserves `0` and `2^64 - 1` as boundary sentinels and signs the outer
intervals too. Issuable identifiers are therefore exactly `1..2^64-2`. An
empty revoked set has one signed sentinel pair.

This option is constant-size at presentation, but it is not a drop-in overlay:
the hidden identifier must be issuer-bound in the credential, and each epoch's
status publisher must issue the signed pair data. Because the epoch is signed,
advancing an epoch re-signs all current adjacent pairs in this harness; a
status change cannot reuse an older pair witness. Fetching only the relevant
pair directly from a registry can reveal the identifier's interval to that
registry, so the no-presentation-lookup goal requires prefetch, batch
distribution, or a privacy-preserving retrieval layer.

## Adversarial coverage

The focused tests cover:

- sparse membership/non-membership, full uint64 boundaries, canonical empty
  roots, path updates, and tampered path/identifier/status/root/epoch;
- LeanIMT+ unsorted insertions, every predecessor interval, odd promotion,
  removals, authenticated tombstone replay, no slot reuse, duplicate/sentinel
  rejection, and tampered mode/order/path/root/epoch;
- the published TS13 little-endian example, real raw P-256 signatures, empty,
  first, middle, and last intervals, reserved boundaries, revoked IDs, epoch
  rotation, restore/revoke behavior, and tampered signer/signature/pair/id; and
- the selected dense tree's exact four two-bit values, depth-17 padding,
  persistent updates, stale witnesses, and byte-identical rebuilds; and
- the ternary tree's three child positions, constrained base-3 path, capacity
  bounds, modified paths, and persistent updates.

The five executable candidates are exported from the isolated
`openac-sdk/status-designs` package subpath; they are not mixed into the normal
credential or presentation API.

## Same-Spartan status proof comparison

The slide explicitly asks for a real sparse-proof size, so the repository also
contains two isolated Circom relations and a closed-profile Spartan runner:

- `swiyu_status_dense_17_bench` proves exact two-bit `VALID` membership in the
  selected fixed depth-17 snapshot;
- `swiyu_status_sparse_64_bench` proves canonical-empty non-membership in the
  depth-64 sparse revoked set.

These are status-component measurements, not duplicate SD-JWT circuits. Each
component pins a public SHA-256 handle over a private query, a private 32-byte
salt, and a design tag. That benchmark-only composition anchor prevents the
prover from choosing an arbitrary valid entry when the credential circuit is
omitted. The final monolithic swiyu relation directly shares the issuer-signed
private status index with the status relation and therefore exposes no such
handle.

Both profiles use the same Spartan2 implementation, six 32-byte public values,
SHA-256 domains byte-identical to the TypeScript constructions, and the same
256-issued/4-revoked deterministic circuit fixture (revoked indices 3, 64,
191, and 255; valid query 42). This fixture is deliberately distinct from the
65,536-issued/1,024-revoked data-structure benchmark below. Results are one
local arm64 macOS 26.4 release run on 2026-07-15:

| status component | constraints | witness bytes / generation | setup | prove | verify | PK / VK bytes | proof bytes | peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| dense depth 17 | 1,197,925 | 37,879,916 / ~3.2 s | 5.016 s | 1.858 s | 0.186 s | 352,474,314 / 352,474,282 | 112,095 | 3,438,018,560 |
| sparse depth 64 | 4,083,606 | 129,137,580 / 7.964 s | 17.733 s | 5.932 s | 0.361 s | 1,130,247,762 / 1,130,247,730 | 180,175 | 6,829,670,400 |

Both real proofs verified, and each failed against a changed public root and a
changed public query handle. The full measurements are committed in
[`status-proof-benchmark-results.json`](status-proof-benchmark-results.json).
Run `wallet-unit-poc/scripts/benchmark-status-proofs.sh` to reproduce them;
candidate R1CS, witnesses, and keys are generated artifacts and are not staged.

These component proof sizes are neither additive to nor substitutes for the
315,967-byte full age/status proof. They answer the design comparison: under
the same SHA/Spartan assumptions, sparse non-membership costs about 3.4x the
constraints, 1.6x the proof bytes, and 2x the peak memory of the selected dense
overlay. Even the dense component reached 3.44 GB RSS, so this run is a
measured mobile-deployment **no-go**, not a mobile claim. The prototype passes
privacy, offline-presentation, and Generic-Verifier interface goals on a
desktop research path; mobile practicality remains future proof-system/circuit
work rather than an unfinished swiyu integration seam.

## Reproducible benchmark

Run:

```sh
cd wallet-unit-poc/openac-sdk
npm run benchmark:status-designs
```

The deterministic fixture models one revoked identifier per 64 issued slots
(1.5625%). It uses 5 samples for build and status update, 25 for witness
generation, and reports p50/p95 wall-clock milliseconds. The queried identifier
is a non-revoked interior value. Dense measurements always build the actual
fixed depth-17 profile; sparse uses depth 64; LeanIMT+ stores only revoked
values plus sentinel/tombstones; the TS13 update advances the epoch and signs
the complete new pair set.

Results below are from the local run on 2026-07-15, Node v25.6.1, arm64 macOS
26.4. They are feasibility measurements from one process, not mobile claims or
cross-device performance guarantees.

| design | issued | revoked | build p50/p95 ms | update p50/p95 ms | witness p50/p95 ms | witness JSON bytes | verifier/circuit input implication |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| selected dense fixed-index | 256 | 4 | 1698.808/1718.725 | 0.194/0.313 | 0.002/0.003 | 1320 | 17 SHA-256 path siblings + two-bit status |
| sparse revoked set | 256 | 4 | 3.196/3.743 | 0.645/0.689 | 0.018/0.028 | 4457 | 64 SHA-256 path siblings + membership bit |
| zkID LeanIMT+ | 256 | 4 | 0.163/0.196 | 0.071/0.135 | 0.009/0.031 | 515 | 3 SHA-256 path siblings + predecessor ordering |
| EUDI TS13 adjacent pair | 256 | 4 | 1.531/1.786 | 1.749/1.787 | 0.001/0.009 | 243 | one P-256 signature + two uint64 comparisons |
| selected dense fixed-index | 4096 | 64 | 1703.713/1713.562 | 0.187/0.203 | 0.002/0.002 | 1322 | 17 SHA-256 path siblings + two-bit status |
| sparse revoked set | 4096 | 64 | 41.671/41.804 | 0.644/0.650 | 0.014/0.023 | 4458 | 64 SHA-256 path siblings + membership bit |
| zkID LeanIMT+ | 4096 | 64 | 3.548/3.668 | 0.102/0.136 | 0.009/0.010 | 893 | 7 SHA-256 path siblings + predecessor ordering |
| EUDI TS13 adjacent pair | 4096 | 64 | 18.826/19.219 | 17.762/18.950 | 0.001/0.001 | 247 | one P-256 signature + two uint64 comparisons |
| selected dense fixed-index | 65536 | 1024 | 1717.449/1727.521 | 0.176/0.196 | 0.002/0.004 | 1324 | 17 SHA-256 path siblings + two-bit status |
| sparse revoked set | 65536 | 1024 | 656.145/656.520 | 0.630/0.635 | 0.013/0.014 | 4459 | 64 SHA-256 path siblings + membership bit |
| zkID LeanIMT+ | 65536 | 1024 | 75.890/76.784 | 0.139/0.165 | 0.009/0.010 | 1271 | 11 SHA-256 path siblings + predecessor ordering |
| EUDI TS13 adjacent pair | 65536 | 1024 | 269.421/272.624 | 268.539/276.411 | 0.001/0.001 | 250 | one P-256 signature + two uint64 comparisons |

“Witness JSON bytes” is the UTF-8 size of the harness's explicit witness
object. It is useful for comparing input shape but is not a compressed wire
encoding and **not a ZK proof size**. Likewise, the last column states the
cryptographic work a future circuit would receive; no constraint counts or
proof sizes are asserted for LeanIMT+ or TS13. The status-only dense/sparse
proof table above is the same-system cryptographic comparison. Only the
selected dense design is included in the final swiyu proof, whose actual proof
and artifact measurements are recorded separately in the completion evidence.

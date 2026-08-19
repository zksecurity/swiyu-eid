# swiyu ZK prototypes A + B

This directory specifies one deliberately narrow, opt-in extension to the
existing swiyu/OpenAC path. It does not replace issuance, SD-JWT, OID4VP,
DCQL, or the normal verifier.

The fixed profile `swiyu-age18-status-2k-v0`, backed by circuit artifact
`swiyu_age18_status_2k`, proves in one fresh presentation proof that:

1. a trusted P-256 issuer signed a Swiss-profile SD-JWT VC;
2. its holder key signed the exact verifier session challenge;
3. an authenticated, selectively disclosed `birthdate` is on or before the
   verifier's age-18 cutoff;
4. the credential is currently valid; and
5. its private status index has value `VALID` in the policy-pinned,
   authoritative two-bit Token Status List snapshot.

The proof reveals the boolean result and verifier-selected public context. The
presentation proof/envelope does not reveal birthdate, disclosure, holder key,
the credential-specific status URI or index, Merkle branch, or raw status-list
root. The verifier operator does know the policy-provisioned issuer/list cohort;
private discovery across arbitrary lists is outside v0.

Measured circuit-size optimizations and reusable/profile-specific follow-up
lanes are documented in [CIRCUIT-OPTIMIZATION.md](./CIRCUIT-OPTIMIZATION.md).

## Smallest integration surface

- Issuer: unchanged. It continues to issue ordinary ES256 SD-JWT VCs and
  `statuslist+jwt` Token Status Lists.
- Wallet: a new prepare/provision/show API is opt-in. Prepare validates and
  caches the credential; provision verifies a locally fetched signed status
  list and selects the credential's authenticated private index; show creates
  one complete, challenge-bound proof without network I/O. The working local
  prototype uses the path-backed native Rust backend so its multi-GB key is
  never copied through JavaScript memory.
- Verifier: one optional DCQL extension, `x_swiyu_zkp`, routes only the fixed
  profile to a local verification sidecar. Ordinary presentations are
  unchanged.
- Status: the selected dense fixed-index SHA-256 Merkle overlay is derived
  from a verified two-bit Token Status List. The issuer format and status
  endpoint are unchanged.

This one-proof design is intentional. The reviewed OpenAC Prepare/Show
protocol did not safely link its two independent proofs. Reusing that split
would make the prototype smaller in lines of code but not sound. The current
`prepare()` is therefore input validation/cache preparation, not a claim of a
cryptographic precomputation that makes `show()` constant-time.

## Narrow interoperability contract

The v0 profile accepts only credentials with:

- protected `alg: ES256`, `typ: dc+sd-jwt`, a unique `kid`, and
  `profile_version: swiss-profile-vc:1.0.0`;
- unique compact-JSON fields in the exact issuer-compatible subset;
- signed `iss`, `vct`, `nbf`, `exp`, `cnf.jwk`, `status.status_list`,
  `_sd_alg: sha-256`, and a top-level `_sd` digest for exactly one
  `birthdate` disclosure;
- a P-256 holder key and issuer key that are canonical, non-infinity, and on
  curve inside the relation;
- a two-bit status token. Other swiyu-supported status widths require a
  different circuit profile.

The generic issuer can omit `nbf`/`exp` for some offers; those credentials are
outside this fixed profile. An issuer deployment opting into the profile must
configure bounded validity so both claims are present. The executable E2E
credential is synthetic, but its protected header, claim layout, status
reference, P-256 keys, and 99-byte `did:tdw` key identifier mirror the shapes
exercised by the local swiyu issuer tests. It is not represented as a captured
production credential.

The verifier policy selects one opaque current snapshot ID before the wallet
presents. That means v0 is suitable when a verification policy is pinned to a
known issuer/list cohort. It does not solve private discovery among arbitrary
status-list URIs.

## Explicit non-goals

- changing the swiyu issuer or one-core credential model;
- arbitrary claims, predicates, JSON, algorithms, or status widths;
- verifier-scoped nullifiers or one-person/one-signup enforcement;
- hiding membership in a status-list cohort (the public snapshot commitment
  is shared by that cohort for one epoch);
- claiming mobile deployment: the same-Spartan component benchmark is already
  a measured no-go at 3.44 GB RSS before the full credential relation.

## Measured feasibility boundary

The final relation is a working **desktop research prototype**, not a mobile
deployment claim. It has 6,461,359 nonlinear constraints. On the local arm64
macOS run, witness generation took 8.14 s, native proving 12.84 s, and native
verification 8.82 s. The proof is 315,967 bytes, but the Spartan proving and
verifying keys are each about 1.60 GB; proving reached 7.50 GB maximum resident
memory and verification reached 4.02 GB.

The browser-targeted WASM module was compiled and exercised under Node's
WebAssembly runtime; it trapped while handling the 1.60 GB key. No committed
in-browser execution harness was used, so a browser/mobile deployment no-go is
an engineering inference from that failure and the measured 7.50 GB native
peak, not a directly measured browser result. The package does not bundle those
keys or claim this fixed relation works in a browser/mobile runtime. The working
SDK integration is the isolated Node/native backend with local-file key
references. Reducing circuit/key/memory cost is follow-on engineering, not
hidden behind a mock or a smaller substitute relation.

Prototype B also has real same-Spartan status-component measurements. The
selected dense component produced a 112,095-byte proof at 3.44 GB peak RSS;
the depth-64 sparse alternative produced a 180,175-byte proof at 6.83 GB peak
RSS. This makes the design choice evidence-based and the mobile no-go
explicit. See [STATUS-DESIGNS.md](STATUS-DESIGNS.md).

See [PROFILE.md](PROFILE.md) for the exact statement and
[REQUIREMENTS-MATRIX.md](REQUIREMENTS-MATRIX.md) for the slide-by-slide result,
[ACCEPTANCE.md](ACCEPTANCE.md) for the executable completion gates, and
[PREPARE-SHOW-BENCHMARK.md](PREPARE-SHOW-BENCHMARK.md) for the measured
zkID-style circuit split.

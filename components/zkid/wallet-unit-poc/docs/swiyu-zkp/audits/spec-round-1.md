# Specification audit — round 1

Date: 2026-07-15

Gate at audit time: **FAIL**. No P0 findings; two P1 findings required
implementation changes before round 2.

## Findings

### P1 — Prototype B lacked comparable proof artifacts

The status comparison measured update time and serialized witness objects for
all candidates, but only the selected dense design participated in a real ZK
proof. Those JSON byte counts are not proof sizes, and the final relation's
7.50 GB prover RSS, 4.02 GB verifier RSS, and WASM trap do not satisfy the
slide's aspirational mobile outcome.

Disposition: **fix in progress**. Add an isolated, same-Spartan status-only
dense-versus-sparse benchmark with real R1CS, witnesses, setup, proofs,
verification, tampered-public-root rejection, and artifact measurements. Keep
LeanIMT+ as the presentation-lookup experiment and TS13 as the issuance-change
experiment requested by the slide. Record mobile deployment as a measured
no-go rather than borrowing results from the old OpenAC relation.

### P1 — signed status provisioning was not wired

The resolver correctly verified `statuslist+jwt`, but `prepare()` only parsed
the credential, `show()` accepted already-derived private status material, and
the production sidecar configuration accepted already-derived authoritative
snapshot fields. The documentation therefore described a background ingestion
path that did not yet have reproducible wiring.

Disposition: **fix in progress**. Wire the resolver into a wallet provisioning
helper and into sidecar startup from bounded local signed-JWT files and pinned
issuer keys. Presentation verification remains network-free.

### P2 — interoperability fixture wording was too broad

The E2E fixture uses a real 99-byte `did:tdw` key-identifier shape and the
issuer's protected-header/status layout, but the credential values and signing
key are synthetic. The generic issuer can also omit `nbf`/`exp`, while the
fixed profile requires both.

Disposition: **resolved**. Documentation now calls the credential synthetic,
lists the exact observed shapes it mirrors, and states that only issuer offers
with bounded `nbf`/`exp` are eligible for this opt-in profile.

### P2 — public OpenAPI omitted the opt-in extension

The Java DTO exposed `x_swiyu_zkp`, but `openapi.yaml` did not describe it.

Disposition: **resolved**. Added the exact fixed policy schema and credential
property to the committed OpenAPI contract.

### P2 — policy time could age between creation and receipt

Java validated the frozen proof time only when creating the management
session. A long-lived request could therefore evaluate snapshot freshness at
an old time.

Disposition: **resolved**. Java now enforces the same five-minute bound at
presentation receipt before contacting the sidecar; a focused regression test
covers the rejection. The signed time remains deterministic circuit input.

### P3 — nullifier/unicity is out of scope

Challenge binding and the verifier's atomic session transition prevent replay
of one request. They do not prevent the same credential from proving again in
a new session. The fixed age/status profile intentionally has no nullifier and
does not claim one-credential/one-signup semantics.

Disposition: **accepted explicit non-goal**. Keep this distinct from replay
prevention in all completion claims.

## Checks that passed

- Profile, circuit, and envelope identifiers agree across Circom, Rust,
  TypeScript, sidecar, and Java.
- The ten public values have one consistent order and are independently
  reconstructed by the verifier.
- The structured proof envelope exposes no birthdate, disclosure, holder key,
  status URI, index, Merkle branch, or raw root.

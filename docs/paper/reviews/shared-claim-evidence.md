# Shared age-25 claim and comparison evidence

## What was built

The project authored an OpenAC Circom circuit, `swiyu_age25_jwt`, to match the bounded statement implemented by eid-privacy `d10_swiyu_jwt`. This is stronger than merely adapting two unrelated providers to one interface.

The common semantic contract is `swiyu.shared.age25-holder-challenge.v0`, statement digest `838df32b57b9ca0aadb533270bbc096cd67b7f85c3ead250cacf765742d3ddc5`. It requires:

- issuer authentication under a verifier-supplied issuer key;
- an authenticated hidden `birth_date`;
- `now_date >= birth_date + 25 * 10000` using the d10 YYYYMMDD rule;
- holder P-256 authorization over the verifier challenge;
- release of acceptance plus an opaque proof, with branch identity hidden.

It deliberately excludes status/revocation, `nbf`/`exp`, and metadata-hash obligations. Both EPFL and OpenAC support manifests register this exact claim ID and statement digest.

Sources:

- `integration/semantics/claims/age25-holder-challenge.json`
- `integration/providers/epfl/support.json`
- `integration/providers/openac/support.json`

## Exact OpenAC circuit alignment

`components/zkid/wallet-unit-poc/circom/circuits/swiyu-age25-jwt.circom` is a new, currently untracked OpenAC fork of the age-18/status relation. It retains issuer ES256 verification, strict/canonical JWT parsing, SD-JWT `_sd` membership for a hidden birth-date disclosure, `cnf.jwk` holder-key binding, and a P-256 holder signature over public `challengeHash`. It replaces the age-18 cutoff with `YyyymmddAgeAtLeast(25)` and removes status/revocation, validity (`nbf`/`exp`), metadata hashes, and the prior session-context digest. Public inputs are issuer key coordinates, `nowDate`, and `challengeHash`.

Supporting authored components and registration:

- `components/zkid/wallet-unit-poc/circom/circuits/swiyu/yyyymmdd-age.circom`
- `components/zkid/wallet-unit-poc/circom/circuits/swiyu/disclosure.circom`
- `components/zkid/wallet-unit-poc/circom/circuits.json`
- `components/zkid/wallet-unit-poc/circom/package.json` (`compile:swiyu:age25`)
- `integration/providers/openac/age25-jwt.md`

## Shared comparison modes

`integration/harness/transcript_shared.py` loads both implementations only after support/digest validation and independent fixture classification. It runs two hidden-birth-date variants per backend through the same four selected Swiyu HTTP boundaries. It produces:

- two within-backend clean A/B reports (one pair per backend);
- one cross-implementation clean report (four eligible EPFL/OpenAC pairs when both variants share the same public class);
- when injections are enabled, two within-backend injected reports and one cross-implementation injected report over another four cross pairs.

`integration/harness/transcript_cross.py` compares only sessions from different implementations with equal claim classification. It exempts implementation identity: profile, circuit ID, EPFL issuer coordinates, proof length, content length, and body size. Extra siblings, hidden markers, and unknown identifiers remain observable.

The fixture-only regression in `integration/harness/tests/test_transcript_shared.py` executes eight accepted sessions (four clean, four injected), requires both clean backend reports and the cross report to be clean, requires both injected backend reports and the injected cross report to contain findings, and requires at least four equivalent clean cross-implementation pairs. Fixture-only output is explicitly marked `evidence_usable: false`.

Operational sources:

- `integration/harness/transcript_shared.py`
- `integration/harness/transcript_cross.py`
- `integration/harness/TRANSCRIPT-PROVIDERS.md`
- `docs/platform/transcript-privacy-design.md`

## Native/synthetic boundary

In the default live Java shared-claim path, EPFL generates native Noir/UltraHonk proofs. OpenAC does **not** generate a Spartan proof: witness WASM and Spartan keys for `swiyu_age25_jwt` are not packaged, and the normal provider reports the profile unsupported. The shared harness instead uses `openac-age25-synthetic-envelope`, a session-bound SHA-256-expanded proof field with the real OpenAC wire shape; its sidecar recomputes the binding. This validates claim registration, OID4VP routing, envelope handling, observer normalization, and cross-implementation comparison, but supplies no native OpenAC cryptographic or performance evidence.

Relevant files:

- `integration/providers/openac/age25_transcript_wallet.py`
- `integration/providers/openac/transcript-sidecar-age25.py`
- `integration/providers/openac/transcript-fixture-age25.py`
- `integration/providers/openac/manifest.json`

No retained live shared-claim `report.json` was found in the repository or current `/tmp`; `/tmp/swiyu-shared-age25-live` is absent. Therefore the paper can affirm the implemented aligned circuit/claim and executed regression modes, but should attach a report before asserting exact live shared-run counts beyond the retained fixture-only test contract. Existing September 15 EPFL reports are native single-backend evidence under the equivalent EPFL-specific claim, not a retained native-vs-native shared-claim result.

## Safe affirmative claim

The project aligned an authored OpenAC Circom statement with eid-privacy d10 under one pinned semantic claim and implemented same-flow, within-backend, and cross-backend transcript comparisons. The retained shared-mode regression demonstrates the comparison machinery and injected-control sensitivity. The executed shared Java mode used a native EPFL proof and a session-bound synthetic OpenAC envelope; native OpenAC age-25 proving remains future work until its artifacts are packaged.

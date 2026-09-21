# OpenAC `swiyu_age25_jwt`

Circom presentation of the shared claim `swiyu.shared.age25-holder-challenge.v0`.

The circuit is an OpenAC fork of the age-18 status relation with the extra OpenAC-only obligations removed so the statement matches EPFL d10:

| Obligation | In this circuit |
|---|---|
| Issuer ES256 | yes |
| Authenticated `birth_date` disclosure | yes |
| `nowDate >= birth + 25 * 10000` (YYYYMMDD) | yes |
| Holder P-256 over the public challenge | yes |
| Status / revocation | no |
| nbf / exp | no |
| Metadata hashes | no |

Source:

- `components/zkid/wallet-unit-poc/circom/circuits/swiyu-age25-jwt.circom`
- `components/zkid/wallet-unit-poc/circom/circuits/swiyu/yyyymmdd-age.circom`
- `components/zkid/wallet-unit-poc/circom/circuits/swiyu/disclosure.circom` (`SwiyuBirthDateDisclosure`)

Compile (heavy; not required for the shared oracle suite):

```bash
cd components/zkid/wallet-unit-poc/circom
yarn compile:swiyu:age25
```

`present` / `verify` on `provider.mjs` stay `unsupported_profile` until witness WASM and Spartan keys exist.

The shared-claim OID4VP campaign still drives this profile through the Java harness. [age25_transcript_wallet.py](age25_transcript_wallet.py) emits a `swiyu-zkp-proof-v0` envelope whose `proof` bytes are a SHA-256 expansion of the Java session (`nonce`, `client_id`, `response_uri`, `state`, `query_id`, `profile`, `circuit_id`, `now_date`). [transcript-sidecar-age25.py](transcript-sidecar-age25.py) recomputes that binding. Label: `openac-age25-synthetic-envelope`. Not a Spartan proof.

[transcript-fixture-age25.py](transcript-fixture-age25.py) emits two adult variants that reuse the EPFL synthetic credentials. See [the provider guide](../../harness/TRANSCRIPT-PROVIDERS.md#shared-claim-two-circuits).

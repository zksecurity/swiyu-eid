# Profiles

| Profile | Circuit IDs | State |
|---|---|---|
| `swiyu-age18-status-2k-v0` | `swiyu_age18_status_2k` | Wired to the optional Java verifier sidecar |
| `swiyu.age-over-18.packed-status-chunk.v2` | `swiyu_age18_prepare_compact`, `swiyu_age18_show_packed_chunk_v2` | Implemented and benchmarked in zkID |
| `swiyu.residence-eligibility.combined-disclosure.v1` | `swiyu_residence_combined_prepare_compact`, `swiyu_residence_show_packed_chunk_v2` | Implemented and benchmarked in zkID |
| `swiyu.age-over-18.scoped-nullifier.v1` | `swiyu_nullifier_age18_prepare`, `swiyu_nullifier_age18_show_packed_chunk_v2` | Implemented, benchmarked, and paired with an atomic registry reference |

The canton and professional-license circuits remain retained experiments, not
active target profiles. Profile constants and descriptors are defined in
[`openac-sdk/src/swiyu-zkp`](../../components/zkid/wallet-unit-poc/openac-sdk/src/swiyu-zkp).

# EPFL d10 integration and differential transcript results

The completed laptop run generated four distinct native UltraHonk proofs. The Java verifier accepted all four presentations, with four selected HTTP exchanges captured per presentation. Both pairs were eligible for semantic comparison.

| Case | Accepted | Transcript result |
|---|---:|---|
| Two hidden birth dates satisfying the same claim | 2/2 | Equivalent after declared normalization; no findings |
| Same pair with deliberate extra credential data and hash header | 2/2 | Hidden disclosure and unknown identifier differences detected |

These are injected regression controls, not a discovered vulnerability in upstream EPFL. The run also exposed a harness codec incompatibility, corrected by canonical Base64url proof transport. All other body fields and headers remain subject to comparison.

[Open the HTML report](campaign-report.html). [Machine-readable results](campaign-report.json). [Provider setup and reproduction](../../epfl-provider.md).

The semantic claim is `swiyu.epfl.d10-age25-jwt.v0`, statement digest `b0b44776cd76859535394cf88151e1f81ff3d17585edfc208a06e806319b29a5`. It states issuer authentication, birth-date disclosure binding, the circuit's fixed YYYYMMDD age threshold of 25, and holder authentication over a supplied challenge. The integration derives that challenge from the persisted verifier session and policy. The claim adds no status, expiry, or revocation guarantees.

Each proof was 16,224 bytes. Gzip witness sizes were 311,413–311,448 bytes. Combined witness generation and proving took 14.9–16.3 seconds per presentation; these are four observations, not a statistical benchmark. Witness and prove have no separate measured clocks in this adapter.

Validation: semantic suite 211 passed and harness suite 183 passed before the final codec change; focused codec tests 4 passed and transcript/EPFL-support checks 38 passed afterward. Independent final review is recorded separately when complete.

Scope: native laptop proofs, real Java controller/service paths through a JDK HTTP test adapter, in-memory persistence, and synthetic issuer inputs. This run does not measure Android, full Spring dispatch, TLS, production infrastructure, or timing-channel distributions. The synthetic reference credential and native circuit witness use compatible payloads but different required JWT headers; arbitrary existing Swiyu credentials are not established as compatible. This testing does not audit cryptographic soundness or prove circuit correctness.

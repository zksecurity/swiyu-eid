# Claim-to-source map

| Key | Supports | Does not support |
|---|---|---|
| `oid4vp` | OID4VP 1.0 defines DCQL, `vp_token`, `direct_post`, fresh `nonce`, and verifier/audience and transaction binding requirements. | It does not define this harness, prove transcript privacy, or endorse the `x_swiyu_zkp` extension. |
| `sdjwt` | SD-JWT disclosure construction, holder/key-binding concepts, and privacy/security considerations. | It does not specify SD-JWT VC profiles, Swiyu, ZK proofs, or guarantee unlinkability of an integration. |
| `swiyu` | Official Swiss Confederation Swiyu verifier implementation and the production codebase integrated by the experiment. | Repository existence does not establish security, standards conformance, or coverage of a deployment. |
| `swiyu-issuer` | Official Swiyu issuer implementation, useful for describing the wider open-source ecosystem. | It was not a live production issuer in the bounded experiment and does not support privacy conclusions. |
| `swiyu-wallet` | Official Android wallet implementation, useful only for the full-system context. | Android/UI/wallet network behavior was explicitly outside the observer and was not tested. |
| `openac` | Original OpenAC design, prepare/show construction, zk-Spartan design, claimed security sketch, and its own benchmarks. | It does not report this project's Swiyu profiles, transcript tests, measurements, or EPFL UltraHonk results. Treat the PDF as a 2025 technical report, not a peer-reviewed venue paper unless independently established. |
| `zkid-repo` | Primary OpenAC/zkID source repository and provenance of imported/forked code. | Current repository state does not prove the paper's security claims or that this experiment ran upstream unchanged. |
| `epfl` | Original `eid-privacy/zkp-pocs` repository containing Noir credential circuits, including the source of `d10_swiyu_jwt`. | It does not describe the harness-side fixture variation, OID4VP lifecycle integration, or transcript comparison. The paper must call the tested system an adaptation/vendored circuit run with UltraHonk, not “OpenAC on UltraHonk” or custom Spartan measurements. |
| `metamorphic` | Prior metamorphic-security-testing work uses relations among executions to automate Web security testing and address oracle problems. | It does not claim this exact semantic/release-policy relation or validate this implementation. |
| `declassification` | Declassification literature motivates explicit permitted-release policy and equivalence classes induced by what may be released. | It does not give a ready-made test oracle for OID4VP or establish computational indistinguishability from finite tests. |
| `hyperproperties` | Hyperproperties formalize security properties over sets of traces, supporting the broad relational framing. | It does not imply that a finite pairwise campaign proves a hyperproperty or zero knowledge. |
| `goldwasser1989` | Classical definition/foundation of zero-knowledge interactive proofs. | It does not analyze these circuits, transcripts, Fiat–Shamir/UltraHonk, or Swiyu. Use only for basic ZK background. |

## Claims that must cite project evidence, not literature

- “No natural privacy counterexample was observed” and counts/timings/sizes: cite the paper's archived artifact or local assessment, never OpenAC/EPFL upstream sources.
- Exact result: nine sessions, eight accepted, seven eligible equivalent pairs; one stale-policy rejection after the 300-second bound; zero candidate transcript findings.
- Positive controls: deliberately injected raw/digest releases demonstrate harness sensitivity, but are not native vulnerabilities.
- Observer: four application-level HTTP boundaries only. Excludes Android, TLS/packets, live authorities, timing distributions, and arbitrary process logs.
- Cryptographic qualification: no crypto/circuit audit; finite structural comparisons do not prove zero knowledge or noninterference.
- EPFL qualification: native `nargo`/`bb` UltraHonk over the vendored `d10_swiyu_jwt` circuit, with project-added authenticated holder fixture variation; fixed-header synthetic circuit credential, not arbitrary SD-JWT compatibility.

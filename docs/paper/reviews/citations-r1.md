# Citation audit r1 — REQUIRED EDITS

The external bibliography is now sound and compact (11 entries including the companion artifact). The draft still needs the following citation/attribution edits before it passes.

1. **Cite `artifact` for every empirical cluster.** At minimum add `\cite{artifact}` to: Table 1's caption; the end of each paragraph in “Injected controls and clean comparisons”; the direct-native-verification paragraph; both measurement paragraphs; and the reproducibility/resource-guard paragraph. None of the upstream OpenAC/zkp-pocs references supports this paper's session counts, accepted results, byte sizes, timings, injected controls, stale-policy rejection, nonce/challenge controls, source hashes, or observer exclusions. The abstract may remain citation-free if these claims are cited in the body.

2. **Cite `artifact` for project-specific method facts.** Add it after the four-boundary observer description, provider lifecycle, `x_swiyu_zkp` integration description, classifier/native-verifier division, and normalization/clock exemptions. These are implemented design facts rather than claims supported by OID4VP or prior literature.

3. **Fix EPFL attribution.** The primary source verifies that `eid-privacy/zkp-pocs` contains `d10_swiyu_jwt`, calls it a full Swiyu JWT age proof with issuer and holder binding but no non-revocation, and says its Noir backend uses Barretenberg UltraHonk. It does **not** identify an individual d10 author or establish “EPFL” authorship in the material verified here. Use “the `eid-privacy` d10 circuit” / “eid-privacy-derived provider,” or define “EPFL” explicitly as this paper's provider label without implying authorship. Keep `\cite{epfl}` at the first technical description. The project-added challenge derivation, fixture variation, fixed-header compatibility, and measured proof sizes require `\cite{artifact}` too.

4. **Keep SD-JWT and SD-JWT VC distinct.** RFC 9901 normatively specifies generic SD-JWT; its SD-JWT VC material is illustrative and it does not define the `dc+sd-jwt` credential profile. The first paragraph is defensible if rewritten as “The generic SD-JWT mechanism separates disclosures from issuer-signed digest commitments” with `\cite{sdjwt}`. Attribute Swiyu's concrete use/profile separately to `swiyu`; do not say RFC 9901 standardizes Swiyu's VC profile.

5. **Credit conceptual origins at the claim.** Add `\cite{declassification}` where permitted releases are introduced, `\cite{goldwasser1989}` at the first background use of zero knowledge, and retain `noninterference`, `hyperproperties`, and `metamorphic` in related work. The metamorphic authors must be Bayati Chaleshtari et al., not Mai et al.

6. **OpenAC boundary.** `openac` supports the original design and its own zk-Spartan discussion. The evaluated Swiyu profile, native loader, status relation, and laptop measurements are project artifacts; cite `artifact`, and do not present them as upstream OpenAC results.

After these changes: PASS, provided the companion bundle receives the stable archive/location promised by the submission workflow. The `artifact` record intentionally has no invented DOI or public URL.

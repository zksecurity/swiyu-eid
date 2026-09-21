# Citation audit r2 — PASS

The current draft passes the claim-by-claim citation audit.

- All 11 cited keys exist in `citations/references.bib`; none is unused. The draft contains 17 `artifact` citations covering the implemented method, observer and normalization assumptions, provider behavior, controls, campaign results, measurements, and provenance. Upstream references are no longer made to carry local empirical claims.
- RFC 9901 is limited to the generic SD-JWT mechanism and linkability/privacy considerations. Swiyu's concrete implementation is attributed separately to its official repository. The draft does not conflate RFC 9901 with an SD-JWT VC profile specification.
- OID4VP supports only the surrounding request, presentation, and session-binding statements. The paper labels `x_swiyu_zkp` as an experimental extension and cites the companion artifact for it.
- OpenAC receives credit for the original design; the evaluated Swiyu profile, loader, controls, and measurements resolve to the artifact.
- The source is now called the eid-privacy `d10` circuit, with “EPFL” explicitly introduced as a local provider label. Later uses are therefore unambiguous and make no affiliation or individual-authorship claim. The cited primary repository supports Noir/UltraHonk, issuer and holder binding, and absence of non-revocation for d10. Project adaptations and measurements cite `artifact`.
- Original conceptual credit is present for zero knowledge, noninterference, declassification, hyperproperties, and metamorphic security testing. The metamorphic authorship is correctly Bayati Chaleshtari et al.
- Every quantitative result and negative conclusion is qualified: injected findings are controls, clean runs found no natural counterexample, and finite comparisons do not establish cryptographic unlinkability, soundness, or computational indistinguishability.
- Bibliography metadata and primary URLs are visible under the `plain` style through `note`/`howpublished`. Repository records use `@misc`. The companion artifact is described as accompanying “this working draft,” with no invented DOI or public URL.

No blocking citation edits remain. When the final repository artifact path is fixed, it may be added to the `artifact` entry's `howpublished` field for reader convenience; that is packaging, not a validity blocker.

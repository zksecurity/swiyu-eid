# Revised paper structure

1. Introduction: Swiyu issuer–wallet–verifier flow, OID4VCI/OID4VP, SD-JWT and batch issuance; motivate hidden predicates and integration privacy.
2. From credentials to ZK presentations: OpenAC Prepare/Show, our Swiyu profiles, eid-privacy/Noir, and backend heterogeneity.
3. Generic integration layer: protocol extension, provider lifecycle, reporting, bounded claims, and authored OpenAC age-25 alignment.
4. Differential leakage testing: assemble the selected transcript, choose comparable presentations, normalize session and implementation differences.
5. Evaluation: shared deterministic regressions, native disclosure and binding tests, native stage measurements.
6. Related work and scope: attribution to standards and relational testing; audit assumptions stated once.

The narrative explains the system and the contribution. Resource guards, loader workarounds, development chronology, and repeated absence-of-findings statements are omitted. Existing scientific boundaries remain attached to the specific results: shared source alignment, fixture-only cross-provider regression, and native per-provider runs.

Authors: Antonio Kambiré and Martín Ochoa, zkSecurity.

Reviews: talk-narrative-review.md (outline), linear-technical-r1.md (evidence), linear-editorial-visual-r2.md (prose/layout).

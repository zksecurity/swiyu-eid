# Verified source notes

Access date for Web sources: 2026-09-21.

- OpenID4VP final specification: https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html . Final approval announced 2025-07-10: https://openid.net/openid-for-verifiable-presentations-1-0-final-specification-approved/ . Authors listed by the specification: Oliver Terbu, Torsten Lodderstedt, Kristina Yasuda, Daniel Fett, Joseph Heenan.
- RFC 9901 HTML record: https://www.rfc-editor.org/rfc/rfc9901.html . RFC Editor publication metadata is authoritative; published November 2025.
- Official Swiyu repositories: https://github.com/swiyu-admin-ch/swiyu-verifier , https://github.com/swiyu-admin-ch/swiyu-issuer , https://github.com/swiyu-admin-ch/eidch-android-wallet . Use organization authorship; do not infer individual authors.
- OpenAC primary report: https://github.com/privacy-ethereum/zkID/blob/main/paper/zkID.pdf . Local PDF title page says “The zkID Team @ PSE,” Ethereum Foundation, 24 November 2025. Local copy: `swiyu-eid/components/zkid/paper/zkID.pdf`.
- OpenAC/zkID source: https://github.com/privacy-ethereum/zkID . The experiment repository identifies its imported/forked lineage separately; avoid implying an unmodified upstream run.
- EPFL/SICPA proof examples: https://github.com/eid-privacy/zkp-pocs . Exact vendored provenance recorded locally as commit `d58bc79dd65ea6560bf199ad332d3ba3746c1c08`, MPL-2.0, in `integration/providers/epfl/circuit/UPSTREAM.txt`. No verified thesis or individual author attribution was found in the bounded pass; cite the repository organization, not an invented author or thesis.
- Metamorphic testing: https://arxiv.org/abs/2208.09505 (v1 2022-08-19; v2 2023-03-07), DOI https://doi.org/10.48550/arXiv.2208.09505 . This is an arXiv/CoRR item unless a final venue is separately verified.
- Declassification: https://doi.org/10.3233/JCS-2009-0352 , Journal of Computer Security 17(5), 517–548.
- Hyperproperties: https://doi.org/10.3233/JCS-2009-0393 , Journal of Computer Security 18(6), 1157–1210.
- Classical ZK: https://doi.org/10.1137/0218012 , SIAM Journal on Computing 18(1), 186–208 (1989); preliminary version appeared at STOC 1985. Cite one version consistently.

## Local primary evidence anchors

- `/tmp/swiyu-bounded-research-20260921/analysis-report/assessment.json`: result counts, measurements, controls, and limits.
- `swiyu-eid/docs/platform/transcript-privacy-design.md`: declared relation, normalization, observer, and non-claims.
- `swiyu-eid/docs/platform/semantics-claim-proposal.md`: pinned complete-claim model and release policy.
- `swiyu-eid/docs/platform/epfl-provider.md`: exact EPFL toolchain/provenance and bounded integration.
- `swiyu-eid/docs/platform/transcript-privacy-findings.md`: injected controls and native OpenAC campaign qualification.

## Deliberately omitted

- zk.golf and better.codes: benchmark-site inspiration was not needed for a technical claim and was not verified as a source of this method.
- A purported EPFL/SICPA thesis: unresolved. Do not cite one without title, author, institution record, and stable URL.
- Noir/Barretenberg documentation: not needed merely to state the exact locally recorded tool versions and backend. Add official Aztec documentation only if explaining UltraHonk internals.

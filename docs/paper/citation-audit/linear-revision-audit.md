# Citation audit for the linear revision

The original eleven references and primary-source checks remain in the existing citation audit. This revision adds three primary sources and restores attribution to both authors for the companion artifact.

| Key | Primary source | Supported claim |
| --- | --- | --- |
| swiyustack | https://swiyu-admin-ch.github.io/technology-stack/ | Swiyu issuer/holder/verifier architecture, SD-JWT and holder binding, OID4VCI issuance and OID4VP presentation, public-key/trust registries. Viewed 2026-09-21. |
| batch | https://github.com/swiyu-admin-ch/community/blob/main/tech-concepts/e-id-key-management-batch-issuance-and-renewal.md | Batch issuance with separate holder key pairs and renewal; source credits CEA KRYPT and is version 1.1, 3 September 2025. Viewed 2026-09-21. |
| spartan | https://github.com/eid-privacy/spartan-backend | The separate Spartan backend for Noir; background context only. Native EPFL measurements in this paper use UltraHonk. Viewed 2026-09-21. |

No rollout dates, legal claims, project-affiliation inference, or unsupported claim that all current Swiyu credentials work with a provider was added. Authored OpenAC circuits, shared registrations, comparator behavior, and empirical numbers cite the companion artifact; upstream references credit the proof-system foundations.

The rewritten evaluation cites the archived shared-claim regression as a deterministic fixture test (evidence_usable:false), separately from native provider measurements. The archive now includes the authored relation and helper components, support declarations, common conformance tests, shared/cross comparator code and tests, and the exact regression report.

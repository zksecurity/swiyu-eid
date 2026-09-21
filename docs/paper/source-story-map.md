# Story map: a semantic and transcript-testing layer for ZK presentations in swiyu

## Central argument

swiyu’s SD-JWT path improves data minimization but still reveals exact attributes for predicates and exposes repeatable credential material. Several ZK systems can address this, but their circuits, proof systems, statements, and lifecycle boundaries differ. The project’s contribution is therefore not “another age circuit.” It is a proof-system-independent integration layer at the real OID4VP/DCQL boundary: (1) versioned semantic claims define what acceptance means and what may be released; (2) provider adapters expose a common prepare/present/verify lifecycle; (3) the verifier carries a signed `x_swiyu_zkp` policy and receives an opaque proof under the normal `vp_token`; and (4) differential transcript tests ask whether equal permitted meaning produces equivalent selected observer transcripts.

This is an engineering evaluation framework, not a proof of cryptographic soundness, universal unlinkability, or standards compliance. The strongest experimental conclusion is negative and useful: across the latest seven eligible native comparisons, no natural privacy counterexample was observed. Deliberately injected leaks were detected, demonstrating detector sensitivity rather than an upstream vulnerability.

## Narrative arc

1. **Motivation.** Ordinary swiyu issuance and presentation use OID4VCI, OID4VP/DCQL, ES256 SD-JWT, holder binding, trust and status infrastructure. Selective disclosure can hide unselected fields, but an “over 18” request still reveals birth date; disclosed values, `cnf`, signed material, and status references can aid correlation. Batch issuance reduces reuse but does not provide predicates. Sources: `website/swiyu-zk-slides.pdf`, `website/talk.html`, `website/index.html`.
2. **Initial direction.** The proposal recommended a narrow age/status/holder profile, two heterogeneous backends, and full-protocol privacy normalization rather than standardizing arbitrary computation. Source: `/Users/coding/.codex/attachments/74b08c76-8869-48af-9c46-7b5255a907bd/pasted-text.txt`.
3. **System built.** A claim separates semantic meaning from implementation and campaign identity; pinned packages define credential/authentication/predicate codecs and disclosure policy. A local runner derives expectations independently, invokes providers, and observes the verifier. Java routing fails closed for ZK requests. Sources: `docs/platform/architecture.md`, `docs/platform/semantics-claim-proposal.md`, `docs/platform/transcript-privacy-design.md`, `integration/semantics/claims/`.
4. **Concrete implementations.** OpenAC/zkID uses Circom→R1CS→Spartan2/Hyrax for issuer authentication, hidden predicates, holder possession, validity, and private status. Implemented profiles include age, canton, residence, and one-claim/nullifier experiments. EPFL d10 uses Noir/UltraHonk with its fixed JWT header, age-25 relation, and holder challenge. These are not interchangeable claims merely because both concern age.
5. **Evaluation.** Compare complete selected HTTP boundaries: management creation, signed request retrieval, `direct_post`, and management result. Normalize only declared fresh session/clock values and opaque proof bytes while retaining lengths and envelope siblings. Classify fixtures before comparison.
6. **Result and lesson.** The semantic contract makes heterogeneous experiments comparable without pretending their circuits are identical; transcript equivalence tests the integration layer that zero-knowledge proofs alone do not cover.

## Implemented versus planned

**Implemented:** claim/catalog loader and independent fixture classification; common provider lifecycle; native OpenAC and EPFL adapters; signed verifier policy/routing and loopback sidecar; local Java controller/service transport; transcript capture, normalization, secret markers, negative controls, reports; OpenAC profiles and laptop benchmarks; wallet policy parsing/runtime request/opaque response carriage.

**Planned or incomplete:** Android-native proof packaging and emulator end-to-end execution; production trust registry, issuer and status infrastructure; full Spring/deployment/TLS path; standardized wire extension; broad credential/profile compatibility; timing-distribution study; formal circuit verification; general arbitrary predicates. EPFL’s synthetic credential uses a circuit-fixed header, so arbitrary swiyu SD-JWT compatibility is unestablished.

## Evidence ledger

- Older OpenAC native transcript campaign: four accepted proofs; clean pair equivalent; injected compact credential field and hash header detected as disclosure/identifier/transcript differences. Proof 315,967 B; witness 199,642,572 B; present 44.1–50.5 s; submit/verify 14.5–19.2 s. `docs/platform/transcript-privacy-findings.md`, `docs/platform/evidence/2026-09-15-openac-transcript/`.
- Older EPFL campaign: four accepted 16,224 B proofs; clean hidden-birth-date pair equivalent; injected controls detected. `docs/platform/evidence/2026-09-15-epfl-transcript/summary.md`.
- Latest bounded natural experiment: nine sessions, eight accepted, seven eligible pairs all equivalent. OpenAC compares repeat, hidden holder key, and hidden expiry; one matrix expiry rejection was caused by the 300 s policy-clock limit and accepted in a fresh pair. EPFL compares repeat and changed authenticated hidden holder. No candidate transcript finding. `/tmp/swiyu-bounded-research-20260921/analysis-report/assessment.json` and `index.html`.
- Native controls: original OpenAC verifier accepted matching public inputs and rejected changed nonce; direct `bb` accepted captured EPFL holder proof and rejected one-byte nonce change. EPFL source/core/circuit hashes and guard cleanup were checked. `/tmp/swiyu-bounded-research-20260921/epfl-holder/evidence-check.json`.
- Performance context from the latest talk/site: ordinary SD-JWT is millisecond-scale and 1.3–1.8 KB; OpenAC experimental profiles require roughly 14–16 s repeat wallet work, 1.7–1.8 s verification, and about 258 KB transmitted, with large circuit/key artifacts. Use as bounded laptop/container measurements, not mobile claims.

## Terminology to keep exact

- **Claim/statement:** complete acceptance relation plus permitted release; identified by `statement_digest`.
- **Implementation:** provider code/artifacts and declared placement of checks.
- **Campaign:** concrete fixtures, givens, runtime and observations.
- **Equivalent transcript:** equality under an explicit observer and normalization policy; not cryptographic unlinkability.
- **Injected control:** intentionally faulty integration used to test detection; never a natural finding.
- **Observer:** four selected application HTTP boundaries; excludes Android, TLS/packets, sidecar IPC, live authorities and timing distributions.

## Conservative 4–5 page outline

1. **Problem and contribution (0.6 page):** swiyu privacy gap; heterogeneous ZK problem; three contributions—semantic claims, provider/OID4VP integration, transcript differential testing.
2. **Design (1.1 pages):** issuer-wallet-verifier flow; signed DCQL extension; claim/implementation/campaign identities; independent oracle; explicit observer and normalization.
3. **Implementations (0.8 page):** OpenAC and EPFL relations/lifecycles; what each authenticates; synthetic and runtime limits. One architecture figure.
4. **Experiments (1.2 pages):** older injected-control campaigns, latest hidden-holder/expiry matrix, controls, resource workaround. One compact table separating natural runs from injections.
5. **Results, limitations, implications (0.8 page):** 9/8/7 headline; clock confound; proof/witness/performance scale; no natural counterexample; what this validates and does not.
6. **Related work and conclusion (0.5 page):** OpenAC, EPFL, Mombelli, Longfellow/Crescent, EUDI TS13; narrow novelty at the swiyu protocol boundary.

## Unknowns requiring author decisions

- Target workshop/template, citation style, anonymity, and whether 4–5 pages include references.
- Which benchmark environment details are comparable enough for the main table.
- Whether to foreground the four OpenAC application profiles or keep canton/residence/nullifier as breadth evidence.
- Public artifact locations for the newest `/tmp` evidence before submission.

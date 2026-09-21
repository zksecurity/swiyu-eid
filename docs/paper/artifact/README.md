# Companion evidence for the working paper

This directory is the local companion cited as `artifact`. It is not a published archive and has no DOI. The paper has not been submitted to a workshop. Before submission, deposit the final version in a stable archive and update that bibliography entry.

`manifest.json` lists content hashes and source locations for every included evidence or method snapshot. The experimental source tree was dirty; the recorded Git HEAD alone is insufficient provenance. The OpenAC loader and d10 source/binary records qualify the native implementations used.

## Map from paper to evidence

| Paper claim | Evidence |
| --- | --- |
| September 15 clean and injected OpenAC pairs | `evidence/openac-20260915.json` |
| September 15 clean and injected d10 pairs | `evidence/d10-20260915.json` |
| Latest nine sessions, eight accepted, seven equivalent comparisons | `evidence/native-20260921.json` |
| Policy freshness rejection and accepted fresh expiry pair | `evidence/native-20260921.json`, fields `stale_policy_rejection` and `comparisons` |
| d10 accepted states, actual proof lengths/digests, source checks | `evidence/d10-evidence-check.json` |
| Native changed-challenge rejection control | `evidence/d10-native-control.json`; OpenAC control is embedded in the combined assessment |
| Shared age-25 contract and both implementation registrations | `claims/shared-age25.json`, `implementation/openac-support.json`, `implementation/epfl-support.json` |
| Authored OpenAC circuit aligned to the d10 statement | `implementation/swiyu-age25-jwt.circom`, `implementation/yyyymmdd-age.circom`, `implementation/disclosure.circom`, main entry point and registry |
| Cross-provider fixture comparison: 4 equivalent clean pairs, 4 injected mismatches | `evidence/shared-age25-fixture-regression.json` (fixture-only, `evidence_usable: false`) |
| Common claim and comparison regression validation: 22 tests passed | `evidence/shared-regression-validation.txt`, `method/test_shared_age25_conformance.py`, `method/test_transcript_shared.py`, `method/test_transcript_cross.py` |
| Original native profiles and their obligations | `claims/openac.json`, `claims/d10.json` |
| Observer, normalization, masking and exclusions | `method/transcript-privacy-design.md` and report policy fields |
| Semantic design versus executable implementation | `method/claim-model-design.md`, `method/implemented-semantics.md` |
| Provider lifecycle and runtime invocation | `method/provider-guide.md` |

The archived reports are sanitized public outputs. Raw credentials, proof bodies and session captures remain in the originating local experiments and are not included. The validator compared these outputs against those private captures before export. This archive supports inspection of reported evidence; it is not a self-contained proving environment.

## Re-execution requirements

Use the repository's `integration/harness/TRANSCRIPT-PROVIDERS.md` from the tested source tree. Native execution requires provider artifacts, the Python semantic environment, a JDK, Maven, and each adapter's toolchain. OpenAC needs its witness calculator and proving/verifying keys. The d10 experiment used nargo 1.0.0-beta.13 and bb 1.2.1. The older and latest campaigns have different inputs; rerunning the default fixture factory does not reproduce the latest hidden-holder/expiry matrix automatically.

The original bounded experiment retains its fixture generators, runners, source checks and reports under `/tmp/swiyu-bounded-research-20260921` on the authoring machine. That temporary location is a local provenance pointer, not a durable public dependency. Before a public release, archive the corresponding experiment sources and supply the large-artifact acquisition/build instructions. No new native experiment was run while drafting the paper.

Private captures, mathematical soundness, opaque proof confidentiality, production authorities, Android execution and timing distributions were not independently audited for this draft. See the paper for the exact observer, implemented claims, and execution modes.

## Shared-claim revision

The paper now follows the talk: Swiyu and SD-JWT, ZK approaches and profiles, generic integration, shared statements, transcript comparison, and evaluation. Circuit alignment is supported by source and registration checks. The shared regression uses simulated proofs and HTTP fixtures; its report is explicitly marked as fixture-only. Native measurements come from the separately identified original OpenAC age-and-status and EPFL age-25 campaigns. The new OpenAC age-25 circuit has a build target and source; the shared Java runner uses a session-bound synthetic envelope for that profile until native witness/key artifacts are built.

The circuit snapshots document the authored relation; dependencies remain in the source repository. They are not a standalone circuit build or a cryptographic audit.

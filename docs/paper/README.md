# Integrating and Testing Zero-Knowledge Presentations in Swiyu

**Antonio Kambiré and Martìn Ochoa, zkSecurity.**

The working paper is [claim-guided-transcript-testing.pdf](claim-guided-transcript-testing.pdf): five pages including references. Editable source is `paper.tex`, with `references.bib`. Run `sh build.sh` with a standard LaTeX installation to rebuild it.

The paper follows the talk's progression: Swiyu and selective disclosure; ZK approaches and our OpenAC profiles; the generic provider and OID4VP integration layer; shared claims and the authored OpenAC age-25 circuit; differential transcript testing; and evaluation. It separates native provider campaigns from deterministic shared-claim regressions and records the execution mode of the aligned OpenAC adapter.

## Evidence and attribution

- `artifact/` contains 32 hashed evidence, circuit, and method snapshots, with a paper-to-evidence map. Raw private captures and large proving artifacts remain outside the bundle.
- `citation-audit/` records primary sources and supported claims for the 14 references. The linear-revision audit adds the Swiyu technology stack, batch-issuance design, and eid-privacy Spartan-backend context.
- `reviewed-plan.md` is the current narrative outline. `source-story-map.md` preserves the initial mapping from the proposal, early slides, website, and talk.
- `reviews/linear-technical-r1.md` and `reviews/linear-editorial-visual-r2.md` are the final reviews of this revision. Earlier rounds are retained as history. These are independent agent reviews, not external academic peer review.
- `reviews/no-ai-slop/` preserves the requested GitHub style skill and checklist.

`source-and-evidence.zip` packages the current paper, editable sources, citations, evidence, and review records. The remaining submission work is venue formatting and a durable public artifact deposit with instructions for acquiring or building the native artifacts.

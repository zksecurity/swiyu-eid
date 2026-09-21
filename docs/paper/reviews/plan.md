# Plan review: APPROVE after revision

The revised plan resolves the five issues below. The evidence taxonomy is now correct: EPFL contributes real native proofs over synthetic credential fixtures; the excluded synthetic substitute is the additional OpenAC age-25 shared-claim envelope. It will not enter native counts or performance comparisons. No remaining blocker prevents drafting.

The argument is publishable at workshop length, but revise the outline before drafting so the paper cannot overstate what the experiments establish.

1. **Make the contribution claim narrower and concrete.** Define the contribution as an implemented connection among a versioned claim contract, provider lifecycle, OID4VP carriage, and observer-relative differential transcript testing. “Can determine” sounds like a proved guarantee. Say the contract *declares* authenticated inputs, permitted releases, and comparison eligibility, while the implementation enforces and tests those declarations. Do not imply formal privacy, soundness, unlinkability, standards compliance, or novelty for relational testing.

2. **Use three evaluation classes, not two.** The main table and prose should keep separate: (a) clean/native selected-flow comparisons, (b) injected leaking controls that establish detector sensitivity, and (c) the synthetic EPFL OpenAC-age-25 envelope. Never count (c) as a second native backend implementing the same claim. State that OpenAC and EPFL authenticate different relations and credential formats; common lifecycle support is the cross-backend result.

3. **Report the latest run without laundering the clock failure.** Say nine sessions executed, eight proofs were accepted, and seven eligible pairwise comparisons were transcript-equivalent under the declared normalization. Identify the rejected expiry session as a 300-second policy-freshness/experiment-scheduling failure, then report the accepted fresh expiry pair. Durations are operational observations, not timing-privacy evidence. Witness sizes are outside the selected HTTP observer and OpenAC/EPFL witness encodings are not directly comparable.

4. **Reallocate space.** Merge “Next experiment” into limitations/conclusion. Suggested budget including references: introduction 0.55; design and definitions 1.05; implementations 0.65; method/evaluation 1.35; results/limitations 0.65; related work/conclusion 0.35; references 0.4 pages. One architecture figure and one compact table are enough.

5. **Citations must anchor the boundary claims.** Cite the normative OID4VP/DCQL and SD-JWT VC specifications for protocol/disclosure behavior; primary OpenAC and EPFL system/circuit sources for authenticated relations; original noninterference/observational-equivalence and metamorphic-testing sources only where those concepts are used; swiyu architecture/docs or repository artifacts for implementation facts; and immutable evidence paths/hashes for measured results. Avoid citing slides for general technical claims when a primary specification exists.

Keep the exact terms **claim**, **implementation**, **campaign**, **observer**, **normalization**, **eligible comparison**, **injected control**, and **natural counterexample**. Define “equivalent transcript” once as equality under the selected observer and declared normalization, then use it consistently.

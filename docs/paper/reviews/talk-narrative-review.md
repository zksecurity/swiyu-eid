# Talk-aligned narrative review

## Recommended linear outline

1. **Swiyu and its privacy gap.** Introduce the issuer–wallet–verifier system, OID4VCI issuance, and OID4VP/DCQL presentation. Explain SD-JWT selective disclosure, then state its two remaining limits: predicates still reveal the underlying claim, and disclosed claims or holder keys remain correlatable. Mention batch issuance as Swiyu’s current unlinkability measure and explain why it does not supply predicates or protect against colluding observers.
2. **Current ZK adaptation.** Present the OpenAC Prepare/Show path and the four implemented Swiyu profiles (age/status, canton, residence, one-claim/nullifier), with one compact benchmark comparison against ordinary SD-JWT. Then introduce eid-privacy/EPFL as a heterogeneous second backend and explain why differing statements and stacks prevent direct comparison.
3. **Generic integration layer.** Describe the signed `x_swiyu_zkp` DCQL policy, opaque proof in `vp_token`, and common provider lifecycle. State precisely which boundaries are implemented and which remain experimental.
4. **Aligned semantics and transcript method.** Introduce claim/implementation/campaign identities, the aligned age-25 plus holder-challenge statement, independent fixture classification, observer boundary, normalization, and within-/cross-provider differential relation.
5. **Evaluation, results, and limits.** Lead with the useful findings: injected leaks were detected despite accepted proofs; the latest native campaign produced nine sessions, eight accepted, and seven eligible equivalent comparisons; no natural privacy counterexample was observed. Report performance as bounded measurements, then close with observer, circuit-audit, Android, and production limits.

## Substantive gaps and cuts

1. **Add the missing Swiyu system model.** The opening “Swiyu uses SD-JWT selective disclosure…” skips issuer, wallet, Generic Verifier, OID4VCI, and DCQL roles. One compact flow paragraph or figure should establish them before ZK.
2. **Add Swiyu’s existing response to linkability.** The paper omits batch issuance. Explain it fairly, then identify the remaining predicate and collusion gaps; this motivates ZK without implying Swiyu has no privacy design.
3. **Restore the actual adaptation before the generic framework.** The talk’s concrete work—four OpenAC predicates and Prepare/Show measurements—is nearly absent. Present it before “We built a framework…” so the abstraction answers a visible integration problem.
4. **Cut dated campaign-log structure.** Replace rows such as “OpenAC clean, Sept. 15,” “OpenAC matrix, Sept. 21,” and prose beginning “The September 21 campaign…” with experiment classes: leak controls, hidden-input comparisons, and the freshness-confounded rejection.
5. **Delete implementation-troubleshooting history.** Cut “The completed OpenAC runs used a temporary read-only memory-mapped key loader…” and the 1.6 GB copy detail. It is artifact provenance, not the paper’s research narrative.
6. **Clarify evidence tiers.** Keep the sentence that the aligned OpenAC age-25 path uses a session-bound synthetic envelope, but place it beside the shared-claim result. Do not let cross-provider integration evidence read as a native two-prover comparison; report native OpenAC and native EPFL campaigns separately.

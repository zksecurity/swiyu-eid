# Technical/evidence review R1: REVISE

The central argument, 9/8/7 headline, proof and witness sizes, timing ranges, injected-control interpretation, native nonce controls, observer boundary, and OpenAC/EPFL distinction agree with the reviewed evidence. Revision is required for presentation precision, not a change of thesis.

## Required

1. **Do not label a run containing an unexpected rejection simply “Equivalent.”** Table 1 currently gives `OpenAC matrix, Sept. 21 ... Equivalent*`; the assessment classifies that run as `findings` because one session unexpectedly rejected. A footnote is too easy to miss. Change the result cell to **“3 pairs equivalent; 1 functional reject”** and remove the star. Keep the fresh-expiry row, which shows that the expiry comparison passed when rerun before the policy deadline.

2. **Reduce the inference attached to the repeat control.** “A same-credential repeat helps separate ordinary session variation from changes across credentials” overstates what one repeat can separate. Replace with: **“A same-credential repeat records one reference for session-induced variation before credentials are changed.”** This preserves the control's purpose without implying a distribution or causal decomposition.

3. **Remove the undeployed submission/audit design from the contribution path.** The paragraph beginning “The platform is designed for local use” spends scarce space on optional public submissions and audit reports that were not evaluated. Replace the paragraph with: **“The evaluated contribution is the executable local integration and test path. It does not certify cryptographic security or operate a public registry.”** This also removes the binary, AI-like “rather than” construction.

## Optional tightening

- Clarify that “It compares compact JWS signatures by algorithm and canonical length” concerns the **normalized request-object JWS signature**, lest readers infer that issuer or holder signatures are accepted without verification.
- “This matters for OpenAC” is interpretive metadiscourse. Join it directly to the fact: **“OpenAC's native status relation differs from the generic reference status package, so the actual verifier evaluates native status.”**
- The draft repeats variants of “not a proof / not compatibility / not timing evidence” often. Keep the domain limits where first needed and in the final limits section; remove duplicate wording from the abstract or intermediate sections when layout is tight. Do not remove the distinctions between clean runs, injected controls, native EPFL fixtures, and the excluded synthetic OpenAC age-25 envelope.
- Replace the known incorrect “Mai et al.” attribution as already planned. No other technical blocker emerged from this review.

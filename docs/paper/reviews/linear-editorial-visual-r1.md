# Linear editorial and visual review

**Verdict: ACTIONABLE CHANGE, then PASS.**

The rewrite now follows the requested research story: Swiyu and SD-JWT; batch issuance and the remaining predicate/linkability gap; current OpenAC profiles and eid-privacy as a heterogeneous backend; the provider/OID4VP integration; semantic alignment; transcript testing; then evaluation by experiment class. It no longer reads like a dated work log. The text correctly separates deterministic cross-provider regressions, native EPFL execution, the synthetic aligned OpenAC transport path, and separate native OpenAC evidence.

One substantive result is missing from the conclusion of Section 5.2. The paragraph says, “These eight accepted presentations yielded seven eligible equivalent pairs,” and later mentions the stale rejection, but never states the complete headline or the negative finding. Replace those sentences with an explicit formulation such as: **“Across nine sessions, eight presentations were accepted and seven eligible pairs compared equivalent; the remaining session was a stale-policy functional rejection. No natural privacy counterexample was observed.”** This restores the requested 9/8/7 result and prevents readers from mistaking the injected controls for a discovered defect. It should also appear once in the abstract or final scope paragraph if space permits.

No other editorial blocker found. The prose passes the no-AI-slop audit: no banned filler, faux-insight setup, dramatic fragments, inflated novelty claim, fake-profound ending, or excessive em dashes. “Our contribution connects…” is normal research framing and is supported by concrete mechanisms.

Author verification: **Antonio Kambiré** and **Martín Ochoa**, with **zkSecurity** directly below, render on page 1; PDF text extraction and metadata preserve both accents.

## Image-by-image visual QA

| Page | Result |
|---|---|
| 1 | PASS: title and author block centered; accents visible; abstract and opening sections legible; no clipping. |
| 2 | PASS: architecture figure, caption, headings, and code identifiers fit; no collision or overflow. |
| 3 | PASS: equation and section transitions are clear; columns fill evenly; no orphaned heading. |
| 4 | PASS: evidence text and measurement table are readable; table rules and values align; moderate lower-right whitespace is acceptable before references. |
| 5 | PASS: 14 references are balanced across columns, URLs remain inside margins, and the remaining lower-page whitespace is even rather than a layout defect. |

Exact page count: **5**. No missing glyphs, overlap, cropped content, blank page, or visibly broken reference layout.

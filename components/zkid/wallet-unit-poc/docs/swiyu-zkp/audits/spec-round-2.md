# Specification audit — round 2

Independent gate result: **PASS for an experiment-complete desktop research
prototype.** No P0/P1 findings remain. This is not a mobile-deployment pass.

## Findings resolved

1. **P2 — status-URI privacy was overclaimed.** The requirements, profile, and
   design docs now distinguish presentation privacy (credential-specific URI,
   index, path, and root stay hidden) from verifier-operator knowledge of the
   provisioned list cohort.
2. **P2 — proof fixture size was misstated.** The same-Spartan proof table now
   identifies its 256-issued/4-revoked fixture and distinguishes the separate
   65,536-issued/1,024-revoked data benchmark. Machine-readable results include
   both counts and indices.
3. **P2 — browser wording exceeded evidence.** Documentation now says the
   browser-targeted build was exercised under Node's WebAssembly runtime. The
   browser/mobile conclusion is explicitly an engineering inference.
4. **P2 — snapshot-ID handoff was underspecified.** Verifier documentation now
   tells orchestration to use the exported authenticated provisioning helper,
   gives the exact deterministic ID shape, and forbids hand-authored reuse.
5. **P2 — private witness authority was undocumented.** `PROFILE.md` now groups
   every private signal class, authority/check, and outside-proof visibility.
6. **P3 — “real shape” wording conflicted with the synthetic fixture.** The
   acceptance gate now says observed local repository-test shapes and forbids
   describing the fixture as a captured production credential.

## Gate boundary

Round-one P1 findings—missing same-system status proof measurements and
unauthenticated production status ingestion—are resolved. The measured mobile
no-go is an acceptable Prototype B research result only while completion
language continues to distinguish experiment completion from the deck's
aspirational mobile outcome.

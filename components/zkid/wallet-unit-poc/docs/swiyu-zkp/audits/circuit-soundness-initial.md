# Initial circuit-soundness review

This review happened during implementation, before the ordered specification,
functionality, and style audit gates. It is recorded separately so fixes are
traceable rather than silently folded into the final relation.

## Blocking findings resolved

- Replaced underconstrained unsigned-JSON accumulation and constrained every
  disabled byte/bit path.
- Fixed compact-JWS separator and padding bounds at the 1,472/1,504-byte
  boundaries.
- Raised fixed string slots to fit the observed 99-byte `did:tdw` key ID.
- Rejected duplicate or escaped security keys and malformed compact-JSON
  member separators.
- Required exact `swiss-profile-vc:1.0.0`, canonical base64url tails, and one
  authenticated `birthdate` disclosure.
- Constrained issuer and holder P-256 points to canonical, finite, on-curve
  coordinates.
- Fixed the shared P-256 complete-addition infinity case and added component
  regressions.
- Bound issuer key, challenge, metadata, validity time, status snapshot, and
  exact two-bit value in one relation.
- Split private wallet status material from authoritative verifier snapshot
  material and added signed `statuslist+jwt` derivation.
- Bound metadata to the session challenge and rejected challenge scalars at or
  above the P-256 scalar order, eliminating field aliases.

## Residual non-blocking limitations

- The inherited ECDSA gadget compares `r` with affine x without conditional
  reduction modulo the scalar order. This can reject an exceedingly rare valid
  signature; it does not make an invalid signature pass.
- The profile has no verifier-scoped nullifier. It prevents request replay but
  intentionally does not implement one-credential/one-signup unicity.
- The fixed relation supports only the documented compact Swiss subset and
  two-bit status lists. Other issuer options require a new profile, not parser
  leniency inside this one.

## Regression evidence

- 45 fixed-profile/P-256 component tests pass.
- The final compiler reports 6,461,359 nonlinear constraints, one linear
  constraint, nine declared public inputs, one output, and 3,266 private
  inputs.
- An issuer-shaped synthetic fixture produces a 199,663,884-byte witness and a
  real Spartan proof that verifies against independently reconstructed public
  values.

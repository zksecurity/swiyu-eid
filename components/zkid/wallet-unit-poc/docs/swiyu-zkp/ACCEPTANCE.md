# Completion gates

The prototype is complete only when every required gate below has local test
or artifact evidence. “Implemented” without the corresponding evidence is not
a pass.

## Specification

- [ ] Exact IDs and wire fields agree across Circom, TypeScript, Rust/WASM,
  and Java.
- [ ] Every public/private signal and trust boundary is documented.
- [ ] Observed local swiyu repository-test header/key/status shapes fit the
  fixed limits; synthetic fixtures are not described as captured production
  credentials.
- [ ] Snapshot provenance, freshness, two-bit restriction, and one-list policy
  precondition are explicit.
- [ ] Non-goals and measured feasibility limits are explicit.
- [ ] At least two independent specification-audit rounds have no unresolved
  P0/P1 findings.

## Functionality

- [ ] Final Circom relation compiles without debug-symbol disk blow-up.
- [ ] Component tests cover parser, date, disclosure, signatures, status path,
  field boundaries, and all audited adversarial cases.
- [ ] A real issuer-shaped SD-JWT produces a real `.wtns`.
- [ ] Native setup, one real Spartan proof, and verification succeed using the
  final R1CS.
- [ ] Tampered challenge, resolver hint, issuer key, age cutoff, time, snapshot,
  status value/path, proof, and verifying key all fail.
- [ ] The packaged witness-generator WASM loads, and the real path-backed
  Node/native SDK backend proves/verifies without copying multi-GB keys; the
  browser-targeted WASM failure measured under Node is explicit and is not
  misreported as an in-browser measurement or a pass.
- [ ] Java DCQL opt-in route calls the configured local sidecar, fails closed,
  and preserves single-use session/replay behavior.
- [ ] Prototype B includes executable fixed-index, non-membership, and
  adjacent-pair comparison harnesses plus build/update/witness measurements.
- [ ] At least two independent functionality-audit rounds have no unresolved
  P0/P1 findings.

## Style and maintainability

- [ ] No normal swiyu presentation or issuer behavior changes when the opt-in
  policy is absent.
- [ ] Fixed-profile code remains isolated and names explain security domains.
- [ ] No mock backend is reachable from production exports.
- [ ] No generated multi-gigabyte artifact is staged in Git.
- [ ] TypeScript lint/build, Rust format/test, Circom focused/full tests, and
  Java format/test pass.
- [ ] At least two independent style-audit rounds have no unresolved P0/P1
  findings.

## Evidence

Final constraint counts, timing, memory, artifact sizes, audit reports, test
commands, and local commit hashes are recorded here only after they exist.

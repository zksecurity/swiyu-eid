# Professional-licence valid-through predicate

## Business statement

The holder controls a credential under an accepted professional-licence VCT
which is currently active, has an exact `VALID` (`00`) entry in the
verifier-selected status snapshot, and whose exclusive JWT expiry is strictly
after a verifier-selected project or service end time. Treating this as a
professional licence relies on the accepted VCT schema and issuer policy; the
circuit does not prove a separate hidden authorization-category or
licence-specific expiry claim. The proof does not reveal the
expiry, holder key, status-list position, issuer lookup tuple, or status URI.

The benchmark credential uses the deployment-specific VCT
`urn:ch:professional-license:v1`. The verifier-side builder rejects
other VCTs before deriving the public session commitment. Prepare authenticates
that same VCT inside the issuer-signed payload and carries its lookup hash into
Show as a committed shared value.

## Relation split

Prepare is reusable for every presentation of the same credential. It proves
the issuer signature, canonical JOSE/base64 and JSON structure, protected
profile header, holder P-256 key, `nbf`, `exp`, status URI/index, and the
issuer/kid/VCT lookup tuple. Unlike the age profile, this dedicated relation
statically removes every birthdate-disclosure and `_sd` membership component;
shared row 2 is a canonical zero.

Show is per presentation. It proves a fresh holder signature, ordinary
`nbf <= currentTime < requiredValidUntil < exp` validity chain, the exact
two-bit `VALID` status entry and status-root binding, and the fresh
challenge/lookup session commitment. The verifier supplies all seven public
inputs, including `requiredValidUntil`; the holder cannot choose a weaker
policy privately.

Prepare and Show reuse the same eleven native Spartan shared rows. Both Circom
relations constrain those rows directly. The benchmark reblinds both proofs
with the same randomness and checks the commitments embedded in the verified
proofs, not caller-supplied duplicate instances.

The profile adapter consumes a verifier-selected issuer key, status URI, and
snapshot root; it does not itself resolve DID keys or authenticate/freshness-
check the upstream status-list object. A production caller must perform those
trust checks before constructing `SwiyuProfessionalLicenseVerifierPolicy`, as
the existing age-profile sidecar does for its authoritative snapshot registry.

## Optimizations

Reusable across predicates:

- bounded compact SD-JWT buffers instead of the 2 KiB general profile;
- one issuer signature in reusable Prepare and one holder signature in Show;
- static, fixed-policy Show relations rather than a general predicate VM;
- two 128-bit SHA limbs for lookup/status context instead of publishing hidden
  credential fields;
- the optimized depth-17 dense status proof and sound shared-output wiring.

Professional-licence-specific:

- use the already issuer-authenticated registered `exp` claim, avoiding another
  selective-disclosure parser and SHA-256 disclosure-membership path;
- remove the entire age disclosure/date-validation relation from Prepare;
- one strict 64-bit comparison directly expresses the exclusive-expiry
  project-end policy;
- no unused age, residency, set-membership, or general-expression machinery is
  present in Show.

## Measurement method

Circom is compiled with `--O2 --prime secq256r1` and only R1CS/WASM artifacts.
The witness runner first records two complete Prepare and Show samples. If
either stage differs by more than 15% relative to the pair's mean, it expands
to seven; otherwise it records three. The native runner independently applies
that same adaptive rule to witness handoff, setup, key serialization,
assignment construction, prepared-state serialization, link randomness, final
linked proof, proof serialization/deserialization, and verification. All raw
samples are retained. Reported summaries contain
minimum, median, maximum, mean, sample variance, sample standard deviation, and
coefficient of variation.

Native proof verification returns field-encoded public values. The SDK adapter
compares those values against the verifier-reconstructed issuer key, challenge,
current time, project end, accepted lookup/VCT commitment and authoritative
status commitment. A cryptographically valid proof is not an authorization
decision unless those expected-value comparisons and embedded shared-
commitment linkage both succeed.

Setup and proving/verifying keys are one-time per relation. Key serialization
is timed by encoding both keys to an in-memory sink, separately from setup;
prepared-state serialization is likewise an optional durability boundary, not
an unavoidable cost when state remains in memory. The Prepare witness and
assignment are reusable per credential. Its final proof is freshly reblinded
per presentation with Show's randomness, so Prepare final-proof time is a
per-presentation cost. Show witness, assignment, final proof, proof transport,
deserialization, and both verification operations are also per presentation.
Verification is performed on the deserialized proof object.

## Results

This correctness pilot ran on an Apple M1 with 16 GiB RAM. Variance in the
first pair triggered seven samples for both witness generation and the native
pipeline. The pinned Docker benchmark should be used for cross-predicate final
comparisons; the following values establish this predicate's complete local
pipeline and data schema.

### Median lifecycle cost

| Lifecycle boundary | Included work | Median |
| --- | --- | ---: |
| One-time relation setup | Prepare setup + Show setup | 21,277.82 ms |
| Optional one-time key persistence | bincode encoding of both Prepare and Show PK/VK to a sink | 393.59 ms |
| Reusable per credential | Prepare witness + WTNS handoff + assignment + prepared-state encoding | 8,496.86 ms |
| Per presentation, wallet | Show witness/handoff/assignment/state encoding + link randomness + both final proofs and proof encoding | 12,301.27 ms |
| Per presentation, verifier | both proof decodes + both Spartan verifications | 1,028.61 ms |

The lifecycle totals are sums of component medians, not medians of synthetic
end-to-end samples. Optional key/prepared-state persistence is shown explicitly
so an in-memory deployment can omit it without silently changing the measured
stages.

### Median stage detail

| Stage | Prepare | Show |
| --- | ---: | ---: |
| Circom witness generation | 4,133.43 ms | 3,998.45 ms |
| WTNS file read + parse | 108.16 ms | 76.57 ms |
| Spartan setup | 13,584.59 ms | 7,693.23 ms |
| PK + VK serialization to sink | 233.18 ms | 160.42 ms |
| Assignment construction | 4,190.21 ms | 1,977.22 ms |
| Prepared-state serialization | 65.06 ms | 29.00 ms |
| Final linked proof | 4,309.09 ms | 1,866.68 ms |
| Proof serialization | 29.54 ms | 14.70 ms |
| Proof deserialization | 95.27 ms | 47.41 ms |
| Verify reconstructed proof | 615.08 ms | 270.85 ms |

Shared link-randomness generation had a 0.015 ms median. All fourteen positive
proofs in seven linked pairs verified, their shared commitments matched, and
the negative Show proof verified independently while its changed shared-expiry
commitment was rejected by the linkage check.

### Exact artifacts

| Artifact | Prepare | Show |
| --- | ---: | ---: |
| Constraints | 2,224,731 | 1,271,440 |
| Wires | 2,127,173 | 1,256,480 |
| R1CS | 470,257,100 B | 313,469,252 B |
| WASM | 9,192,642 B | 5,399,967 B |
| WTNS | 68,069,612 B | 40,207,436 B |
| Proving key | 574,634,082 B | 370,543,754 B |
| Verifying key | 574,634,050 B | 370,543,722 B |
| Final proof | 180,055 B | 112,135 B |
| Pre-reblind instance | 135,471 B | 68,047 B |
| Assignment | 134,348,817 B | 67,174,417 B |

Witness generation peaked at 899,039,232 bytes RSS. The sequential native
process peaked at 3,654,287,360 bytes before the deliberate negative control;
this is an upper bound for a process that performs setup, wallet work, and
verification together rather than a production role-specific memory figure.

Exact raw samples and all min/median/max/mean/CV/sample-variance summaries are
checked into `professional-license-benchmark-results.json`, including the raw
witness-generation record.

# Assessment after the EPFL hidden-holder run

The native EPFL run accepted baseline A, a fresh repeat of A, and an authentically reissued credential with holder B. All three selected-flow comparisons were equivalent. Proofs were distinct and each was 16,224 bytes. A direct invocation of the original native verifier accepted the captured holder-B proof and rejected the same proof with one changed challenge byte.

This adds evidence for a second provider under the bounded observer. It does not demonstrate a natural integration privacy defect.

## Local witness-size telemetry

The discovery review identifies a real provider JSONL output: `artifact_sizes.witness`. EPFL's measured compressed sizes were 311,420, 311,426 and 311,433 bytes. The same-holder repeat also changes size, so these three observations cannot attribute that change to holder identity.

More fundamentally, the provider and its local harness already receive the credential and witness inputs. No inspected reachable path forwards this telemetry to the verifier or another actor with less access. Extending the observer to this trusted local channel would not establish a verifier privacy issue. Public benchmark reports here describe synthetic fixtures. This candidate is deferred unless a concrete consumer exposes the telemetry across a relevant trust boundary.

## Remaining evidence boundary

The selected local integrations provision issuer/status information before presentation. The discovery pass found no supported live issuer/status-network experiment in these paths. Android and the reusable split Prepare/Show lifecycle are not executed by these transcript providers. Findings about those flows require a real reachable implementation and an explicitly expanded observer before execution.

Further synthetic mutations inside an envelope that contains only fixed public labels and an opaque constant-length proof have diminishing value. The next investigation should establish an actual additional wallet/integration boundary, then state its public inputs, permitted releases and observer access before running differential cases. A hypothetical emitter or an injected extra field remains a detector control, not a natural finding.

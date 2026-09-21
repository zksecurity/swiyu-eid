# Shared integration privacy campaign — 2026-09-15

The campaign implementation lives in `integration/harness/privacy_campaign.py`.
Run instructions and the contributor observation contract are in
`integration/harness/PRIVACY.md`.

## Confirmed shared-facade defect, fixed

The local mobile-runtime facade forwarded a provider's arbitrary error message,
error code, and verification reason into its CLI response. A deliberately faulty
provider returning a synthetic credential in those fields caused three separate
red tests. This is a shared boundary defect reproduced by fault injection; it
is not a finding that OpenAC emitted those values in normal operation.

`integration/runtime/mobile_runtime.py` now maps provider failures to fixed
public messages and restricts verification reasons to fixed values. Successful
verification drops diagnostic reasons. Existing behavior for the known
`binding_or_predicate_failed` reason remains compatible. Provider-internal logs
are outside this fix.

Reproduce against the current implementation:

```sh
python3 integration/harness/zkbench.py privacy-run \
  --adapter integration/harness/facade_privacy.py --controls \
  --output /tmp/facade-privacy
```

The fault-injection provider and fixtures are test-only. `test_facade_privacy.py`
checks the actual CLI output; it does not mock the redaction function.

## SDK export contract concern

`resolveSwiyuStatusListJwt` describes its authoritative snapshot as URI-free,
but its `subject` field contains the credential's status-list URI. A scan of that
export detects the synthetic URI. The private snapshot inside the resolver is
not treated as a leak.

This finding is at the local SDK projection boundary. The current sidecar also
provisions known status subjects independently in trusted configuration. This
campaign has not demonstrated a credential URI being sent over verifier HTTP,
nor inferred that every status-list URI identifies an individual. Consumers
must not assume the authoritative object is safe to publish merely because of
that comment. The report's strict URI-free release expectation is explicit.

## SDK packaging issue

The built SDK exports separate bundled instances of `SwiyuVerifierSidecarService`
through its index and sidecar entrypoints. The server's `instanceof` check rejects
a service constructed using the index entrypoint. This is a functional
integration finding, not a privacy leak. The HTTP collector records this failure
and uses an explicit test-only module export shim to exercise the existing
sidecar implementation with its own bundled class. No production SDK file is
modified by that shim.

## Scope of evidence

The collectors exercise provider JSONL, the desktop mobile facade, SDK public
APIs, and a loopback HTTP sidecar. SDK split-proof and HTTP lifecycle checks use
mock cryptographic backends, explicitly labeled. Their outcomes test routing,
state isolation, output projections, and error handling; they do not validate
Spartan proof generation or reblinding. Nullifier helpers are real computations.

Android wallet consent, complete OID4VP transport, third-party status-service
traffic, and native mobile proving require their own observers. The report lists
these gaps. Requester-known HTTP method/path/body-size differences are not
classified as hidden-input privacy leaks. Synthetic detector controls are kept
separate from observed integration findings.

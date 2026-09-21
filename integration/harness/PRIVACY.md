# Integration privacy campaigns

Run the same observation rules against any provider or Swiyu boundary. A campaign
checks what an observer receives, relative to a stated release policy. It does
not establish proof-system security, circuit correctness, or cryptographic
unlinkability.

## Run

From the repository root:

```sh
# Fast provider-contract rejection checks; no proof generation.
python3 integration/harness/zkbench.py privacy-run \
  --manifest integration/providers/openac/manifest.json \
  --controls --output /tmp/provider-privacy

# Existing Swiyu SDK and loopback HTTP boundaries. Proof backends are test doubles.
python3 integration/harness/zkbench.py privacy-run \
  --adapter integration/privacy_adapters/swiyu-zkid.mjs \
  --controls --output /tmp/swiyu-privacy

# Real shared facade with deliberate provider faults.
python3 integration/harness/zkbench.py privacy-run \
  --adapter integration/harness/facade_privacy.py \
  --controls --output /tmp/facade-privacy

# Analyze externally captured traces, including emulator collectors.
python3 integration/harness/zkbench.py privacy-run \
  --traces /path/to/traces.json --output /tmp/captured-privacy
```

Each command writes `privacy-report.json` and standalone `privacy-report.html`.
Exit status is 1 for findings, 2 for unavailable/inconclusive evidence or invalid
input, and 0 for completed checks without findings. Always inspect coverage;
passing observations do not imply every runtime or family was exercised.

Manifest mode optionally accepts `--presentations 2` (maximum 8). It uses the
provider's existing `source.provider_run_fixture`, prepares once, presents with
fresh nonces, verifies each result, and scans for supplied synthetic secrets.
It does not assume an age predicate or a particular proof encoding. The fixture
may add `privacy.secrets: [{"label":"holder-secret","value":"synthetic value"}]`.
The original raw credential is scanned automatically. Additional fixture axes
and lifecycle scenarios belong in a collector, since the harness cannot safely
rewrite a contributor's signed credential or witness.

For one-command provider selection, add a manifest-local collector path:

```json
{"source": {"privacy_collector": "privacy/collect.mjs"}}
```

Then `privacy-run --manifest manifest.json` uses that collector. Its provider ID
must match the manifest. Paths cannot escape the provider directory, including
through symlinks. Declared collectors own their scenario counts; `--presentations`
is reserved for the default provider-contract collector.

A provider report can import the resulting report using `provider-run
--privacy-report PATH`. The campaign provider ID must match that manifest.

## Contributor contract

A collector is a local `.py`, `.mjs`, or `.js` program that writes one JSON object
to stdout. Run diagnostics on stderr. Collectors are executable contributor code,
not a sandbox. The runner enforces a 180-second deadline and a 16 MiB combined
stdout/stderr limit, tracks observed child processes across session boundaries, closes its owned process group, and withholds raw diagnostic
output from public failures. It exports analyzed summaries rather than raw traces.
Use synthetic credentials. Raw collector stdout contains test inputs and should
not be uploaded as a public report.

```json
{
  "schema": "swiyu.privacy-traces.v1",
  "provider": {"id": "example", "title": "Example integration"},
  "cases": [{
    "id": "private-attribute-in-error",
    "family": "failure_fallback",
    "relation": "secret_scan",
    "observer": "wallet response to verifier",
    "runtime": "android-emulator",
    "evidence_kind": "integration",
    "secrets": [{"label": "hidden-attribute", "value": "SYNTHETIC-SECRET-7182"}],
    "records": [{
      "id": "attempt-1", "subject": "credential-a", "session": "session-1",
      "scope": "verifier-a", "public_context": {"claim": "eligibility"},
      "expected_outcome": "reject", "outcome": "reject",
      "view": {"error": "presentation rejected"}, "allowed_public": {}
    }]
  }]
}
```

`runtime` and `observer` must describe what was actually executed and captured.
Returning an SDK object is not observing OID4VP HTTP. An emulator with a host
prover does not measure native Android proving. `evidence_kind` is `integration`
for boundary checks, `crypto` only when the stated cryptographic execution really
occurred, and `control` for detector fixtures. A mock backend must be stated in
the scenario runtime or description.

The collector supplies observations and fixtures, never pass/fail verdicts.
`expected_outcome`, permitted values, and scope rules come from the scenario's
claim/release policy or a reference oracle, independently of provider results.
These declarations remain reviewable test assumptions; a dishonest collector
can omit evidence, so campaign success is not contributor certification.

## Observation rules

JSON pointers address `record.view` directly: `/body`, not `/view/body`.
`allowed_public` maps pointers to exact expected public values; those values are
checked before removal from a differential comparison. `opaque_paths` suppress
structural comparison of randomized fields but never exempt known secret markers
from inspection. Marking opaque bytes does not establish their privacy.

| Relation | Required evidence |
|---|---|
| `secret_scan` | Nonempty captured view; known synthetic private markers. Scan nested JSON and bounded common encodings, including base64url, hex, URL encoding, and JWT segments. |
| `equivalent` | At least two cases with the same public context and expected outcome. Remaining observed structure must agree. |
| `same` / `different` | At least two records and `compare_paths`; every selected path must exist. Use for stated lifecycle invariants, never universal proof byte equality. |
| `unlinkable` | Fresh sessions plus multiple credential subjects with equivalent permitted public information. Detect credential-specific repeated values after excluding public fields; inadequate controls remain inconclusive. |
| `scoped` | `compare_paths` containing a scoped identifier; repeats within a subject/scope and changes across scopes. Scope must derive from authenticated scenario policy. |
| `metrics` | At least eight interleaved samples per subject class, under equivalent public conditions. Detect exploratory timing/size separation; no constant-time claim. |

Families describe the scenario: `disclosure`, `hidden_branch`, `linkability`,
`failure_fallback`, `probing`, `status_access`, `session_isolation`, `diagnostics`,
`side_channel`, `prepared_state`, and `scoped_identifier`.

Use `records: []` and `skip_reason` when a required observer or capability is
unavailable. Failed functional outcomes must remain visible. Do not discard
failed runs to manufacture equivalent successful pairs. Differences in public
request method, URL, content type, consent, or policy are not hidden-input leaks.

For a hidden OR branch, construct coherently issued fixtures for A only, B only,
and both while keeping the same permitted release. For linkability, separate
same-credential repeats from independent credentials. For preparation pools,
exercise fresh sessions, cancellation, concurrency, and restart; distinguish
reusable private assignments from commitments actually sent to a verifier.

## Known boundaries of the shipped collectors

The shared facade collector tests provider error messages, codes, and verifier
reasons through the actual desktop CLI, with a deliberately faulty provider.
The SDK collector exercises local sidecar HTTP, library rejection handling,
split-wallet lifecycle, status projection, and scoped-nullifier helpers. It does
not boot Android, run the complete wallet OID4VP consent flow, capture third-party
status-service traffic, or prove cryptographic reblinding with its mock backend.
Those require additional observers and remain named gaps.

## Selected complete OID4VP flows

The claim-derived HTTP campaign is a separate execution path that records the complete selected exchanges, validates session bindings, and compares equivalent fixtures. Use [TRANSCRIPT-PROVIDERS.md](TRANSCRIPT-PROVIDERS.md); see [the property](../../docs/platform/transcript-privacy-design.md) and [the native OpenAC evidence](../../docs/platform/transcript-privacy-findings.md).

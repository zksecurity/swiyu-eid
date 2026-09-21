# Provider integration guide

A provider is a drop-in adapter that satisfies the Swiyu provider process contract. It can wrap any proof system: OpenAC, another ZK stack, a native binary, a WASM prover, a service running on localhost, or a test-only reference implementation. The harness treats all providers the same way.

## What a provider must contain

Create a directory under `integration/providers/<provider-id>/` with these files:

| File | Required | Purpose |
|------|----------|---------|
| `manifest.json` | yes | Declares provider identity, supported implementation profiles and launch command. |
| Provider executable | yes | Implements the JSONL provider protocol over stdin/stdout. |
| `support.json` | for semantic claim runs | Declares which semantic claims the provider supports and pins relevant files. |
| `README.md` | recommended | Explains build artifacts, env vars, limitations and test commands. |
| `tests/` | recommended | Provider-specific tests for artifacts and edge cases. |
| Audit report links/files | optional | Independent review evidence. The platform displays these without treating them as proof of correctness. |

Do not add semantic meaning to a `profiles` directory. Implementation profiles live in provider manifests. Semantic claims and predicates live in `integration/semantics`.

## Manifest contract

A minimal manifest looks like this:

```json
{
  "schema": "swiyu.provider-manifest.v1",
  "id": "example-provider",
  "title": "Example provider",
  "kind": "implementation",
  "profiles": ["example.profile.v0"],
  "circuits": ["example_circuit_v1"],
  "command": ["python3", "provider.py"],
  "coverage": {
    "prepare": "implemented",
    "present": "implemented",
    "verify": "implemented"
  },
  "source": {
    "certification": "none",
    "note": "Brief artifact/runtime note."
  }
}
```

Use `kind: "test-only"` for transparent fixtures, mocks or reference providers. Use `kind: "implementation"` for a real ZK-backed adapter. If the provider is intentionally partial, set `incomplete: true` and report honest operation readiness from `initialize`.

Declare every circuit ID that semantic support may reference in `circuits` or in `source.circuit_id`. The harness rejects support rows whose circuit is not independently declared by the provider manifest.

The `command` runs from the provider directory. Keep it stable and local. Prefer env vars for machine-specific artifact roots.

## Process protocol

The harness starts the provider and sends one JSON request per line on stdin. The provider writes one JSON response per line on stdout.

Every request has:

```json
{
  "protocol": "swiyu.provider.v1",
  "id": "request-uuid",
  "operation": "initialize",
  "payload": {}
}
```

Every response echoes the same `id` and uses either `status: "ok"` with `result`, or another status with `error`:

```json
{
  "protocol": "swiyu.provider.v1",
  "id": "request-uuid",
  "status": "ok",
  "result": {}
}
```

Required operations:

| Operation | Purpose |
|-----------|---------|
| `initialize` | Return supported profiles, operations, readiness and artifact status. |
| `prepare` | Parse/authenticate/precompute credential state and return an opaque handle. |
| `present` | Use a prepared handle plus verifier challenge/context to produce an opaque presentation. |
| `verify` | Verify a presentation against verifier-supplied public inputs and return a JSON boolean `verified`. |
| `cleanup` | Release handles, temp files and child processes owned by the provider. |

Return `unsupported` with `error.code: "unsupported_profile"` for unknown profiles. Return `error` with stable `error.code` for bad inputs, missing artifacts or backend failures. Never print logs on stdout; use stderr for diagnostics.

## Semantic support contract

A support file connects a concrete implementation profile to semantic claims. It should name supported claim IDs and statement digests, declare which obligations are enforced, and pin files whose contents matter for that claim.

```json
{
  "schema": "swiyu.claim-support.v0",
  "id": "example-support",
  "title": "Example semantic support",
  "supported_claims": [
    {
      "id": "example.claim.v0",
      "statement_digest": "<64 hex chars from integration/semantics>",
      "implementation_profile": "example.profile.v0",
      "circuit": "example_circuit_v1",
      "enforcement": {
        "issuer_authentication": "both",
        "metadata_profile_binding": "both",
        "credential_validity": "both",
        "holder_authorization": "proof",
        "session_binding": "both",
        "where": "proof"
      }
    }
  ],
  "artifact_pins": [
    {"path": "manifest.json", "sha256": "<64 hex chars>"},
    {"path": "provider.py", "sha256": "<64 hex chars>"}
  ]
}
```

The harness uses support files to reject stale or mismatched providers before running claim campaigns. It checks claim IDs, statement digests, implementation profiles, circuit IDs, obligation coverage and artifact pins. This does not audit the proof system or prove that a circuit exactly implements the semantic statement.

## Testing expectations

At minimum, a provider should pass:

1. Manifest validation.
2. Lifecycle smoke: `initialize`, `prepare`, `present`, `verify`, `cleanup`.
3. Failure cases: unsupported profile, malformed credential, stale handle, wrong challenge, wrong issuer/status inputs when applicable.
4. Process hygiene: no malformed stdout, no orphaned owned child processes, bounded failures.
5. Claim support validation if the provider declares semantic claims.
6. Heavy proof tests behind an explicit flag if proving is expensive.

Fast tests should not require multi-GB keys or long proofs. Put heavyweight proof/benchmark runs behind an env flag, as OpenAC does with `SWIYU_OPENAC_REAL_E2E=proof`.

## Benchmark and report expectations

Provider runs should produce machine-readable JSON and human-readable HTML. A report should show:

- provider identity and implementation profiles;
- semantic claim IDs and digests when available;
- artifact readiness and pinned files;
- operation readiness;
- per-stage timings;
- proof or presentation size;
- functional pass/fail cases;
- leakage status: `clean`, `findings`, `inconclusive` or `not_run`;
- benchmark notes and hardware/runtime caveats;
- optional audit report references.

## What remains the contributor's responsibility

The harness does not prove that a proof system is secure. It does not prove that a circuit exactly implements its stated semantics. Contributors should provide independent audits for those claims. The platform can display audit evidence, but integration tests only establish that the provider can run through the declared contract and fails closed for the cases we exercise.

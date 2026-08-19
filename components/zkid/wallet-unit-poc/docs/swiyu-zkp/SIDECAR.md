# Local verifier sidecar contract

The Java Generic Verifier keeps its existing DCQL/session state machine. For an
opt-in `x_swiyu_zkp` credential request it sends one loopback-only HTTP request
to the local proof sidecar.

The request contains:

- the opaque proof envelope;
- nonce, client ID, response URI, OAuth state, and DCQL query ID derived from
  the persisted request session;
- exact profile/circuit IDs, cutoff, frozen current time, and opaque snapshot
  ID from the signed DCQL policy; and
- allowed VCT values plus the verifier's accepted-issuer/trust-anchor policy.

The sidecar must not use proof-returned values or envelope hints as expected
policy. It resolves the envelope's `iss`/`kid` against a preloaded trusted P-256
key registry, checks the issuer/VCT policy, resolves the opaque snapshot ID to
an authoritative fresh commitment, reconstructs the exact public context, and
verifies the Spartan proof with the profile's pinned verification key.

Only this response shape is accepted:

```json
{
  "verified": true,
  "profile": "swiyu-age18-status-2k-v0",
  "circuit_id": "swiyu_age18_status_2k",
  "predicate_satisfied": true,
  "status_valid": true,
  "status_list_snapshot": "opaque-policy-id"
}
```

Java compares every returned field with its signed policy. A missing adapter,
non-loopback endpoint, timeout, non-200 response, malformed/oversized JSON,
false result, or mismatched field fails the presentation.

The frozen `current_time` is accepted only within five minutes of both request
creation and presentation receipt. The proof and snapshot are evaluated at
that exact time, while the second check prevents an old signed request from
extending a snapshot's useful lifetime.

Status-list JWT fetching and trust/key refresh are background ingestion tasks,
not presentation-time calls. The production startup factory reads bounded
local `statuslist+jwt` files, verifies each ES256 signature with a locally
provisioned issuer/kid key, checks the exact configured issuer and subject, and
evaluates `iat`/`exp`/`ttl` against the process startup time. It then derives
the fixed-depth root and runtime snapshot registry. The registry contains only
the opaque digest-derived ID, commitment, epoch/capacity, exclusive validity
boundary, and provenance digest. Raw URI, packed list, root, and credential
index do not enter the presentation path.

## Run the local research sidecar

Build the SDK, then run `openac-swiyu-sidecar <config.json>` (or execute
`dist/swiyu-zkp/sidecar-node.js` directly). The Node listener accepts only the
configured loopback host, exact POST path, and JSON content type. It bounds the
body, request duration, verification duration, and concurrent verifications;
all external failures return only `{"verified":false}`.

The production path uses the native `swiyu-profile` verifier. It holds the
1.6 GB verification key as an immutable local-file reference and symlinks it
into a private per-call directory, rather than copying it through JavaScript.
The current WASM verifier traps on this relation and is not production wiring.
A minimal configuration has this shape (all paths are local and resolved from
the configuration file). `status_lists` is the production authority input;
operator-authored commitment/root/freshness records are not accepted:

```json
{
  "listen": {
    "host": "127.0.0.1",
    "port": 7788,
    "path": "/v1/verify",
    "max_concurrent_requests": 1,
    "request_timeout_ms": 180000,
    "verification_timeout_ms": 120000
  },
  "native_backend": {
    "binary": "../../ecdsa-spartan2/target/release/swiyu-profile",
    "cwd": "../../ecdsa-spartan2",
    "temp_root": "./private-tmp",
    "verify_timeout_ms": 120000
  },
  "verifying_key": "./keys/swiyu_age18_status_2k_verifying.key",
  "issuers": [{
    "issuer": "did:example:issuer",
    "kid": "did:example:issuer#assert-key-01",
    "public_key": {
      "kty": "EC",
      "crv": "P-256",
      "x": "<unpadded-base64url-32-byte-x>",
      "y": "<unpadded-base64url-32-byte-y>",
      "kid": "did:example:issuer#assert-key-01"
    },
    "vct_values": ["https://example.ch/vct/person"],
    "trust_anchors": [{
      "did": "did:example:anchor",
      "trustRegistryUri": "https://trust.example/registry"
    }]
  }],
  "status_lists": [{
    "jwt_file": "./status-lists/person-2026-07.jwt",
    "issuer": "did:example:issuer",
    "kid": "did:example:issuer#assert-key-01",
    "subject": "https://status.example.ch/lists/person-2026-07"
  }]
}
```

Configuration JSON uses unique-key parsing and exact field sets. The factory
caps configuration, arrays, strings, paths, and each JWT file; zlib inflation
is stopped at the depth-17 profile capacity. Every status entry must name one
unambiguous provisioned issuer/kid and the exact signed subject. Duplicate
issuer/kid records, ambiguous issuer/kid/subject bindings, and duplicate
digest-derived snapshot IDs abort startup. A stale, not-yet-valid, malformed,
tampered, or wrong-key JWT likewise aborts startup instead of leaving a partial
registry.

The measured native verifier takes roughly nine seconds and peaks near 4 GB
RSS on the development machine, so the safe default is one concurrent proof.
This is a desktop research prototype, not a mobile or horizontally scalable
verification service. Raising concurrency is an explicit operator decision.

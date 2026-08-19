# Experimental ZK presentation sidecar

The `swiyu-age18-status-2k-v0` prototype is an opt-in extension of the existing
DCQL flow. A credential query enables it with `x_swiyu_zkp`; ordinary DCQL
credentials continue through the existing SD-JWT verifier.

The policy is persisted in `management.dcql_query` and included in the signed
OID4VP request object. `status_list_snapshot` and `current_time` are mandatory.
`current_time` is a Unix timestamp in seconds and must be within 300 seconds of
the verifier clock both when the session is created and when the presentation
is received. Freezing it in the signed request ensures that proof validity is
evaluated at one unambiguous instant rather than at wallet-selected time; the
receipt check prevents an old request from extending snapshot freshness.

The business verifier owns the legal-policy calculation of `cutoff_date`,
including its jurisdiction and timezone. This fixed relation proves only that
the hidden birthdate is on or before the exact supplied cutoff; it does not
silently derive "today minus 18 years" from `current_time`. The caller must
supply the intended age-18 cutoff, and the circuit profile limits its year to
`1900..2199`.

## Configuration and fail-closed behaviour

Configure an explicit loopback endpoint, for example:

```properties
swiyu.zkp.sidecar.endpoint=http://127.0.0.1:7788/v1/verify
swiyu.zkp.sidecar.timeout=120s
swiyu.zkp.sidecar.max-response-bytes=65536
```

Only `http://localhost:<port>/...`, `http://127.0.0.1:<port>/...`, and
`http://[::1]:<port>/...` are accepted. Redirects are disabled. If the endpoint
is absent, malformed, unavailable, times out, returns a non-200 status, or
returns malformed JSON, a ZK presentation is rejected. There is no fallback to
the ordinary SD-JWT path after a query opts into `x_swiyu_zkp`.

The snapshot ID is not operator-authored. Before creating the management
request, local orchestration calls the SDK's exported Node helper
`provisionSwiyuAuthoritativeStatusSnapshotFromFile(...)` with the same signed
JWT, issuer key, issuer, and subject used by sidecar startup, then copies the
returned `.id` into `x_swiyu_zkp.status_list_snapshot`. The config-file loader
derives the same deterministic value, `statuslist-jwt:<base64url SHA-256 of the
exact compact JWT>`. Loading a newer signed list yields a new ID and requires a
new management request/session; IDs must never be invented or carried across
list bytes.

## `POST /v1/verify` contract

The verifier sends the proof envelope unchanged. Every expected value comes
from the persisted session and signed DCQL request, never from envelope lookup
hints:

```json
{
  "proof_envelope": "<opaque wallet output>",
  "expected": {
    "nonce": "...",
    "client_id": "...",
    "response_uri": "...",
    "state": "...",
    "query_id": "age",
    "profile": "swiyu-age18-status-2k-v0",
    "circuit_id": "swiyu_age18_status_2k",
    "cutoff_date": "2008-07-15",
    "current_time": 1784092800,
    "status_list_snapshot": "statuslist-jwt:kQ3YmU6DAiSWxt0S_R57tVdHkZKzg538cb3qs3Tpl_o",
    "vct_values": ["..."],
    "accepted_issuer_dids": ["..."],
    "trust_anchors": [{"did": "...", "trustRegistryUri": "..."}]
  }
}
```

The local sidecar is the cryptographic authority. It must:

1. Resolve and validate the issuer key and trust policy against the supplied
   issuer constraints.
2. Resolve `status_list_snapshot` to its configured, signed Status List JWT;
   validate its signature and validity; then supply the committed root locally.
   It must not fetch status data during presentation verification.
3. Recompute the challenge and all public inputs from `expected`, verify the
   `swiyu_age18_status_2k` proof, and reject any mismatch.

The response contains no hidden credential or status-list data:

```json
{
  "verified": true,
  "profile": "swiyu-age18-status-2k-v0",
  "circuit_id": "swiyu_age18_status_2k",
  "predicate_satisfied": true,
  "status_valid": true,
  "status_list_snapshot": "statuslist-jwt:kQ3YmU6DAiSWxt0S_R57tVdHkZKzg538cb3qs3Tpl_o"
}
```

The digest in this example is illustrative; production uses the helper's value
for the exact provisioned JWT bytes.

The Java verifier independently requires exact profile, circuit, snapshot,
predicate and status equality before returning a result. The existing atomic
`PENDING -> IN_PROGRESS` session claim remains ahead of the sidecar call, so a
proof envelope cannot be verified twice for the same session.

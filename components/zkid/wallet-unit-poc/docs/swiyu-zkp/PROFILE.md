# Fixed proof profile

## Identifiers

| Field | Exact value |
| --- | --- |
| profile | `swiyu-age18-status-2k-v0` |
| circuit artifact | `swiyu_age18_status_2k` |
| proof envelope | `swiyu-zkp-proof-v0` |

Profile and circuit identifiers are intentionally distinct and are validated
as separate wire fields.

## Public statement

The single Spartan proof exposes ten canonical P-256-base-field values in this
order:

1. `expressionResult = 1`;
2. trusted issuer public-key x;
3. trusted issuer public-key y;
4. the fresh session challenge reduced modulo the P-256 scalar order;
5. the verifier's Gregorian cutoff date encoded as `YYYYMMDD`;
6. the verifier's frozen Unix time;
7. session-bound metadata SHA-256 high 128-bit limb;
8. session-bound metadata SHA-256 low 128-bit limb;
9. opaque status-snapshot SHA-256 high 128-bit limb;
10. opaque status-snapshot SHA-256 low 128-bit limb.

The verifier supplies all ten expected values. Proof-returned values are never
treated as policy input.

## Private witness and authority

Every signal not listed above is private to the proof. Some values also appear
outside the proof as bounded resolver hints; that does not make their circuit
signals public.

| Private group | Signals/data | Authority and checks | Outside-proof observability |
| --- | --- | --- | --- |
| Signed credential | padded compact-JWS signing bytes; message/header/payload lengths; period; private `nbf`, `exp`, status index; issuer signature `r` and `s^-1` | Issuer ES256 signature plus strict compact/base64url/JSON selectors | Raw credential remains in the wallet |
| Authenticated identity hints | padded `iss`, `kid`, and `vct` strings and lengths | Each is selected from the issuer-signed header/payload and included in the metadata commitment | Exact bounded strings also appear in the proof envelope so the verifier can resolve policy/key material |
| Birthdate disclosure | padded disclosure JSON, lengths, salt length, and signed digest bytes | Disclosure digest must occur exactly once in the signed `_sd` graph; claim name/date grammar and age cutoff are constrained | Birthdate, salt, tuple, and disclosure bytes are not emitted |
| Holder possession | signed `cnf.jwk` x/y base64url bytes; holder signature `r` and `s^-1` | Holder point is selected from the issuer-signed payload and verifies the canonical public session challenge | Holder key and signature are not emitted |
| Status evidence | signed private URI/index, exact two-bit value, 17 SHA-256 siblings, epoch, and list length | URI/index are selected from the signed credential; witness comes from the verified issuer-signed `statuslist+jwt`; relation requires value `VALID` and the public commitment | Credential URI/index/path/root are not emitted; the operator separately knows the provisioned list subject/cohort |
| Parser hints | all `*KeyStart`, `*Close`, and `payloadDigestStart` indices plus digit lengths | Untrusted witness accelerators only; structural selectors, parent/depth checks, bounds, and literal comparisons constrain every hint | Not emitted |

## Session challenge

The wallet and verifier hash ASCII `swiyu-show-v0`, a zero byte, then each
UTF-8 field prefixed by an unsigned 32-bit big-endian length:

1. nonce;
2. client ID;
3. response URI;
4. state;
5. DCQL query ID;
6. profile ID;
7. cutoff date;
8. frozen current time in canonical decimal;
9. opaque status snapshot ID.

The SHA-256 digest is signed by the credential's P-256 holder key and reduced
modulo the P-256 scalar order for the circuit public input.

## Metadata commitment

The metadata commitment is session-specific. Its 448-byte preimage is:

| Offset | Contents |
| --- | --- |
| 0..21 | ASCII `swiyu-age18-status-v1` then `0x00` |
| 22..53 | 32-byte big-endian canonical challenge scalar |
| 54 | `iss` byte length |
| 55..166 | `iss`, zero-padded to 112 bytes |
| 167 | `kid` byte length |
| 168..279 | `kid`, zero-padded to 112 bytes |
| 280 | `vct` byte length |
| 281..392 | `vct`, zero-padded to 112 bytes |
| 393..447 | zero reserved bytes |

The proof envelope exposes only `iss`, `kid`, and `vct` as resolver hints.
Credential-specific `nbf` and `exp` remain private; the relation proves
`nbf <= currentTime < exp`.

## Status statement

The wallet proves a 17-level SHA-256 Merkle path at the signed private index.
Leaves commit to the index and exact two-bit status value. Internal nodes are
ordered and domain-separated. The snapshot commits entry count, signed epoch,
and tree root. A final fixed record also commits the private URI and exposes
only its two SHA-256 limbs.

The presentation-time verifier request does not receive the credential URI or
caller-authored tree data. At process startup the verifier operator configures
the signed-list subject, so v0 does not hide cohort membership from that
operator. Its authoritative registry reads a bounded local issuer-signed
`statuslist+jwt`, verifies it with the exact provisioned issuer/kid key,
requires `bits == 2`, checks issuer/subject and signed time bounds, and derives
the padded tree itself. It publishes only a digest-derived opaque policy ID
plus the already-derived commitment. Raw roots and freshness metadata are not
operator configuration inputs.

`VALID` is status value 0. Values 1, 2, and 3 fail the profile.

## Parser subset

This is not a generic JSON proof. Header, payload, and disclosure bytes must be
canonical compact JSON in the exact supported subset. Structural whitespace,
escaped key spellings, duplicate semantic keys, malformed member separators,
and noncanonical base64url encodings fail closed.

## Artifact and runtime boundary

The profile's setup artifacts are generated by the native `swiyu-profile`
CLI from the final R1CS. Node callers pass `{ kind: "local-file", path }` key
references to the native backend; it creates a private per-call workspace,
symlinks the provisioned key, invokes the CLI without a shell, and removes the
workspace on success or failure. Proof verification still supplies all 320
expected public-context bytes independently.

The WASM exports remain byte-key adapters for experimentation, but the final
1.60 GB key makes that browser-targeted build fail when exercised under Node's
WebAssembly runtime. This was not an in-browser measurement. WASM setup is
intentionally not exported because setup requires the native R1CS. The 25 MB
Circom witness-generator WASM does work and produced the real final
199,663,884-byte witness.

The inherited P-256 ECDSA gadget compares `r` with the affine x-coordinate
without the standard conditional reduction modulo the scalar order. This can
reject the vanishingly rare otherwise-valid signature whose x-coordinate is
at least the scalar order; it is a completeness limitation, not a way to make
an invalid signature pass. The prototype records it rather than pretending
the upstream gadget has exact edge-case completeness.

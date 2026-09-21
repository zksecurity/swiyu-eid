# Contracts

The signed DCQL `x_swiyu_zkp` policy selects the verifier's ZK branch. Android maps the selected query and credential into `ZkPresentationRuntimeRequest`; the runtime returns an opaque envelope that follows the normal OID4VP `vp_token` path. `fixtures/mobile-runtime-v1.json` pins the cross-language request, challenge hash, proof envelope, and four experiment descriptors.

## Local mobile-runtime facade

`fixtures/local-mobile-runtime-v1.json` is the executable golden contract for the boundary that a future Android adapter will call. Its `request` contains:

- `schema`: `swiyu.mobile-runtime-facade.v1`.
- `provider_manifest`: provider selection by manifest path. Relative paths are resolved from the request file.
- `profile`: the concrete provider implementation profile.
- `credential`: opaque format and data supplied by wallet storage.
- `request_context`: challenge binding (`nonce` and `audience`).
- `inputs`: verifier policy inputs such as the cutoff date.
- `verification_context` (optional): verifier-side challenge override for adversarial tests; it defaults to `request_context`.

The `swiyu.mobile-runtime-result.v1` response contains only the opaque `presentation` and the provider's verifier decision (`verified` and `reason`). Provider launch and protocol details stay behind this facade. The fixture's `expected` object pins the deterministic test-stub output; it is scaffolding and makes no cryptographic claim.

# Slide-to-implementation matrix

This matrix distinguishes a completed research prototype from a successful
mobile deployment. A measured no-go is a valid experiment result, but it is
not relabeled as deployment success.

## Prototype A

| Slide requirement | Local implementation/evidence | Result |
| --- | --- | --- |
| Parse the swiyu SD-JWT VC | Fixed compact Swiss subset, exact profile/header/claim parsing, synthetic issuer-shaped fixture | pass |
| Verify ES256 and disclosures | Issuer P-256 signature, authenticated disclosure graph, exact `birthdate` tuple inside the final relation | pass |
| Normalize/cache | `prepareSwiyuCredential` returns an opaque authenticated prepared object | pass |
| Challenge-bound device signature | Holder P-256 signature over the full verifier session tuple | pass |
| Prove age predicate and holder possession | One fresh monolithic Spartan proof | pass |
| Verify profile, issuer key/trust, challenge/audience/replay | Strict local sidecar plus opt-in Java DCQL route and existing atomic session claim | pass |
| Reveal no raw birthdate, holder key, or disclosure bundle | Structured envelope contains only proof plus issuer/VCT resolver hints | pass |
| Keep ordinary issuance/presentation | Issuer unchanged; Java branch exists only when `x_swiyu_zkp` is present | pass |

The profile prevents replay of one verifier session. It does not implement the
separate slide-7 one-credential/one-signup nullifier idea.

## Prototype B

| Slide requirement | Local implementation/evidence | Result |
| --- | --- | --- |
| Compare sparse Merkle status | Executable depth-64 tree plus real same-Spartan non-membership component proof | pass |
| Measure sparse proof/update/witness | 180,175-byte proof and 7.964 s circuit-witness generation on the 256-issued/4-revoked proof fixture; 0.630 ms update p50 and 0.013 ms data-witness p50 on the separate 65,536-issued/1,024-revoked harness fixture | pass (desktop) |
| Evaluate zkID non-membership lookup | LeanIMT+ harness shows no presentation lookup only when nodes/public set are prefetched; root alone is insufficient | pass, conditional result |
| Evaluate TS13 adjacent pairs | Real ES256 pair harness; explicitly requires issuer-bound hidden handle and new epoch pair publication | pass |
| Hide status URI/index from verifier | The presentation relation/envelope keeps the credential-specific URI, index, path, and raw root private. The verifier operator still provisions the signed list subject and therefore knows the allowed issuer/list cohort. | partial: presentation privacy, not private cohort discovery |
| Avoid presentation timing at issuer/registry | Wallet provisions a signed list before show; sidecar derives signed snapshots at startup; show/verify make no registry request | pass |
| Keep Generic Verifier integration simple | One strict loopback request on the opt-in DCQL branch | interface pass; operationally heavy |
| Practical mobile witness/proving | Dense status component peaks at 3.44 GB RSS; full proof peaks at 7.50 GB; the browser-targeted WASM build traps when exercised under Node with the 1.60 GB key | **measured desktop/Node no-go; browser/mobile conclusion is an engineering inference** |

Thus Prototype B is experiment-complete and its selected desktop path works,
but the deck's aspirational mobile outcome is not achieved. Meeting that
outcome requires circuit/proof-system reduction, not another swiyu API seam.

# Contracts

There are two current proof contracts:

- The verifier-wired monolithic age contract is defined by
  [`x_swiyu_zkp`](../../components/swiyu-verifier/openapi.yaml), the Java
  [`HttpZkPresentationVerifier`](../../components/swiyu-verifier/verifier-service/src/main/java/ch/admin/bj/swiyu/verifier/service/oid4vp/adapters/HttpZkPresentationVerifier.java),
  and the Node [`sidecar`](../../components/zkid/wallet-unit-poc/openac-sdk/src/swiyu-zkp/sidecar.ts).
- The optimized profiles use the generic TypeScript
  [`split-proof`](../../components/zkid/wallet-unit-poc/openac-sdk/src/swiyu-zkp/split-proof.ts)
  envelope and profile-specific descriptors.

These contracts are intentionally indexed here rather than duplicated. The
next integration step is to version one shared Prepare/Show wire schema for the
Android wallet, Java verifier, and Node/native sidecar.

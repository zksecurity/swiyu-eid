# Swiyu zkID privacy adapters

Independently runnable privacy scenario collector for the existing OpenAC/Swiyu SDK.

## Run

```bash
node integration/privacy_adapters/swiyu-zkid.mjs
node --test integration/privacy_adapters/tests/test_swiyu_zkid.mjs
```

Stdout is one `swiyu.privacy-traces.v1` JSON bundle (`provider.id`: `swiyu-zkid-integration`). Import `collect()` from `swiyu-zkid.mjs` in tests.

## Boundaries recorded

- Loopback sidecar HTTP (`startSwiyuSidecarServer` + `fetch`) with a mock proof verifier.
- `SwiyuVerifierSidecarService.verifyJson` library rejections.
- `SwiyuSplitZkpWallet` prepare/show with an explicit mock split backend (not real reblinding).
- Nullifier helpers (`buildSwiyuNullifierScope`, `computeSwiyuScopedNullifier`); nonce is absent from the scope API.
- `resolveSwiyuStatusListJwt` **authoritativeSnapshot only** at the SDK projection boundary (`privateSnapshot` is not treated as a public view).

JSON pointers are relative to each record `view` (not `/view/...`). HTTP 400/413/404/415 differences under distinct public method/path/type/length are rejection metadata, not privacy oracles.

`evidence_kind` is `integration` except a test-only AND/OR `control` fixture. Real proving keys are not run; those families are skipped with reasons. Android emulator is not claimed.

This directory does not own the campaign CLI/report or harness analyzers.

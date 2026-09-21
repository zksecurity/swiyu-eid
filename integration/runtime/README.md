# Mobile runtime facade

`mobile_runtime.py` exercises the same request/presentation/verification boundary planned for Android while running the provider as a local laptop process.

From the repository root:

```bash
python3 integration/runtime/mobile_runtime.py integration/contracts/fixtures/local-mobile-runtime-v1.json
```

The command prints one `swiyu.mobile-runtime-result.v1` JSON object. It also accepts `-` to read a request from standard input. Failures are JSON on standard error with a stable `invalid_request`, `provider_unavailable`, or `provider_error` code and exit status 2.

The bundled fixture uses `providers/test-stub`. That provider is deterministic integration scaffolding, not a cryptographic implementation.

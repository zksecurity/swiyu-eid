# Integration

This folder is organized by seam. Keep concrete provider code, semantic meaning and runner logic in separate modules so contributors can add implementations without changing the harness.

| Directory | Role |
|-----------|------|
| `contracts/` | Shared protocol notes and runtime fixtures. |
| `harness/` | Local runner, provider process client, reports and campaign execution. |
| `providers/` | Drop-in provider adapters. Each provider owns its manifest and command. |
| `runtime/` | Host/runtime environment notes, including Docker and future emulator setup. |
| `semantics/` | Semantic claims, predicates, assertion catalogs, fixtures and claim tests. |
| `tests/` | Cross-cutting integration layout and repository-level checks. |
| `tools/` | Developer tools that support the integration work but are not provider runtime code. |

An implementation profile identifies a concrete adapter/artifact contract, such as OpenAC's fixed `swiyu-age18-status-2k-v0` circuit. A semantic claim describes what that adapter claims to prove. Keep those concepts separate:

- Provider manifests declare implementation profiles, circuit IDs and executable commands.
- `semantics/claims` and `semantics/predicates` define claim meaning.
- Support files connect a provider to a semantic claim and pin the files being vouched for.

Do not add semantic definitions to a profiles directory. If we need a profile index later, generate it from provider manifests and semantic support declarations instead of maintaining a second source of truth.

## Common commands

Run harness tests:

```bash
PYTHONPATH=integration/harness:integration/tools integration/semantics/.venv/bin/python -m unittest discover -s integration/harness/tests -p 'test_*.py'
```

Run semantics tests:

```bash
PYTHONPATH=integration/semantics integration/semantics/.venv/bin/python -m unittest discover -s integration/semantics/tests -p 'test_*.py'
```

Shared age-25 claim (EPFL d10 + OpenAC `swiyu_age25_jwt`):

```bash
PYTHONPATH=integration/semantics integration/semantics/.venv/bin/python -m unittest discover -s integration/tests -p 'test_shared_age25*.py'
PYTHONPATH=integration/harness:integration/semantics:integration/runtime integration/semantics/.venv/bin/python -m unittest discover -s integration/harness/tests -p 'test_transcript_shared.py'
```

Same-claim OID4VP transcript differential (Java harness per backend; OpenAC age-25 envelope is session-bound synthetic, not Spartan):

```bash
integration/semantics/.venv/bin/python integration/harness/zkbench.py shared-claim-run \
  --claim integration/semantics/claims/age25-holder-challenge.json \
  --inject hash_header,hidden_field \
  --output /tmp/swiyu-shared-age25-live
```

Run cross-cutting layout checks:

```bash
python3 -m unittest discover -s integration/tests -p 'test_*.py'
```

## Transcript privacy evidence

[Run and contribute a provider](harness/TRANSCRIPT-PROVIDERS.md) for the selected OID4VP transcript campaign. [The OpenAC case study](../docs/platform/transcript-privacy-findings.md) includes real accepted proofs, differential findings, measurements, and a standalone HTML report.

# Cross-cutting integration tests

This directory holds repository-level checks for the integration tree itself. Component-specific tests stay with their module:

- `harness/tests` checks provider process lifecycle, manifest handling, reports and claim campaigns.
- `semantics/tests` checks claims, predicates, support declarations, fixtures and leakage analysis.
- `providers/<name>/tests` checks a concrete provider adapter.
- `tools/tests` checks developer tooling.

Run these layout checks from the repository root:

```bash
python3 -m unittest discover -s integration/tests -p 'test_*.py'
```

# Integration tools

This directory contains developer tools that support integration work but are not part of the provider runtime contract.

Current tool:

- `worker_contracts.py` builds and validates structured author/reviewer handoff contracts for Cursor/Pi worker loops.

Run tests:

```bash
python3 -m unittest discover -s integration/tools/tests -p 'test_*.py'
```

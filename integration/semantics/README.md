# Complete presentation semantics

Versioned complete claims combine authenticated credential attributes, mandatory
cryptographic assertions, bounded AND/OR predicates, verifier-given inputs and a
disclosure policy. This is a reference oracle and empirical integration harness;
it does not certify a contributor's circuit or proof system.

Read [CONTRIBUTING.md](CONTRIBUTING.md) for the contract and contribution workflow.
The executable examples are [cutoff](claims/cutoff-status.json),
[composed eligibility](claims/composed-status.json), and
[age-free clearance](claims/clearance-status.json).
The shared ZK comparison claim is
[age ≥ 25 + holder/challenge](claims/age25-holder-challenge.json)
(`swiyu.shared.age25-holder-challenge.v0`), implemented by EPFL d10 and
OpenAC `swiyu_age25_jwt`.

## Run a complete claim

From the repository root, create an isolated environment once:

```sh
python3 -m venv integration/semantics/.venv
integration/semantics/.venv/bin/python -m pip install -r integration/semantics/requirements.txt
```

Then run the transparent reference provider through the local integration runner:

```sh
integration/semantics/.venv/bin/python integration/harness/zkbench.py claims-demo \
  --claim integration/semantics/claims/composed-status.json \
  --output artifacts/platform-semantics
```

Open `artifacts/platform-semantics/report.html`. Functional outcomes and privacy
findings are separate: this provider exposes fixture material and is deliberately
not a ZK implementation. Add `--inject-accept-all` to exercise incorrect provider
acceptance; mismatched verdicts produce a nonzero exit status.

From `integration/semantics`, inspect or evaluate a claim:

```sh
.venv/bin/python -m semantics.claim_cli check --claim claims/clearance-status.json
.venv/bin/python -m semantics.claim_cli explain --claim claims/composed-status.json
.venv/bin/python -m semantics.claim_cli plan --claim claims/composed-status.json
.venv/bin/python -m semantics.claim_cli evaluate --claim claims/composed-status.json \
  --fixture fixture.json --given given.json
.venv/bin/python -m unittest discover -s tests -v
```

The evaluator prints assertion/condition outcomes without echoing private values.
Plans describe generated cases; they do not persist raw credentials or witnesses.
The synthetic flat SD-JWT and SHA-256 status packages have their own identities;
they do not assert compatibility with the complete legacy OpenAC relation.

To try your own synthetic attributes from `integration/semantics`:

```python
from semantics.claims import load_claim
from semantics.fixtures import make_fixture
from semantics.assertions import evaluate_claim

claim = load_claim("claims/clearance-status.json")
bundle = make_fixture(
    claim,
    attributes={"clearance": "staff"},
    given_overrides={"required_clearance": "staff"},
)
result = evaluate_claim(claim, bundle["fixture"], bundle["given"])
print(result)  # every required assertion and the condition hold
```

Changing the attribute to `guest` while keeping the given requirement `staff`
creates a coherently signed negative case. Its cryptographic assertions still
hold; its attribute condition is false.

## Earlier age-predicate experiment

The original API below remains available independently of the complete-claim path.

- `age-at-least.v1` — Gregorian age on `reference_date` is at least `min_age`.

Descriptor: `predicates/age-at-least.v1.json`

Contributors choose a published version ID in their future presentation profile. They cannot redefine the oracle rule or descriptor digest; a trusted cutoff computed differently must not silently map to this semantic version.

This predicate alone does not authenticate SD-JWT, issuer trust, holder binding,
revocation status, or proof soundness. The complete-claim API adds explicit
assertions for those integration relationships; proof soundness remains outside
the platform's scope.

## Canonical digest

Descriptor digests use SHA-256 over deterministic JSON:

1. Recursively sort object keys lexicographically.
2. Serialize with `json.dumps(..., separators=(",", ":"), sort_keys=True, ensure_ascii=False)`.
3. Encode UTF-8 and hash.

Duplicate JSON keys and non-finite numbers are rejected at load time.

## Evaluate

```python
from semantics.evaluate import evaluate

evaluate(
    "age-at-least.v1",
    {"birthdate": "1990-01-01"},
    {"reference_date": "2020-01-01", "min_age": 18},
)
# -> {"status": "ok", "value": True}
```

Unknown predicate IDs return `{"status": "unsupported"}` (not `false`). Invalid inputs return `{"status": "invalid_input"}` without echoing private values.

## CLI

Run from the `integration/semantics` directory (the package root containing `semantics/` and `predicates/`):

```bash
cd integration/semantics
python3 -m semantics.cli check
python3 -m semantics.cli evaluate --input payload.json
echo '{"predicate":"age-at-least.v1","private_inputs":{"birthdate":"1990-01-01"},"parameters":{"reference_date":"2020-01-01","min_age":18}}' | python3 -m semantics.cli evaluate
python3 -m semantics.cli vectors
```

Shell stdin usage reads one JSON object with exactly `predicate`, `private_inputs`, and `parameters` root keys and prints one result object. No private input persistence is performed.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

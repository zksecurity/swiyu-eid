# Contributing a complete claim

A claim describes what acceptance is supposed to establish. The provider's
support declaration separately says which obligations its proof and verifier
enforce. Passing an empirical campaign does not certify that declaration or
prove that the circuit implements the claim.

Start with a file in `claims/`. There are three examples:

| File | Attribute condition |
| --- | --- |
| `cutoff-status.json` | Birthdate is on or before the given cutoff |
| `composed-status.json` | Cutoff holds AND (nationality is in the given set OR residence equals the given value) |
| `clearance-status.json` | Clearance equals the given value; no age condition |

Each example also requires issuer authentication, expected metadata, credential
validity, holder authorization, request binding and a status check. Those
requirements surround the entire attribute condition. They cannot be bypassed
by putting a permissive condition on the other side of an OR.

## Bind the attributes and inputs

Attribute aliases refer to exact top-level disclosure names in one authenticated
credential. For example:

```json
{
  "attributes": {
    "clearance": {
      "credential": "eid",
      "path": ["clearance"],
      "type": "utf8@1"
    }
  },
  "given": {
    "required_clearance": { "type": "utf8@1" }
  },
  "where": {
    "predicate": "value.equals@1",
    "args": {
      "left": { "attribute": "clearance" },
      "right": { "given": "required_clearance" }
    }
  }
}
```

This is a fragment explaining the condition, not a complete runnable claim.
Retain the complete claim's packages, credential, required assertions and release
policy. A new condition using existing operators needs no new runner branch.

`given` means supplied independently by the verifier or harness. An expected
issuer record includes a public key, issuer/key identifiers and allowed types.
Time, session context and an authoritative status reference work the same way.
The provider cannot substitute its own values for the frozen expected record.

The complete reference statement consists of these obligations plus the
attribute condition:

| Assertion | Meaning in the reference package |
| --- | --- |
| `credential.authentic@1` | The credential signature verifies under the given issuer key; declared attributes come from its authenticated disclosures. |
| `credential.expected-metadata@1` | Signed issuer/key identifiers and credential type match the given issuer record and allowed types. |
| `credential.valid-at@1` | The given time is at or after the signed not-before time and strictly before expiry. |
| `holder.signature-valid@1` | The key authenticated in the credential verifies the holder signature over the expected context digest. |
| `presentation.context-bound@1` | The presentation context equals the independently derived digest of the claim identity and complete given record. |
| `status.zero-at-reference@1` | The authenticated credential's status location proves a zero bit under the given, fresh status root. |

The first five are mandatory in this package. A claim may omit status explicitly;
that produces a distinct statement identity and makes no status assertion.
An assertion's local `id` is a reference label. Its versioned `assert` operation
defines its meaning, so renaming the label does not require new evaluator code.

The first scalar types are exact UTF-8 text, uppercase two-letter ASCII codes,
Gregorian dates in 1900–2199, and unsigned 64-bit integers encoded as canonical
decimal strings. There is no implicit case folding, Unicode normalization,
string-to-number conversion or timezone interpretation. Sets contain at most
16 distinct values of a supported scalar type. Attribute aliases cannot shadow
the reserved metadata names `issuer`, `key_id` or `credential_type`.

## Compose predicates

The first catalog contains exact equality, bounded set membership and inclusive
date comparison. Combine leaves with `all` and `any`:

```text
all
  date.on-or-before(attribute birthdate, given cutoff)
  any
    value.in-set(attribute nationality, given allowed_nationalities)
    value.equals(attribute residence, given required_residence)
```

All declared attributes must be present and well typed, including attributes on
an OR branch that does not determine the result. Empty groups, duplicate sibling
expressions, unknown operations and incompatible operand types are rejected.
The current limits are one credential, 16 attributes, 16 required assertions,
32 predicate leaves, depth four, and two to eight children per Boolean group.
Claim files and concrete given records are limited to 64 KiB each.

Use given inputs for comparison parameters. The executable first version does
not accept predicate constants, NOT, arithmetic, optional presence, nested
attribute selection or joins between credentials. New operations require their
own reviewed definition, evaluator and tests; a provider manifest cannot install
an oracle or redefine an existing operation.

## Understand the cryptographic package

The executable package is `platform.sd-jwt-es256@1`, with
`platform.presentation@1` assertions. It authenticates flat SD-JWT disclosures
under a given P-256 issuer key. The holder signs the exact SHA-256 digest of the
domain-separated canonical `{statement_digest, given}` record, using ECDSA over
that already computed digest. The whole given record is covered, including new
condition parameters.

This first format has a deliberately closed input domain: flat scalar
disclosures, a fixed metadata structure, and a supplied disclosure for every
signed disclosure hash. It does not yet cover arbitrary nested SD-JWT credentials
or presentations that omit unrelated disclosures. That restriction belongs to
the package identity and must stay visible in comparisons.

The synthetic status relation uses a given SHA-256 Merkle root. A leaf commits
to its index and bit; internal nodes have a separate domain prefix. The index
and status URI must match the authenticated credential. The path must prove a
zero bit under the given root, and the given snapshot must still be fresh.

These package names deliberately differ from the exact legacy OpenAC profile.
They exercise real reference cryptography but do not claim compatibility with
OpenAC's circuit, status commitment or public-input encoding. The older
`age-at-least.v1` API remains available as a separate predicate experiment.

## Declare disclosures and enforcement

`release` describes what the verifier may learn. The example claims permit the
acceptance result and authenticated issuer/key/type metadata. Their request
digest is an explicitly declared derived public output. The successful OR branch
stays hidden. The current decoder checks known structured envelopes. Differences
in opaque proof bytes alone are inconclusive: randomized proofs may differ for
the same public result. General canary scanning inside arbitrary proof encodings
and statistical timing analysis remain later work.

A provider declares every required assertion and the complete `where` tree as
enforced by `proof`, `verifier` or `both`. `both` means each location independently
enforces the complete obligation. Wallet prechecks do not establish what an
adversarial presentation's verifier will reject. The first implementation accepts
whole-obligation declarations; split enforcement needs a future reviewed
subcheck definition.

Optional audit references describe additional evidence. Local experiments need
no public registration. Public submission of an implementation remains separate
from reviewing executable changes to the shared oracle catalog.

## Run a local registration

Keep the claim, provider manifest and support declaration in dedicated files.
Use `semantics.claim_cli check` to obtain the exact statement digest. Add that
ID/digest to `supported_claims` in the support declaration and declare every
required assertion ID plus `where`. A per-claim `enforcement` map allows one
provider to register claims with different assertion labels. The global fallback
map must match the selected claim exactly.

The provider manifest selects the executable command; the support declaration
pins its artifacts. A source or artifact change requires an explicit reviewed
pin update. From the repository root, the local runner accepts:

```bash
integration/semantics/.venv/bin/python integration/harness/zkbench.py claims-demo \
  --claim /absolute/path/to/claim.json \
  --manifest /absolute/path/to/manifest.json \
  --support /absolute/path/to/support.json \
  --output /absolute/path/to/local-results
```

This runner currently uses the synthetic reference profile and fixture contract.
Wrapping a different circuit requires its contributor-owned adapter and a
compatible registered claim package. Copying a support declaration alone does
not make an arbitrary proof format compatible. The older neutral JSONL contract
remains the process boundary for that work.

## Keep identities and evidence honest

The statement digest pins the claim and its semantic dependencies. Provider
artifacts and enforcement declarations have a separate implementation identity.
A campaign additionally identifies its realized fixtures, given inputs, recipes
and execution configuration. Changing a fixture does not change the parameterized
claim. Refactoring pinned semantic code may conservatively change the statement
identity; the platform does not try to prove equivalence between versions.

Source-pin maintenance is explicit. Review a semantic change and its tests
before updating the catalog pins. Never repair stale pins automatically while
evaluating a submission. A readable claim ID alone is insufficient for matching
implementations: compare the exact statement digest too.

Use synthetic material in campaigns. Derive expected outcomes before running the
provider and reevaluate the whole claim after mutations. A changed OR leaf need
not make the condition false. A wallet refusal, prover failure, verifier rejection
and execution error are different observations. Missing coverage stays visible.

The transparent reference provider is a harness demonstration: it exposes fixture
material and must produce privacy findings. It shares the reference evaluator,
so its functional results are not independent evidence about a ZK system.

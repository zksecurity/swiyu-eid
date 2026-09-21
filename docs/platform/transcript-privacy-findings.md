# OpenAC: accepted proofs with distinguishable presentation flows

The 2026-09-15 native campaign produced four distinct fresh OpenAC proofs. All four submissions returned HTTP 200 and reached Swiyu's `SUCCESS` management state. The clean pair satisfied the declared transcript relation. Deliberately leaking transport wrappers violated that relation while proof verification still succeeded.

Open [the standalone HTML report](evidence/2026-09-15-openac-transcript/report.html), [machine-readable results](evidence/2026-09-15-openac-transcript/report.json), or [execution checks](evidence/2026-09-15-openac-transcript/execution-checks.json).

## Concrete contribution

The harness connects a pinned semantic claim and permitted releases to executable privacy relations over selected complete Swiyu OID4VP HTTP flows. Contributors supply coherent signed fixtures and a provider adapter; the common harness classifies those fixtures, drives fresh sessions, captures the exchanges, measures stages, and locates distinctions outside its explicit normalization policy.

The tested relation is: **equal declared public meaning should yield equivalent selected observer transcripts**. Its value is a reproducible counterexample where the cryptographic verifier accepts but the surrounding protocol leaks. This is an engineering contribution to provider integration testing. It does not claim priority over all relational or metamorphic security testing; see [the design and related work](transcript-privacy-design.md).

## Experiment

Two synthetic signed credentials differ in birth date and status-list index. Both satisfy the same pinned claim: authentic credential under the supplied issuer, expected metadata, validity at the supplied time, holder/session binding, valid native status, and birth date at or before the supplied cutoff. The claim identifier retains the existing `age18` profile name; the predicate uses an explicit cutoff (`2007-06-15`), not an independently calculated current-age rule.

The same issuer, holder key, credential type, verifier, cutoff, and status snapshot are used throughout. Nonce, state, callback request identifier, proof randomness, and request-object issuance time vary with fresh sessions. The fixture classifier independently checks signature, metadata, validity, and supported attribute predicates. The actual submitted verifier evaluates the native holder/status relations. This separation is disclosed in the report.

Each session records four complete selected application HTTP exchanges:

1. Create the verification request through the management endpoint.
2. Fetch its signed request object.
3. Submit the DCQL presentation in an OID4VP `direct_post` form.
4. Read the verifier's final management result.

Headers, URLs, methods, response codes, body sizes, nested bodies, and order are captured. Opaque proof bytes retain their measured length; extra siblings and unknown identifiers remain comparable. Fresh values are checked against the session before renaming. Response Date and absolute request-object issuance time are explicit clock exceptions; request-object validity duration remains visible. Compact JWS signatures are an explicit algorithm/length assumption of the comparator.

| Campaign | Native verifier | Compared pairs | Transcript result |
|---|---|---:|---|
| Clean credentials A/B | 2 accepted | 1 | No findings in these observations |
| Injected transport A/B | 2 accepted | 1 | Private disclosure and unexplained identifier differences |

The injected integration adds the compact SD-JWT to the form field `x_swiyu_wallet_tag` and its SHA-256 digest to the `X-Swiyu-Wallet-Correlation` header. These are deliberately faulty integration behavior, not defects found in unchanged OpenAC code.

The generic decoder exposes differences in the credential's disclosed birth date, status index, and disclosure digest; marker scanning also detects the raw private disclosure. The differential comparison catches the hash header even though it contains no recognizable private value. Body size and Content-Length also differ. The report records each difference's boundary and path, without exporting raw credentials or proof bodies.

The digest is a plausible credential correlation mechanism, but this two-credential experiment establishes a distinction only. It does not independently establish repeated-session or cross-verifier linkability.

## Measurements

| Measurement | Observed values |
|---|---|
| Distinct fresh proofs | 4 |
| Proof size, measured from presentation leaf | 315,967 bytes each |
| Witness size, provider-reported from generated buffer | 199,642,572 bytes each |
| Prepare | 6–74 ms |
| Present, including witness construction and native proving | 44.111–50.543 s |
| Submit, Swiyu processing, and native verification | 14.546–19.232 s |
| Selected HTTP exchanges | 16 total |

These are four laptop observations with two native worker threads. They do not characterize a timing distribution or phone performance. The harness cross-checks reported proof size against actual bytes; witness size is supplied by the adapter, whose measurement wraps the actual witness buffer.

## Runtime and remaining boundary

The run uses the real existing OpenAC WASM witness calculator, native prover, proving/verifying keys, SDK policy checks, and native verifier. The Java transport invokes production Swiyu controllers and services, including request signing, DCQL handling, and sidecar verification. Its JDK HTTP adapter and in-memory repository are test infrastructure. Issuer and status data are provisioned locally.

This run does not execute Android, Spring HTTP dispatch/Bean Validation, deployment filters, TLS, or live issuer/status lookups. Sidecar traffic, unselected wallet traffic, and process logs are not included in this observer transcript. The report therefore establishes the selected integration case, not complete deployed-wallet privacy.

During integration, a ten-second timeout introduced by the test transport rejected valid proofs before native verification finished. The harness now preserves the production 120-second timeout, with a regression test covering verification beyond ten seconds. This was a harness bug, not an OpenAC privacy finding.

The shared transcript engine and report have no OpenAC predicate branches. The current credential classifier supports SD-JWT ES256 and bounded release types. A distinct zkID credential format needs the corresponding classifier support, and a different Swiyu profile needs verifier admission/routing. No zkID execution is claimed here.

## Reproduce

Follow [the provider guide](../../integration/harness/TRANSCRIPT-PROVIDERS.md), including artifact roots and local runtime prerequisites. Add `--inject hash_header,hidden_field` to generate both campaigns. Omit it for baseline-only provider evaluation. Every session generates a fresh proof. Raw captures are optional local debugging artifacts; the retained evidence here is sanitized.

## Validation

The final run passed 181 Python harness tests, 8 integration layout/runtime checks, 5 Java transport tests, and 3 sidecar adapter tests. The native campaign independently produced four accepted fresh proofs. [Validation results](evidence/2026-09-15-openac-transcript/validation.json) record the counts and command. Regression coverage includes private disclosures, unknown identifiers, incomplete captures, malformed/repeated fields, fresh-session binding, proof-size disagreement, decoder bounds, clock lifetime preservation, report redaction, and runtime cleanup.

Independent reviews challenged the comparison policy and integration boundaries. The final review had no blocking findings; its witness provenance and clock-scope notes are reflected in the report.

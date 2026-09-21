# Plug a provider into transcript privacy testing

The harness compares complete selected presentation flows for credentials with the same approved meaning. It runs the provider, measures stages, captures HTTP exchanges, classifies fixtures independently, and writes an HTML report. The provider does not supply the verdict or decide which observations disappear.

## Contributor files

1. Implement the existing JSONL provider interface: `initialize`, `prepare`, `present`, `verify`, `cleanup`. `present` returns the presentation string and measured `artifact_sizes.proof` / `artifact_sizes.witness` in **bytes** when available. Missing measurements stay missing; do not substitute encoded-envelope size.
2. Declare the supported semantic claim in `support.json`, with its statement digest, implementation profile, circuit identifier, enforcement descriptions, and source/artifact pins. Claims contain the issuer, holder, validity, session, status, and attribute assertions that the provider claims to enforce. The harness is not a circuit audit.
3. Add a fixture factory and register it as `manifest.json → source.transcript_fixture`. The OpenAC example is `integration/providers/openac/transcript-fixture.mjs`. It emits one `swiyu.transcript-fixture.v1` JSON document on stdout. Use synthetic credentials and test keys only.
4. Provide at least two coherent variants: each includes `id`, the signed `credential`, canonical semantic `given`, and the provider's `prepare`, `present`, and `verify` inputs. Vary hidden data while keeping the intended public policy fixed. The harness authenticates the credentials and evaluates the supported predicates; a factory label saying “equivalent” is not evidence.
5. Include the actual `dcql_query`, `mapping.query_id`, `mapping.challenge_fields`, and `proof_path` in the fixture document. `challenge_fields` maps provider challenge names to fetched request-object names. `proof_path` points to the scalar proof bytes inside a decoded envelope, for example `/proof`. The harness adds the outer form/DCQL path and validates the leaf. It never exempts the whole `vp_token` object.
6. Register `source.transcript_sidecar` for automatic local startup. The command accepts `--fixture PATH --ready-file PATH`, listens on loopback, and writes a readiness JSON object containing `url`. It must implement the verifier-side HTTP contract using the provider's real verifier, supplied issuer policy, and status authority inputs. Reject malformed requests before cryptographic execution. The OpenAC example delegates policy and proof checking to the existing SDK; its small HTTP wrapper is test infrastructure.
7. Pin the new contributor files in `support.json`. Supply an independent audit report as additional provenance when one exists; passing these tests is not an audit.

## Fixture inputs

Use the claim's actual given names. The supported SD-JWT ES256 classifier resolves issuer and time operands from the claim's assertion graph and evaluates the predicate tree, including AND/OR structure. The current release model supports acceptance, issuer, key identifier, and credential type. Unsupported releases fail closed.

For the native OpenAC status adapter, `status_snapshot.commitment` is the canonical 64-digit hexadecimal concatenation of its high/low 128-bit public commitment limbs. Preserve the actual epoch, list length, and authority metadata. Do not replace the native root with a dummy reference root to satisfy validation. The classifier validates this public envelope, while the real submitted verifier checks the native holder/status relation.

Prepare inputs remain private. For every session the harness fetches a new request, maps its nonce, state, verifier identifier, and callback into the provider challenge, and creates a fresh proof. Reusing a proof across new nonces is not a valid benchmark shortcut.

## Run locally

Activate the semantic harness environment described in `integration/semantics/README.md`. For the existing OpenAC artifacts, from the repository root:

```sh
export SWIYU_OPENAC_ARTIFACT_ROOT="$PWD/components/zkid/wallet-unit-poc/openac-sdk"
export RAYON_NUM_THREADS=2
export SWIYU_OPENAC_KEYS_ROOT="$PWD/components/zkid/wallet-unit-poc/ecdsa-spartan2"
export SWIYU_OPENAC_TEMP_ROOT="/tmp/swiyu-transcript-prover"
mkdir -p "$SWIYU_OPENAC_TEMP_ROOT"

integration/semantics/.venv/bin/python integration/harness/zkbench.py provider-run \
  integration/providers/openac/manifest.json \
  --flow oid4vp \
  --claim integration/semantics/claims/openac-age18-status-2k.json \
  --output /tmp/swiyu-transcript-report
```

The local Java transport requires a working JDK and Maven; `integration/runtime/transcript/java/run-harness.sh` builds the production verifier classes and the HTTP test adapter. The adapter invokes production controllers and services with an in-memory repository. It does not run the full Spring HTTP dispatch, deployment filters, or Bean Validation. Issuer and status inputs are provisioned locally.

This selects the transcript campaign and its stage measurements. It starts the local Java verifier harness and the registered sidecar, then stops its owned processes. Existing proving artifacts must already be built. No phone is needed.

Add `--inject hash_header,hidden_field` to validate detector sensitivity against deliberate transport regressions. These sessions are reported separately from the baseline and create fresh proofs. The hash header is deliberately not a recognizable private marker: the differential comparison must catch its change.

## Shared claim, two circuits

EPFL `d10_swiyu_jwt` and OpenAC `swiyu_age25_jwt` both register `swiyu.shared.age25-holder-challenge.v0`. The shared-claim campaign runs both through the same selected Swiyu OID4VP flow (management create, request object, `direct_post`, management result) and compares the complete observer transcripts.

Within each backend it still checks the A/B hidden-birth-date relation. Across backends it exempts only implementation identity: `x_swiyu_zkp.profile`, `circuit_id`, EPFL issuer coordinates, proof length, and message size. Extra form fields, correlation headers, and hidden fixture markers remain findings.

```sh
integration/semantics/.venv/bin/python integration/harness/zkbench.py shared-claim-run \
  --claim integration/semantics/claims/age25-holder-challenge.json \
  --inject hash_header,hidden_field \
  --output /tmp/swiyu-shared-age25-live
```

The default starts one Java OID4VP harness per backend, with that backend's sidecar. Request objects are locally signed. `direct_post` is the production form. EPFL presents native UltraHonk proofs (`nargo`/`bb`). OpenAC age-25 proving keys are not packaged, so that backend presents a session-bound synthetic envelope with the real OpenAC wire keys (`version` / `profile` / `circuitId` / `proof` / `lookup`). The sidecar checks the session binding. That is not a Spartan proof and is not cryptographic evidence. Loopback host/port differences between the two harness processes are treated as test infrastructure.

`--fixture-only` keeps the in-process HTTP mock and opaque envelopes for unit tests. `--verifier-base` points both backends at one already-running verifier; that only works if the sidecar behind it accepts both envelope types.

`--verifier-base URL` selects an already running verifier. `--fixture-document PATH` supplies a previously generated fixture document when coordinating an external sidecar. Runtime provenance must be reported accurately; a reachable URL alone does not prove which implementation is running.

`--retain-private` saves synthetic credentials and raw observations for local debugging. Keep those files local. The default public report contains selected summaries, measured sizes, and difference locations, not raw private credentials or full proof payloads.

## What a clean result means

The submitted fixtures had the same permitted predicate outcome and disclosure values; the verifier accepted them as expected; and these complete selected HTTP flows did not differ outside the recorded normalization policy. A missing exchange, invalid fixture, unsupported decoder, or absence of comparable pairs is not a pass.

The report keeps proof lengths, message sizes, headers, extra fields, endpoints, and flow structure observable. It validates fresh nonce/state values before normalization. Server Date values, absolute request-object issuance time, and timing distributions are explicitly unassessed channels in the small structural campaign. Request-object validity duration remains observable. Proof sizes are measured from the presentation proof leaf and checked against provider reports; witness sizes are provider-reported (the OpenAC adapter measures its generated witness buffer). Measurements are laptop observations, not phone performance estimates.

## Scope for another provider, including zkID

The transcript classifier, observer capture, decoder, comparison rules, and report do not contain OpenAC predicate logic. Another provider supplies its signed fixtures, claim mapping, proof leaf, provider process, and verifier-side adapter. A split prepare/show design can be measured through the same lifecycle; additional prepared-state or cross-verifier privacy relations require their corresponding fixture variations and selected flows.

This milestone's executed Java flow uses Swiyu's existing fixed ZK profile. A different statement or protocol profile, such as a distinct zkID integration, also needs admission and routing in Swiyu's verifier. These tests do not make that unsupported profile work automatically. No zkID cryptographic run is claimed by the OpenAC report.

For the complete property and its limits, see `docs/platform/transcript-privacy-design.md`.

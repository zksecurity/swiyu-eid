# EPFL native providers (d10 default, c05 explicit)

Native `eid-privacy/zkp-pocs` circuits at commit `d58bc79dd65ea6560bf199ad332d3ba3746c1c08` (MPL-2.0), `nargo 1.0.0-beta.13` + `bb 1.2.1` UltraHonk. The d10 provider has a bounded semantic claim and a laptop OID4VP test integration. Android was not run for this EPFL campaign.

## d10_swiyu_jwt (`epfl-d10-swiyu-jwt-age25-v0`)

Default manifest profile. From `main.nr`:

- Private: SD-JWT payload, issuer ECDSA signature, birth_date salt/value/offsets, device signature.
- Public (97 Noir fields, 3104 bytes): `issuer_pub_x`/`issuer_pub_y` (32 u8 fields each, value in LSB), `now_date` u32 YYYYMMDD, `challenge_nonce` (32 u8 fields).
- Checks issuer ES256, birth_date disclosure digest binding, `now_date >= birth + 25*10000`, holder ECDSA over `challenge_nonce`.
- Does **not** check status/revocation or OID4VP request/response binding.

`prepare` takes a **local** `Prover.toml` path (`format: epfl-d10-prover-toml`). The file is not in this repo. `present` runs `nargo execute` + `bb prove` on a **private copy** (directory mode `0700`, files `0600`) and does not rotate the nonce (holder cannot re-sign here). The static demo nonce is **not** a fresh OID4VP challenge. Owned `present-*` / `verify-*` scratch is deleted on success, failure, and `cleanup`; caller files and cached `compiled/` + `vk/` stay. `artifact_sizes.witness` is the **gzip** `.gz` byte length from `nargo execute`, not an uncompressed witness. zkbench `witness`/`prove` stages are `covered_by_present` (null ms); they are not independent clocks.

`verify` encodes the 97 fields from caller `request_context` (`issuer_pub_x`, `issuer_pub_y`, `now_date`, `challenge_nonce`) and calls `bb verify` with the **pinned VK** written at compile time. Envelope `public_inputs_b64` / `vk_b64` are ignored.

## c05_age_verification (`epfl-c05-age18-fixedcred-v0`)

Explicit profile. Fixed 218-byte credential, public unix `current_date`, age ≥ 18 via `31557600` seconds/year. No signatures.

Provider-run with this profile: point a copy of the manifest `source.provider_run_fixture` at `provider-run-fixture-c05.json`. The default factory is `provider-run-fixture.js` (d10). There is no `provider-run-fixture.json` alias.

## Bounded semantic claim + OID4VP transcript scope

- Claim `swiyu.epfl.d10-age25-jwt.v0` with pinned `integration/providers/epfl/support.json`.
- Synthetic `dc+sd-jwt` transcript factory (`transcript-fixture.py`) rotates fresh holder challenges; static `Prover.toml` path does not.
- Java JDK HTTP adapter + EPFL sidecar verify presentations in owned OID4VP transcript campaigns.
- `proof_b64` on the wire is canonical unpadded base64url; transcript equivalence treats other encodings as `opaque_invalid`.
- Not OpenAC, not Android, not full Spring/TLS. Native negative tests are not differential leakage findings.

## Run

```bash
export PATH="/tmp/swiyu-epfl-20260915/owned/scratch/toolchain/bin:$PATH"
export HARDWARE_CONCURRENCY=2 RAYON_NUM_THREADS=2 OMP_NUM_THREADS=2 BB_NUM_CPUS=2
export SWIYU_EPFL_D10_PROVER_TOML="/tmp/swiyu-epfl-20260915/d10/circuit/Prover.toml"
# or: export SWIYU_EPFL_SOURCE_ROOT="<zkp-pocs checkout>"

# Run both commands from the swiyu-eid repository root.
python3 -m unittest discover -s integration/providers/epfl/tests -p 'test_*.py' -v

python3 integration/harness/zkbench.py provider-run \
  integration/providers/epfl/manifest.json \
  --output /tmp/swiyu-epfl-20260915/report
```

bb 1.2.1 has no `--threads` flag; with `RAYON_NUM_THREADS=2` it still spawned 8 workers in the d10 probe. Keep the process under `guard.py`.

Do not commit `Prover.toml`, JWTs, or witnesses. Reports must not embed them.

Final validation: 15 native adapter tests passed after the cleanup fix; the default d10 provider-run was regenerated successfully. See evidence/2026-09-15-epfl-provider/validation-final.json.

## Reproduce the completed differential campaign

Run from the `swiyu-eid` repository root with the pinned toolchain installed. The following paths match the completed local run:

```bash
export SWIYU_EPFL_TOOLCHAIN=/tmp/swiyu-epfl-20260915/owned/scratch/toolchain/bin
export PATH="$SWIYU_EPFL_TOOLCHAIN:$PATH"
export SWIYU_EPFL_CIRCUIT_ROOT="$PWD/integration/providers/epfl/circuit"
export SWIYU_EPFL_WORK_ROOT=/tmp/swiyu-epfl-privacy-20260915/owned/scratch/epfl-work
export RAYON_NUM_THREADS=2 OMP_NUM_THREADS=2 HARDWARE_CONCURRENCY=2 BB_NUM_CPUS=2

GUARD_MIN_MEM_FREE_PCT=25 GUARD_MAX_SWAP_GROWTH_MIB=2048 GUARD_MIN_DISK_FREE_GIB=16 \
python3 /tmp/swiyu-epfl-privacy-20260915/guard.py run \
  --label epfl-reproduce --kind heavy --timeout 600 -- \
  "$PWD/integration/semantics/.venv/bin/python" \
  "$PWD/integration/harness/zkbench.py" provider-run \
  "$PWD/integration/providers/epfl/manifest.json" --flow oid4vp \
  --claim "$PWD/integration/semantics/claims/epfl-d10-age25-jwt.json" \
  --support "$PWD/integration/providers/epfl/support.json" \
  --inject hash_header,hidden_field --output /tmp/swiyu-epfl-reproduce
```

This makes four fresh proofs: two hidden birth-date variants with equal public claim meaning, then the same pair with deliberate transport leaks. The recorded run accepted all four, compared the baseline as equivalent, and detected the injected credential disclosure and hash identifier. [Completed report](evidence/2026-09-15-epfl-transcript/campaign-report.html).

The synthetic factory signs a reference `dc+sd-jwt` credential and a native `typ=JWT` circuit signing input over the corresponding payload. This controlled test mapping does not establish compatibility with arbitrary existing Swiyu credentials. Issuer keys are test fixtures. The claim covers no revocation or expiry checks; the verifier adapter derives the circuit challenge from persisted session and policy inputs.

#!/usr/bin/env bash
set -euo pipefail

ROOT=/workspace
SDK="$ROOT/openac-sdk"
CIRCOM="$ROOT/circom"
NATIVE="$ROOT/ecdsa-spartan2"
BENCH="$ROOT/benchmark/docker"
RESULTS=/results
RAW="$RESULTS/raw"
export BENCH_COMMAND_LOG="$RESULTS/command-log.jsonl"

RESIDENCE_DIRECTORY="$ROOT/benchmark/fixtures/residence-municipality-directory-2025-01-01.json"
RESIDENCE_DIRECTORY_SHA256="2a510d6f7de86e40a8d584daba5985422728317619f1e9225bf3c3e28c40905c"
if [[ "$(sha256sum "$RESIDENCE_DIRECTORY" | awk '{print $1}')" != "$RESIDENCE_DIRECTORY_SHA256" ]]; then
  echo "frozen residence municipality directory hash mismatch" >&2
  exit 1
fi

mkdir -p "$RAW/controls" "$RAW/control-workers" "$RAW/production-control" \
  "$RAW/sdk-host" "$RAW/nullifier-state" "$RAW/age" "$RAW/residence" \
  "$RAW/scoped-nullifier"
node "$BENCH/collect-metadata.mjs" "$RESULTS/metadata.json" start
finish_metadata() {
  local status=$?
  node "$BENCH/collect-metadata.mjs" "$RESULTS/metadata.json" finish "$status" || true
}
trap finish_metadata EXIT

record() {
  node "$BENCH/run-recorded.mjs" "$@"
}

run_control_worker() {
  local profile="$1"
  local run="$2"
  local directory="$RAW/control-workers/$profile"
  mkdir -p "$directory"
  record --id "control-$profile-worker-$run" --cwd "$SDK" \
    --stdout "$directory/worker-$run.json" -- \
    node --experimental-strip-types scripts/benchmark-swiyu-no-zk.ts \
      --profile "$profile" --worker --run "$run" --iterations 1000
}

run_witness() {
  local profile="$1"
  local run="$2"
  case "$profile" in
    age)
      record --id "age-witness-$run" --cwd "$SDK" \
        --stdout "$RAW/age/witness-$run.log" \
        --env SWIYU_SPLIT_BENCHMARK=1 \
        --env SWIYU_PACKED_STATUS_PRIMARY=1 -- \
        "$SDK/node_modules/.bin/vitest" run \
          tests/swiyu-zkp/split-benchmark-witness.test.ts --reporter=dot
      cp "$CIRCOM/build/swiyu_split_benchmark/fixture.json" \
        "$RAW/age/witness-$run.json"
      ;;
    residence)
      record --id "residence-show-control-witness-$run" --cwd "$SDK" \
        --stdout "$RAW/residence/witness-show-control-$run.log" \
        --env SWIYU_RESIDENCE_BENCHMARK=1 \
        --env SWIYU_PACKED_STATUS_PRIMARY=1 \
        --env SWIYU_RESIDENCE_RUNS=1 -- \
        "$SDK/node_modules/.bin/vitest" run \
          tests/swiyu-zkp/residence-benchmark-witness.test.ts --reporter=dot
      record --id "residence-optimized-prepare-witness-$run" --cwd "$SDK" \
        --stdout "$RAW/residence/witness-optimized-prepare-$run.log" \
        --env SWIYU_RESIDENCE_COMBINED_BENCHMARK=1 \
        --env SWIYU_RESIDENCE_COMBINED_RUNS=1 -- \
        "$SDK/node_modules/.bin/vitest" run \
          tests/swiyu-zkp/residence-combined-benchmark-witness.test.ts --reporter=dot
      node "$BENCH/merge-residence-witness.mjs" \
        "$CIRCOM/build/swiyu_residence_benchmark" \
        "$CIRCOM/build/swiyu_residence_combined_benchmark"
      cp "$CIRCOM/build/swiyu_residence_combined_benchmark/witness-runs.json" \
        "$RAW/residence/witness-$run.json"
      ;;
    scoped-nullifier)
      record --id "scoped-nullifier-witness-$run" --cwd "$SDK" \
        --stdout "$RAW/scoped-nullifier/witness-$run.log" \
        --env SWIYU_NULLIFIER_BENCHMARK=1 \
        --env SWIYU_PACKED_STATUS_PRIMARY=1 \
        --env SWIYU_NULLIFIER_RUNS=1 -- \
        "$SDK/node_modules/.bin/vitest" run \
          tests/swiyu-zkp/nullifier-benchmark-witness.test.ts --reporter=dot
      cp "$CIRCOM/build/swiyu_nullifier_age18_benchmark/witness-runs.json" \
        "$RAW/scoped-nullifier/witness-$run.json"
      ;;
    *) return 2 ;;
  esac
}

run_native() {
  local profile="$1"
  local run="$2"
  case "$profile" in
    age)
      record --id "age-native-$run" --cwd "$NATIVE" \
        --stdout "$RAW/age/native-$run.json" \
        --env BENCHMARK_RUNS=1 \
        --env SWIYU_BENCH_PROFILE=swiyu.age-over-18.packed-status-chunk.v2 \
        --env SWIYU_BENCH_STATEMENT="issuer-authenticated birthdate is on or before the verifier-selected age-18 cutoff and status is VALID" \
        --env SWIYU_BENCH_VCT=https://example.ch/vct/person \
        --env SWIYU_BENCH_FIXTURE_DIR=swiyu_split_benchmark \
        --env SWIYU_BENCH_PREPARE_CIRCUIT=swiyu_age18_prepare_compact \
        --env SWIYU_BENCH_SHOW_CIRCUIT=swiyu_age18_show_packed_chunk_v2 \
        --env SWIYU_BENCH_PREPARE_PUBLIC_INPUTS=2 \
        --env SWIYU_BENCH_SHOW_PUBLIC_INPUTS=7 \
        --env SWIYU_BENCH_SHARED_OUTPUTS=11 \
        --env SWIYU_BENCH_WITNESS_METADATA=fixture.json \
        --env SWIYU_BENCH_PREPARE_WITNESS=prepare.wtns \
        --env SWIYU_BENCH_SHOW_WITNESS=show-packed-v2.wtns \
        --env SWIYU_BENCH_UNLINKED_SHOW_WITNESS=show-unlinked-packed-v2.wtns -- \
        "$NATIVE/target/release/swiyu-professional-license-benchmark"
      ;;
    residence)
      record --id "residence-native-$run" --cwd "$NATIVE" \
        --stdout "$RAW/residence/native-$run.json" \
        --env BENCHMARK_RUNS=1 \
        --env SWIYU_BENCH_PROFILE=swiyu.residence-eligibility.combined-disclosure.v1 \
        --env SWIYU_BENCH_STATEMENT="authoritative current main residence is in the accepted municipality set and began at least the required whole UTC days ago" \
        --env SWIYU_BENCH_VCT=urn:ch:swiyu-lab:residence-eligibility:v1 \
        --env SWIYU_BENCH_FIXTURE_DIR=swiyu_residence_combined_benchmark \
        --env SWIYU_BENCH_PREPARE_CIRCUIT=swiyu_residence_combined_prepare_compact \
        --env SWIYU_BENCH_SHOW_CIRCUIT=swiyu_residence_show_packed_chunk_v2 \
        --env SWIYU_BENCH_PREPARE_PUBLIC_INPUTS=2 \
        --env SWIYU_BENCH_SHOW_PUBLIC_INPUTS=24 \
        --env SWIYU_BENCH_SHARED_OUTPUTS=11 \
        --env SWIYU_BENCH_PREPARE_WITNESS=prepare.wtns \
        --env SWIYU_BENCH_SHOW_WITNESS=show.wtns \
        --env SWIYU_BENCH_UNLINKED_SHOW_WITNESS=show-unlinked.wtns -- \
        "$NATIVE/target/release/swiyu-professional-license-benchmark"
      ;;
    scoped-nullifier)
      record --id "scoped-nullifier-native-$run" --cwd "$NATIVE" \
        --stdout "$RAW/scoped-nullifier/native-$run.json" \
        --env BENCHMARK_RUNS=1 \
        --env SWIYU_BENCH_PROFILE=swiyu.age-over-18.scoped-nullifier.v1 \
        --env SWIYU_BENCH_STATEMENT="age over 18 and at most one accepted claim per credential/nullifier attestation in the verifier-selected scope" \
        --env SWIYU_BENCH_VCT=https://example.ch/vct/person \
        --env SWIYU_BENCH_FIXTURE_DIR=swiyu_nullifier_age18_benchmark \
        --env SWIYU_BENCH_PREPARE_CIRCUIT=swiyu_nullifier_age18_prepare \
        --env SWIYU_BENCH_SHOW_CIRCUIT=swiyu_nullifier_age18_show_packed_chunk_v2 \
        --env SWIYU_BENCH_PREPARE_PUBLIC_INPUTS=2 \
        --env SWIYU_BENCH_SHOW_PUBLIC_INPUTS=11 \
        --env SWIYU_BENCH_SHARED_OUTPUTS=13 \
        --env SWIYU_BENCH_PREPARE_WITNESS=prepare.wtns \
        --env SWIYU_BENCH_SHOW_WITNESS=show-packed-v2.wtns \
        --env SWIYU_BENCH_UNLINKED_SHOW_WITNESS=show-unlinked-packed-v2.wtns -- \
        "$NATIVE/target/release/swiyu-professional-license-benchmark"
      ;;
    *) return 2 ;;
  esac
}

control_for_profile() {
  case "$1" in
    age) echo age-over-18 ;;
    residence) echo authoritative-residence-exact ;;
    scoped-nullifier) echo scoped-nullifier ;;
    *) return 2 ;;
  esac
}

thermal_cooldown() {
  local label="$1"
  # Keep prior heavy work away from the next timing phase with a fixed,
  # provenance-recorded idle interval. Order is rotated/reversed across rounds
  # because an idle interval cannot by itself guarantee identical frequency.
  record --id "thermal-cooldown-$label" --cwd "$ROOT" -- \
    /bin/sleep 30
}

assemble_control() {
  local profile="$1"
  record --id "control-$profile-assemble" --cwd "$SDK" \
    --stdout "$RAW/controls/$profile.json" -- \
    node --experimental-strip-types scripts/benchmark-swiyu-no-zk.ts \
      --profile "$profile" --iterations 1000 \
      --assemble-workers "$RAW/control-workers/$profile"
}

# Primary controls and ZK witnesses are interleaved one fresh process at a
# time. All witness work in a round finishes before the recorded cooldown and
# native phase, so profile-specific negative witness checks cannot immediately
# precondition that profile's setup/prove timings.
for run in 1 2; do
  case "$run" in
    1) order=(age residence scoped-nullifier) ;;
    2) order=(residence scoped-nullifier age) ;;
  esac
  thermal_cooldown "before-control-round-$run"
  witness_profiles=()
  for profile in "${order[@]}"; do
    control="$(control_for_profile "$profile")"
    run_control_worker "$control" "$run"
    if [[ "$profile" == residence ]]; then
      run_control_worker authoritative-residence-derived "$run"
    fi
  done
  for profile in "${order[@]}"; do
    run_witness "$profile" "$run"
    witness_profiles+=("$profile")
  done
  thermal_cooldown "after-witness-round-$run"
  for ((index = ${#witness_profiles[@]} - 1; index >= 0; index--)); do
    run_native "${witness_profiles[$index]}" "$run"
  done
done

for profile in age residence scoped-nullifier; do
  record --id "adaptive-zk-$profile" --cwd "$ROOT" \
    --stdout "$RAW/$profile/repetition-rule.json" -- \
    node "$BENCH/adaptive-profile-runs.mjs" "$profile" "$RAW/$profile"
done
for control in age-over-18 authoritative-residence-exact \
  authoritative-residence-derived scoped-nullifier; do
  record --id "adaptive-control-$control" --cwd "$ROOT" \
    --stdout "$RAW/control-workers/$control/repetition-rule.json" -- \
    node "$BENCH/adaptive-control-runs.mjs" "$control" \
      "$RAW/control-workers/$control"
done

AGE_RUNS="$(jq -r .requiredRuns "$RAW/age/repetition-rule.json")"
RESIDENCE_RUNS="$(jq -r .requiredRuns "$RAW/residence/repetition-rule.json")"
SCOPED_NULLIFIER_RUNS="$(jq -r .requiredRuns "$RAW/scoped-nullifier/repetition-rule.json")"
AGE_CONTROL_RUNS="$(jq -r .requiredRuns "$RAW/control-workers/age-over-18/repetition-rule.json")"
RESIDENCE_CONTROL_RUNS="$(jq -r .requiredRuns "$RAW/control-workers/authoritative-residence-exact/repetition-rule.json")"
RESIDENCE_DERIVED_CONTROL_RUNS="$(jq -r .requiredRuns "$RAW/control-workers/authoritative-residence-derived/repetition-rule.json")"
SCOPED_NULLIFIER_CONTROL_RUNS="$(jq -r .requiredRuns "$RAW/control-workers/scoped-nullifier/repetition-rule.json")"

for ((run = 3; run <= 7; run++)); do
  # Cyclic and reversed rotations balance first/middle/last positions over the
  # maximum seven-round campaign.
  case "$run" in
    3) order=(scoped-nullifier age residence) ;;
    4) order=(age scoped-nullifier residence) ;;
    5) order=(scoped-nullifier residence age) ;;
    6) order=(residence age scoped-nullifier) ;;
    7) order=(age residence scoped-nullifier) ;;
  esac
  if ((run > AGE_RUNS && run > RESIDENCE_RUNS && run > SCOPED_NULLIFIER_RUNS &&
       run > AGE_CONTROL_RUNS && run > RESIDENCE_CONTROL_RUNS &&
       run > RESIDENCE_DERIVED_CONTROL_RUNS && run > SCOPED_NULLIFIER_CONTROL_RUNS)); then
    continue
  fi
  thermal_cooldown "before-control-round-$run"
  witness_profiles=()
  for profile in "${order[@]}"; do
    control="$(control_for_profile "$profile")"
    case "$profile" in
      age)
        zk_required="$AGE_RUNS"
        control_required="$AGE_CONTROL_RUNS"
        ;;
      residence)
        zk_required="$RESIDENCE_RUNS"
        control_required="$RESIDENCE_CONTROL_RUNS"
        ;;
      scoped-nullifier)
        zk_required="$SCOPED_NULLIFIER_RUNS"
        control_required="$SCOPED_NULLIFIER_CONTROL_RUNS"
        ;;
    esac
    if ((run <= control_required)); then
      run_control_worker "$control" "$run"
    fi
    if [[ "$profile" == residence ]] && ((run <= RESIDENCE_DERIVED_CONTROL_RUNS)); then
      run_control_worker authoritative-residence-derived "$run"
    fi
  done
  for profile in "${order[@]}"; do
    case "$profile" in
      age) zk_required="$AGE_RUNS" ;;
      residence) zk_required="$RESIDENCE_RUNS" ;;
      scoped-nullifier) zk_required="$SCOPED_NULLIFIER_RUNS" ;;
    esac
    if ((run <= zk_required)); then
      run_witness "$profile" "$run"
      witness_profiles+=("$profile")
    fi
  done
  if ((${#witness_profiles[@]} > 0)); then
    thermal_cooldown "after-witness-round-$run"
    for ((index = ${#witness_profiles[@]} - 1; index >= 0; index--)); do
      run_native "${witness_profiles[$index]}" "$run"
    done
  fi
done

assemble_control age-over-18
assemble_control authoritative-residence-exact
assemble_control authoritative-residence-derived
assemble_control scoped-nullifier

# Supplementary implementation and common durable-state studies are kept out
# of the interleaved direct-comparison rounds.
record --id "control-production-swiyu-verifier-age-over-18" --cwd "$ROOT" \
  --stdout "$RAW/production-control/age-over-18.json" -- \
  node "$ROOT/benchmark/swiyu-verifier/run-production-control.mjs" \
    --java /opt/java/openjdk/bin/java \
    --classpath '/opt/swiyu/classes:/opt/swiyu/benchmark:/opt/swiyu/lib/*' \
    --iterations 1000 --warmups 100
record --id "control-scoped-nullifier-state" --cwd "$SDK" \
  --stdout "$RAW/nullifier-state/state.json" -- \
  node --no-warnings scripts/benchmark-swiyu-nullifier-state.mjs \
    --adaptive --iterations 1000

# Measure the common SDK path separately for the three retained profiles so
# proof-envelope framing uses that profile's exact native proof-pair size.
for profile in age residence scoped-nullifier; do
  case "$profile" in
    age)
      prepare_proof_bytes="$(jq '.exact_sizes.prepare.proof_bytes' "$RAW/age/native-1.json")"
      show_proof_bytes="$(jq '.exact_sizes.show.proof_bytes' "$RAW/age/native-1.json")"
      ;;
    residence)
      prepare_proof_bytes="$(jq '.exact_sizes.prepare.proof_bytes' "$RAW/residence/native-1.json")"
      show_proof_bytes="$(jq '.exact_sizes.show.proof_bytes' "$RAW/residence/native-1.json")"
      ;;
    scoped-nullifier)
      prepare_proof_bytes="$(jq '.exact_sizes.prepare.proof_bytes' "$RAW/scoped-nullifier/native-1.json")"
      show_proof_bytes="$(jq '.exact_sizes.show.proof_bytes' "$RAW/scoped-nullifier/native-1.json")"
      ;;
  esac
  proof_pair_bytes=$((prepare_proof_bytes + show_proof_bytes))
  record --id "zk-sdk-host-$profile" --cwd "$SDK" \
    --stdout "$RAW/sdk-host/$profile.json" -- \
    "$CIRCOM/node_modules/.bin/tsx" scripts/benchmark-swiyu-zk-host.ts \
      --profile "$profile" --adaptive --iterations 1000 \
      --proof-pair-bytes "$proof_pair_bytes" \
      --prepare-proof-bytes "$prepare_proof_bytes" \
      --show-proof-bytes "$show_proof_bytes"
done

# Publish a completed pre-aggregation provenance snapshot. The final metadata
# pass below runs again after aggregation so its command is also retained.
node "$BENCH/collect-metadata.mjs" "$RESULTS/metadata.json" finish 0

record --id aggregate-final-overhead --cwd "$SDK" \
  --stdout "$RESULTS/aggregate.log" -- \
  node --experimental-strip-types scripts/aggregate-swiyu-final-results.ts \
    --results-root "$RESULTS" \
    --out "$RESULTS/zk-overhead-results.json"

node "$BENCH/collect-metadata.mjs" "$RESULTS/metadata.json" finish 0
trap - EXIT

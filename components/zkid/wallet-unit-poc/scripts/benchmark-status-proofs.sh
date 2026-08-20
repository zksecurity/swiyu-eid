#!/usr/bin/env bash
# PROTOTYPE: compile and benchmark the two isolated status-only relations.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CIRCOM="$ROOT/circom"
RUST="$ROOT/ecdsa-spartan2"
INPUTS="$CIRCOM/build/status-proof-benchmark-inputs"
RESULTS="$CIRCOM/build/status-proof-benchmark-results"

DENSE_CIRCUIT="swiyu_status_dense_17_bench"
SPARSE_CIRCUIT="swiyu_status_sparse_64_bench"

cleanup_candidate_artifacts() {
  rm -rf \
    "$CIRCOM/build/$DENSE_CIRCUIT" \
    "$CIRCOM/build/$SPARSE_CIRCUIT" \
    "$INPUTS"
}
trap cleanup_candidate_artifacts EXIT

mkdir -p "$INPUTS" "$RESULTS"
cd "$CIRCOM"
node --import tsx src/status-proof-benchmark-fixtures.ts "$INPUTS" >/dev/null

run_profile() {
  local profile="$1"
  local circuit="$2"
  local input="$INPUTS/$circuit.json"
  local witness="$INPUTS/$circuit.wtns"
  local output="$RESULTS/$circuit.json"

  bash scripts/compile.sh "$circuit" 2>&1 | tee "$RESULTS/$circuit.compile.log"
  node \
    "$CIRCOM/build/$circuit/${circuit}_js/generate_witness.js" \
    "$CIRCOM/build/$circuit/${circuit}_js/$circuit.wasm" \
    "$input" \
    "$witness"

  cd "$RUST"
  cargo run --quiet --release --no-default-features \
    --bin status-proof-benchmark -- "$profile" "$witness" >"$output"
  cd "$CIRCOM"
  cat "$output"

  # Release candidate R1CS/WASM before compiling the next profile.  The final
  # swiyu_age18_status_2k relation and its keys are deliberately outside this
  # cleanup list.
  rm -rf "$CIRCOM/build/$circuit"
  rm -f "$witness"
}

run_profile "dense-fixed-index-status-v1" "$DENSE_CIRCUIT"
run_profile "sparse-valid-nonmembership-v1" "$SPARSE_CIRCUIT"

printf 'Generated reports (ignored build artifacts): %s\n' "$RESULTS"

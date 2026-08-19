#!/usr/bin/env bash
set -euo pipefail

# Reproducible, sequential same-host benchmark. Circuit compilation is a
# developer/build-time operation and is intentionally not mixed into runtime
# setup/proving measurements. Compile the Prepare/Show artifacts first.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SDK_DIR="$POC_DIR/openac-sdk"
NATIVE_DIR="$POC_DIR/ecdsa-spartan2"
OUTPUT="${1:-$POC_DIR/docs/swiyu-zkp/zk-overhead-benchmark-results.json}"
BENCH_TMP="$(mktemp -d "${TMPDIR:-/tmp}/swiyu-zk-overhead.XXXXXX")"
trap 'rm -rf "$BENCH_TMP"' EXIT

for profile in age-over-18 resident-canton professional-license; do
  (
    cd "$SDK_DIR"
    node --experimental-strip-types scripts/benchmark-swiyu-no-zk.ts \
      --profile "$profile" --runs 3 --iterations 1000 \
      --out "$BENCH_TMP/control-$profile.json" >/dev/null
  )
done

(
  cd "$NATIVE_DIR"
  cargo build --release --no-default-features --bin swiyu-split-benchmark
)

run_zk() {
  local run="$1"
  (
    cd "$SDK_DIR"
    SWIYU_SPLIT_BENCHMARK=1 npx vitest run \
      tests/swiyu-zkp/split-benchmark-witness.test.ts --reporter=dot >/dev/null
    cp "$POC_DIR/circom/build/swiyu_split_benchmark/fixture.json" \
      "$BENCH_TMP/zk-witness-$run.json"
  )
  (
    cd "$NATIVE_DIR"
    ./target/release/swiyu-split-benchmark >"$BENCH_TMP/zk-run-$run.json"
  )
}

run_zk 1
run_zk 2

if node - "$BENCH_TMP" <<'NODE'
const fs = require("node:fs");
const dir = process.argv[2];
const native = [1, 2].map((run) => JSON.parse(fs.readFileSync(`${dir}/zk-run-${run}.json`)));
const witness = [1, 2].map((run) => JSON.parse(fs.readFileSync(`${dir}/zk-witness-${run}.json`)));
const pairs = [
  [witness[0].witnessGenerationMs.prepare, witness[1].witnessGenerationMs.prepare],
  [witness[0].witnessGenerationMs.show, witness[1].witnessGenerationMs.show],
];
for (const stage of ["prepare", "show"]) {
  for (const field of ["setup_ms", "assignment_ms", "final_proof_ms", "verify_ms"]) {
    pairs.push([native[0][stage][field], native[1][stage][field]]);
  }
}
const unstable = pairs.some(([a, b]) => Math.abs(a - b) / ((a + b) / 2) > 0.15);
process.exit(unstable ? 0 : 1);
NODE
then
  ZK_RUNS=7
else
  ZK_RUNS=3
fi

for ((run = 3; run <= ZK_RUNS; run++)); do
  run_zk "$run"
done

(
  cd "$SDK_DIR"
  node --experimental-strip-types scripts/aggregate-swiyu-zk-overhead.ts \
    --out "$OUTPUT" --raw-dir "$BENCH_TMP" --zk-runs "$ZK_RUNS" \
    --age-over-18-control "$BENCH_TMP/control-age-over-18.json" \
    --resident-canton-control "$BENCH_TMP/control-resident-canton.json" \
    --professional-license-control "$BENCH_TMP/control-professional-license.json"
)

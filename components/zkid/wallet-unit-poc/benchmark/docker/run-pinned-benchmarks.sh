#!/usr/bin/env bash
set -euo pipefail

# This host wrapper is the only supported entry point for final measurements.
# It builds with network access, then runs the immutable image offline with one
# fixed CPU/memory envelope. No benchmark command is executed during build.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPO_DIR="$(cd "$POC_DIR/.." && pwd)"
SWIYU_VERIFIER_DIR="${SWIYU_VERIFIER_DIR:-$(cd "$REPO_DIR/../swiyu-verifier" && pwd)}"
RESULTS_ROOT="${BENCH_RESULTS_ROOT:-$POC_DIR/benchmark/results/runs}"
IMAGE_TAG="${BENCH_IMAGE_TAG:-swiyu-zk-benchmark:node22.14-rust1.91-arm64}"
BENCH_CPUS="${BENCH_CPUS:-4}"
BENCH_CPUSET="${BENCH_CPUSET:-0-3}"
BENCH_MEMORY="${BENCH_MEMORY:-12g}"
BENCH_PIDS="${BENCH_PIDS:-4096}"
RUN_ID="${BENCH_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
RUN_DIR="$RESULTS_ROOT/$RUN_ID"
LOCK_DIR="$RESULTS_ROOT/.run-lock"

mkdir -p "$RESULTS_ROOT"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  echo "another pinned benchmark owns $LOCK_DIR" >&2
  exit 1
fi
cleanup() { rmdir "$LOCK_DIR" 2>/dev/null || true; }
trap cleanup EXIT
mkdir -p "$RUN_DIR"

node "$SCRIPT_DIR/source-fingerprint.mjs" "$REPO_DIR" >"$RUN_DIR/source-fingerprint.json"
SOURCE_COMMIT="$(jq -r .commit "$RUN_DIR/source-fingerprint.json")"
SOURCE_DIFF_SHA256="$(jq -r .diffSha256 "$RUN_DIR/source-fingerprint.json")"
SOURCE_STATUS_SHA256="$(jq -r .statusSha256 "$RUN_DIR/source-fingerprint.json")"
SOURCE_TREE_SHA256="$(jq -r .sourceTreeSha256 "$RUN_DIR/source-fingerprint.json")"
SOURCE_DIRTY="$(jq -r .dirty "$RUN_DIR/source-fingerprint.json")"
if [[ "$SOURCE_DIRTY" != "false" ]]; then
  echo "final benchmarks require a clean committed source tree" >&2
  exit 1
fi

node "$SCRIPT_DIR/external-source-fingerprint.mjs" "$SWIYU_VERIFIER_DIR" \
  >"$RUN_DIR/swiyu-verifier-source-fingerprint.json"
SWIYU_VERIFIER_COMMIT="$(jq -r .commit "$RUN_DIR/swiyu-verifier-source-fingerprint.json")"
SWIYU_VERIFIER_TREE_SHA256="$(jq -r .sourceTreeSha256 "$RUN_DIR/swiyu-verifier-source-fingerprint.json")"
SWIYU_VERIFIER_DIRTY="$(jq -r .dirty "$RUN_DIR/swiyu-verifier-source-fingerprint.json")"
if [[ "$SWIYU_VERIFIER_DIRTY" != "false" ]]; then
  echo "final benchmarks require a clean committed swiyu-verifier source tree" >&2
  exit 1
fi

docker buildx build --load --platform linux/arm64 \
  --file "$SCRIPT_DIR/Dockerfile" \
  --tag "$IMAGE_TAG" \
  --iidfile "$RUN_DIR/image-iid.txt" \
  --build-context "swiyu_verifier_source=$SWIYU_VERIFIER_DIR" \
  --build-arg "SOURCE_COMMIT=$SOURCE_COMMIT" \
  --build-arg "SOURCE_DIFF_SHA256=$SOURCE_DIFF_SHA256" \
  --build-arg "SOURCE_DIFF_STATUS=$SOURCE_DIRTY" \
  --build-arg "SWIYU_VERIFIER_COMMIT=$SWIYU_VERIFIER_COMMIT" \
  --build-arg "SWIYU_VERIFIER_TREE_SHA256=$SWIYU_VERIFIER_TREE_SHA256" \
  "$POC_DIR"

node "$SCRIPT_DIR/source-fingerprint.mjs" "$REPO_DIR" \
  >"$RUN_DIR/source-fingerprint-after-build.json"
if ! cmp -s "$RUN_DIR/source-fingerprint.json" "$RUN_DIR/source-fingerprint-after-build.json"; then
  echo "source changed during Docker build; refusing to run timed benchmarks" >&2
  exit 1
fi

node "$SCRIPT_DIR/external-source-fingerprint.mjs" "$SWIYU_VERIFIER_DIR" \
  >"$RUN_DIR/swiyu-verifier-source-fingerprint-after-build.json"
if ! cmp -s "$RUN_DIR/swiyu-verifier-source-fingerprint.json" \
  "$RUN_DIR/swiyu-verifier-source-fingerprint-after-build.json"; then
  echo "swiyu-verifier source changed during Docker build; refusing to run timed benchmarks" >&2
  exit 1
fi

IMAGE_DIGEST="$(cat "$RUN_DIR/image-iid.txt")"
docker image inspect "$IMAGE_TAG" >"$RUN_DIR/image-inspect.json"
DOCKER_VERSION="$(docker version --format 'client={{.Client.Version}} server={{.Server.Version}}')"
HOST_OS="$(uname -srv)"
HOST_ARCH="$(uname -m)"
HOST_CPU="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || lscpu | sed -n 's/^Model name:[[:space:]]*//p')"
HOST_MEMORY_BYTES="$(sysctl -n hw.memsize 2>/dev/null || awk '/MemTotal/ {print $2 * 1024}' /proc/meminfo)"

EXACT_COMMAND="docker run --rm --platform linux/arm64 --network none --cpus $BENCH_CPUS --cpuset-cpus $BENCH_CPUSET --memory $BENCH_MEMORY --memory-swap $BENCH_MEMORY --pids-limit $BENCH_PIDS --volume $RUN_DIR:/results $IMAGE_TAG"

docker run --rm --platform linux/arm64 \
  --network none \
  --cpus "$BENCH_CPUS" \
  --cpuset-cpus "$BENCH_CPUSET" \
  --memory "$BENCH_MEMORY" \
  --memory-swap "$BENCH_MEMORY" \
  --pids-limit "$BENCH_PIDS" \
  --volume "$RUN_DIR:/results" \
  --env "BENCH_IMAGE_DIGEST=$IMAGE_DIGEST" \
  --env "BENCH_IMAGE_TAG=$IMAGE_TAG" \
  --env "BENCH_CPUS=$BENCH_CPUS" \
  --env "BENCH_CPUSET=$BENCH_CPUSET" \
  --env "BENCH_MEMORY=$BENCH_MEMORY" \
  --env "BENCH_PIDS=$BENCH_PIDS" \
  --env "BENCH_NETWORK=none" \
  --env "BENCH_EXACT_COMMAND=$EXACT_COMMAND" \
  --env "BENCH_DOCKER_VERSION=$DOCKER_VERSION" \
  --env "BENCH_HOST_OS=$HOST_OS" \
  --env "BENCH_HOST_ARCH=$HOST_ARCH" \
  --env "BENCH_HOST_CPU=$HOST_CPU" \
  --env "BENCH_HOST_MEMORY_BYTES=$HOST_MEMORY_BYTES" \
  --env "SOURCE_COMMIT=$SOURCE_COMMIT" \
  --env "SOURCE_DIFF_SHA256=$SOURCE_DIFF_SHA256" \
  --env "SOURCE_STATUS_SHA256=$SOURCE_STATUS_SHA256" \
  --env "SOURCE_TREE_SHA256=$SOURCE_TREE_SHA256" \
  --env "SOURCE_DIRTY=$SOURCE_DIRTY" \
  --env "SWIYU_VERIFIER_COMMIT=$SWIYU_VERIFIER_COMMIT" \
  --env "SWIYU_VERIFIER_TREE_SHA256=$SWIYU_VERIFIER_TREE_SHA256" \
  "$IMAGE_TAG"

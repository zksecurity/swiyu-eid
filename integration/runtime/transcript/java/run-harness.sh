#!/usr/bin/env bash
set -euo pipefail

PORT=0
SIDECAR=""
READY_FILE=""
STOP_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="${2:?}"; shift 2 ;;
    --sidecar) SIDECAR="${2:?}"; shift 2 ;;
    --ready-file) READY_FILE="${2:?}"; shift 2 ;;
    --stop-file) STOP_FILE="${2:?}"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$SIDECAR" ]]; then
  echo "usage: $0 --port 0 --sidecar http://127.0.0.1:PORT/verify --ready-file PATH [--stop-file PATH]" >&2
  exit 2
fi
case "$SIDECAR" in
  http://127.0.0.1:*|http://localhost:*) ;;
  *) echo "sidecar must be an http loopback URL" >&2; exit 2 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EID_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
SRC_VERIFIER="$EID_ROOT/components/swiyu-verifier"
BUILD="/tmp/swiyu-verifier-transcript"

mkdir -p "$BUILD"
rsync -a --exclude target/ "$SRC_VERIFIER/" "$BUILD/"

export MAVEN_OPTS="${MAVEN_OPTS:--Xmx768m}"
unset JAVA_TOOL_OPTIONS
cd "$BUILD"
./mvnw --batch-mode -pl verifier-application -am test-compile \
  -DskipTests -Dpgpverify.skip=true -Dmaven.compiler.proc=full \
  org.apache.maven.plugins:maven-dependency-plugin:3.8.1:build-classpath \
  -DincludeScope=test \
  -Dmdep.pathSeparator=: \
  -Dmdep.outputFile="$BUILD/verifier-application/target/transcript-cp.txt"

APP="$BUILD/verifier-application"
CP="$APP/target/classes:$APP/target/test-classes:$BUILD/verifier-service/target/classes:$BUILD/verifier-service/target/test-classes:$(cat "$APP/target/transcript-cp.txt")"

ARGS=(--port "$PORT" --sidecar "$SIDECAR")
if [[ -n "$READY_FILE" ]]; then
  ARGS+=(--ready-file "$READY_FILE")
fi
if [[ -n "$STOP_FILE" ]]; then
  ARGS+=(--stop-file "$STOP_FILE")
fi

echo "process_owner=exec-java pid=$$ workspace_copy=$BUILD" >&2
exec java -Xmx768m -cp "$CP" \
  ch.admin.bj.swiyu.verifier.infrastructure.web.oid4vp.TranscriptTransportHarnessIT \
  "${ARGS[@]}"

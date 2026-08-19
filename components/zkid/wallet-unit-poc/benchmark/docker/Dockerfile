# syntax=docker/dockerfile:1.7

# Multi-architecture index digests are pinned; the build wrapper additionally
# requires --platform linux/arm64 so both stages resolve to ARM64 manifests.
ARG NODE_IMAGE=docker.io/library/node:22.14.0-bookworm-slim@sha256:1c18d9ab3af4585870b92e4dbc5cac5a0dc77dd13df1a5905cea89fc720eb05b
ARG RUST_IMAGE=docker.io/library/rust:1.91.0-bookworm@sha256:e187887ec511b3d93e45c0231d2f0fd59f1347526c58aa86343aa83c74f3e1a9
ARG MAVEN_IMAGE=docker.io/library/maven:3.9.11-eclipse-temurin-21@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237

FROM ${NODE_IMAGE} AS node_runtime

# Build the supplementary control from the real swiyu-verifier sources. The
# source arrives through an explicit named build context, independently
# fingerprinted by the host wrapper before and after this image build.
FROM ${MAVEN_IMAGE} AS swiyu_verifier_build
WORKDIR /src
COPY --from=swiyu_verifier_source . /src/
RUN mvn -q -pl verifier-service -DskipTests -Dpgpverify.skip=true test-compile \
 && mvn -q -pl verifier-service -Dpgpverify.skip=true dependency:copy-dependencies \
      -DincludeScope=runtime -DoutputDirectory=/opt/swiyu/lib
COPY benchmark/swiyu-verifier/SwiyuProductionControlBenchmark.java /tmp/
RUN mkdir -p /opt/swiyu/benchmark \
 && javac --release 21 -proc:none \
      -cp '/src/verifier-service/target/classes:/opt/swiyu/lib/*' \
      -d /opt/swiyu/benchmark /tmp/SwiyuProductionControlBenchmark.java

FROM ${RUST_IMAGE} AS benchmark

ARG SOURCE_COMMIT=unknown
ARG SOURCE_DIFF_SHA256=unknown
ARG SOURCE_DIFF_STATUS=unknown
ARG SWIYU_VERIFIER_COMMIT=unknown
ARG SWIYU_VERIFIER_TREE_SHA256=unknown
ARG CIRCOM_GIT_REV=ad44e915a12bb047b05745c2884aad9cc8326bc6

LABEL org.opencontainers.image.title="swiyu-zk-benchmark" \
      org.opencontainers.image.description="Pinned ARM64 swiyu SD-JWT versus ZK benchmark" \
      org.opencontainers.image.node_base="node:22.14.0-bookworm-slim@sha256:1c18d9ab3af4585870b92e4dbc5cac5a0dc77dd13df1a5905cea89fc720eb05b" \
      org.opencontainers.image.rust_base="rust:1.91.0-bookworm@sha256:e187887ec511b3d93e45c0231d2f0fd59f1347526c58aa86343aa83c74f3e1a9" \
      org.opencontainers.image.maven_base="maven:3.9.11-eclipse-temurin-21@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237"

COPY --from=node_runtime /usr/local/ /usr/local/
COPY --from=swiyu_verifier_build /opt/java/openjdk /opt/java/openjdk
COPY --from=swiyu_verifier_build /src/verifier-service/target/classes /opt/swiyu/classes
COPY --from=swiyu_verifier_build /opt/swiyu/lib /opt/swiyu/lib
COPY --from=swiyu_verifier_build /opt/swiyu/benchmark /opt/swiyu/benchmark

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates clang cmake git jq libssl-dev pkg-config python3 time \
 && rm -rf /var/lib/apt/lists/*

RUN cargo install \
      --git https://github.com/iden3/circom.git \
      --rev "${CIRCOM_GIT_REV}" \
      --locked \
      --root /opt/circom circom

ENV PATH="/opt/java/openjdk/bin:/opt/circom/bin:${PATH}" \
    CARGO_NET_OFFLINE=true \
    NODE_OPTIONS="--max-old-space-size=8192" \
    RAYON_NUM_THREADS=4 \
    TZ=UTC \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

WORKDIR /workspace

# Dependency layers are intentionally separate from source compilation. The
# final timed container is run with --network none; all downloads happen here.
COPY circom/package.json circom/yarn.lock circom/.yarnrc.yml /workspace/circom/
COPY circom/.yarn/releases /workspace/circom/.yarn/releases
RUN cd /workspace/circom && node .yarn/releases/yarn-4.13.0.cjs install --immutable

COPY openac-sdk/package.json openac-sdk/package-lock.json /workspace/openac-sdk/
RUN cd /workspace/openac-sdk && npm ci --ignore-scripts

COPY ecdsa-spartan2/Cargo.toml ecdsa-spartan2/Cargo.lock /workspace/ecdsa-spartan2/
RUN cd /workspace/ecdsa-spartan2 \
 && mkdir -p src/bin \
 && touch build.rs src/lib.rs src/main.rs \
      src/bin/swiyu-profile.rs src/bin/status-proof-benchmark.rs \
      src/bin/swiyu-split-benchmark.rs src/bin/swiyu-canton-benchmark.rs \
      src/bin/swiyu-professional-license-benchmark.rs \
 && CARGO_NET_OFFLINE=false cargo fetch --locked

COPY circom /workspace/circom
COPY openac-sdk /workspace/openac-sdk

RUN cd /workspace/circom \
 && bash scripts/compile.sh swiyu_age18_prepare_compact \
 && bash scripts/compile.sh swiyu_age18_show_split \
 && bash scripts/compile.sh swiyu_age18_show_packed_chunk_v2 \
 && bash scripts/compile.sh swiyu_residence_prepare_compact \
 && bash scripts/compile.sh swiyu_residence_combined_prepare_compact \
 && bash scripts/compile.sh swiyu_residence_show_split \
 && bash scripts/compile.sh swiyu_residence_show_packed_chunk_v2 \
 && bash scripts/compile.sh swiyu_nullifier_prepare \
 && bash scripts/compile.sh swiyu_nullifier_show \
 && bash scripts/compile.sh swiyu_nullifier_age18_prepare \
 && bash scripts/compile.sh swiyu_nullifier_age18_show \
 && bash scripts/compile.sh swiyu_nullifier_age18_show_packed_chunk_v2

COPY ecdsa-spartan2 /workspace/ecdsa-spartan2

RUN cd /workspace/ecdsa-spartan2 \
 && cargo build --locked --release --no-default-features \
      --bin swiyu-split-benchmark \
      --bin swiyu-professional-license-benchmark

# Source provenance belongs on the finished image. Keeping these dynamic
# values after compilation lets reporting/harness-only fixes reuse the exact
# circuit and native build layers.
LABEL org.opencontainers.image.source_commit="${SOURCE_COMMIT}" \
      org.opencontainers.image.source_diff_sha256="${SOURCE_DIFF_SHA256}" \
      ch.admin.bitbox.swiyu.verifier_source_commit="${SWIYU_VERIFIER_COMMIT}" \
      ch.admin.bitbox.swiyu.verifier_source_tree_sha256="${SWIYU_VERIFIER_TREE_SHA256}"
ENV SOURCE_COMMIT="${SOURCE_COMMIT}" \
    SOURCE_DIFF_SHA256="${SOURCE_DIFF_SHA256}" \
    SOURCE_DIFF_STATUS="${SOURCE_DIFF_STATUS}" \
    SWIYU_VERIFIER_COMMIT="${SWIYU_VERIFIER_COMMIT}" \
    SWIYU_VERIFIER_TREE_SHA256="${SWIYU_VERIFIER_TREE_SHA256}"

# Harness-only changes must not invalidate the expensive circuit and native
# compilation layers above.
COPY benchmark /workspace/benchmark
COPY scripts /workspace/scripts

RUN node --version | grep -Fx 'v22.14.0' \
 && rustc --version | grep -F 'rustc 1.91.0' \
 && java --version | head -n 1 | grep -F 'openjdk 21' \
 && circom --version | grep -F '2.2.3'

ENTRYPOINT ["/workspace/benchmark/docker/run-final-benchmarks.sh"]

// PROTOTYPE benchmark main: status-only dense baseline, not a production profile.
pragma circom 2.2.3;

include "../swiyu/status-proof-benchmark.circom";

component main {public[snapshotEpoch, expectedSnapshotRootHi, expectedSnapshotRootLo, expectedQueryHandleHi, expectedQueryHandleLo]}
    = SwiyuDenseStatusBenchmark();

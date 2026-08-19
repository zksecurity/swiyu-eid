pragma circom 2.2.3;

include "../swiyu/status-merkle-packed-chunk.circom";
include "../swiyu/status-proof-benchmark.circom";

template SwiyuPackedStatusChunkV2CoreBenchmark() {
    signal input statusIndex;
    signal input statusValue;
    signal input statusChunk[64];
    signal input siblings[6][2][32];
    signal input listLength;
    signal input snapshotEpoch;
    signal input expectedSnapshotRootHi;
    signal input expectedSnapshotRootLo;
    signal output valid;

    component status = SwiyuPackedStatusChunkMerkleV2();
    status.statusIndex <== statusIndex;
    status.statusValue <== statusValue;
    status.packedChunk <== statusChunk;
    status.siblings <== siblings;
    status.listLength <== listLength;
    status.epoch <== snapshotEpoch;

    component root = SwiyuDigestBytesToLimbs();
    root.digest <== status.snapshotRoot;
    root.hi === expectedSnapshotRootHi;
    root.lo === expectedSnapshotRootLo;
    valid <== 1;
}

component main {public[snapshotEpoch, expectedSnapshotRootHi, expectedSnapshotRootLo]} = SwiyuPackedStatusChunkV2CoreBenchmark();

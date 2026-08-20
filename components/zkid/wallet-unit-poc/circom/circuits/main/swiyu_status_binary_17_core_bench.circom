pragma circom 2.2.3;

include "../swiyu/status-proof-benchmark.circom";

template SwiyuBinaryStatusCoreBenchmark() {
    signal input statusIndex;
    signal input statusValue;
    signal input siblings[17][32];
    signal input listLength;
    signal input snapshotEpoch;
    signal input expectedSnapshotRootHi;
    signal input expectedSnapshotRootLo;
    signal output valid;

    component status = SwiyuStatusMerkle(17);
    status.statusIndex <== statusIndex;
    status.statusValue <== statusValue;
    status.siblings <== siblings;
    status.listLength <== listLength;
    status.epoch <== snapshotEpoch;

    component root = SwiyuDigestBytesToLimbs();
    root.digest <== status.snapshotRoot;
    root.hi === expectedSnapshotRootHi;
    root.lo === expectedSnapshotRootLo;
    valid <== 1;
}

component main {public[snapshotEpoch, expectedSnapshotRootHi, expectedSnapshotRootLo]} = SwiyuBinaryStatusCoreBenchmark();

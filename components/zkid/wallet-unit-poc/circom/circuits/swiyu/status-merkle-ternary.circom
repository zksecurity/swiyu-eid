pragma circom 2.2.3;

include "status-merkle.circom";

/// SHA-256(u16be(21) || "swiyu-status-node3-v1" || child0 || child1 || child2).
///
/// Three children and the deliberately short, versioned domain occupy exactly
/// 119 bytes.  That is the largest SHA-256 message that still fits into two
/// compression blocks after padding.  An 11-level ternary tree consequently
/// authenticates 177,147 slots with 22 compression blocks, versus 34 blocks
/// for the depth-17 binary profile's internal nodes.
template SwiyuTernaryStatusNode() {
    var DOMAIN[21] = [
        115,119,105,121,117,45,115,116,97,116,117,115,
        45,110,111,100,101,51,45,118,49
    ];
    var MESSAGE_LEN = 119;
    signal input children[3][32];
    signal output digest[32];

    signal padded[128];
    padded[0] <== 0; padded[1] <== 21;
    for (var i = 0; i < 21; i++) padded[2 + i] <== DOMAIN[i];
    for (var child = 0; child < 3; child++) {
        for (var i = 0; i < 32; i++) {
            padded[23 + child * 32 + i] <== children[child][i];
        }
    }
    padded[MESSAGE_LEN] <== 128;
    for (var i = MESSAGE_LEN + 1; i < 126; i++) padded[i] <== 0;
    padded[126] <== 3;
    padded[127] <== 184; // 119 * 8 = 0x03b8

    signal digestBits[256] <== Sha256Bytes(128)(padded, 128);
    component toBytes = ShaBitsToBytes();
    toBytes.bits <== digestBits;
    digest <== toBytes.bytes;
}

/// Fixed-index ternary Merkle authentication path.
///
/// Each `siblings[level]` pair is ordered from the lowest to highest child
/// position after omitting the current child.  Ternary digits are derived and
/// constrained inside the circuit; callers cannot choose a path independent
/// of `statusIndex`.
template SwiyuTernaryStatusMerkle(depth) {
    signal input statusIndex;
    signal input statusValue;
    signal input siblings[depth][2][32];
    signal input listLength;
    signal input epoch;
    signal output treeRoot[32];
    signal output snapshotRoot[32];

    component indexRange = Num2Bits(32);
    indexRange.in <== statusIndex;
    component lengthBits = Num2Bits(32);
    lengthBits.in <== listLength;
    component epochBits = Num2Bits(64);
    epochBits.in <== epoch;
    component lengthPositive = GreaterThan(32);
    lengthPositive.in[0] <== listLength;
    lengthPositive.in[1] <== 0;
    lengthPositive.out === 1;
    component indexInList = LessThan(32);
    indexInList.in[0] <== statusIndex;
    indexInList.in[1] <== listLength;
    indexInList.out === 1;
    component capacityCheck = LessEqThan(32);
    capacityCheck.in[0] <== listLength;
    capacityCheck.in[1] <== 3 ** depth;
    capacityCheck.out === 1;

    component statusBits = Num2Bits(2);
    statusBits.in <== statusValue;
    statusValue === 0;

    signal quotient[depth + 1];
    signal trit[depth];
    component tritBits[depth];
    quotient[0] <== statusIndex;
    for (var level = 0; level < depth; level++) {
        trit[level] <-- quotient[level] % 3;
        quotient[level + 1] <-- quotient[level] \ 3;
        quotient[level] === quotient[level + 1] * 3 + trit[level];
        tritBits[level] = Num2Bits(2);
        tritBits[level].in <== trit[level];
        tritBits[level].out[0] * tritBits[level].out[1] === 0;
    }
    quotient[depth] === 0;

    component leaf = SwiyuStatusLeaf();
    leaf.index <== statusIndex;
    leaf.status <== statusValue;

    signal current[depth + 1][32];
    signal children[depth][3][32];
    signal middle01[depth][32];
    for (var i = 0; i < 32; i++) current[0][i] <== leaf.digest[i];

    component nodes[depth];
    for (var level = 0; level < depth; level++) {
        for (var i = 0; i < 32; i++) {
            // trit 0: [current, sibling0, sibling1]
            // trit 1: [sibling0, current, sibling1]
            // trit 2: [sibling0, sibling1, current]
            children[level][0][i] <== current[level][i]
                + (tritBits[level].out[0] + tritBits[level].out[1])
                * (siblings[level][0][i] - current[level][i]);
            middle01[level][i] <== siblings[level][0][i]
                + tritBits[level].out[0]
                * (current[level][i] - siblings[level][0][i]);
            children[level][1][i] <== middle01[level][i]
                + tritBits[level].out[1]
                * (siblings[level][1][i] - siblings[level][0][i]);
            children[level][2][i] <== siblings[level][1][i]
                + tritBits[level].out[1]
                * (current[level][i] - siblings[level][1][i]);
        }
        nodes[level] = SwiyuTernaryStatusNode();
        nodes[level].children <== children[level];
        for (var i = 0; i < 32; i++) {
            current[level + 1][i] <== nodes[level].digest[i];
        }
    }
    for (var i = 0; i < 32; i++) treeRoot[i] <== current[depth][i];

    component snapshot = SwiyuStatusSnapshot();
    snapshot.treeRoot <== treeRoot;
    snapshot.entryCount <== listLength;
    snapshot.epoch <== epoch;
    snapshotRoot <== snapshot.digest;
}

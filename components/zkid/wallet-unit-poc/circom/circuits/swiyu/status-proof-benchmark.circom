pragma circom 2.2.3;

include "status-merkle.circom";

/// Pack a SHA-256 digest represented as 32 big-endian bytes into two
/// big-endian 128-bit field elements.  This keeps the benchmark public context
/// small without reducing the digest modulo the circuit field.
template SwiyuDigestBytesToLimbs() {
    signal input digest[32];
    signal output hi;
    signal output lo;

    component bytes[32];
    var hiValue = 0;
    var loValue = 0;
    for (var i = 0; i < 32; i++) {
        bytes[i] = Num2Bits(8);
        bytes[i].in <== digest[i];
        if (i < 16) {
            hiValue += digest[i] * 2 ** (8 * (15 - i));
        } else {
            loValue += digest[i] * 2 ** (8 * (31 - i));
        }
    }
    hi <== hiValue;
    lo <== loValue;
}

/// Benchmark-only composition anchor:
/// SHA-256(u16be(21) || "swiyu-status-query-v1" || designTag ||
///        u64be(privateQuery) || privateSalt[32]).
///
/// An external benchmark verifier pins the resulting public limbs.  The salt
/// prevents a small dense index from being enumerable from the handle alone.
/// The monolithic swiyu relation does not need this adapter: its status index
/// is directly shared with the signed credential relation in one witness.
template SwiyuStatusQueryHandle(designTag) {
    assert(designTag == 1 || designTag == 2);
    var DOMAIN[21] = [
        115,119,105,121,117,45,115,116,97,116,117,115,45,113,
        117,101,114,121,45,118,49
    ];
    var MESSAGE_LEN = 64;
    signal input query;
    signal input salt[32];
    signal output hi;
    signal output lo;

    component queryBytes = Uint64BE();
    queryBytes.value <== query;

    signal padded[128];
    padded[0] <== 0; padded[1] <== 21;
    for (var i = 0; i < 21; i++) padded[2 + i] <== DOMAIN[i];
    padded[23] <== designTag;
    for (var i = 0; i < 8; i++) padded[24 + i] <== queryBytes.bytes[i];
    for (var i = 0; i < 32; i++) padded[32 + i] <== salt[i];
    padded[MESSAGE_LEN] <== 128;
    for (var i = MESSAGE_LEN + 1; i < 126; i++) padded[i] <== 0;
    padded[126] <== 2;
    padded[127] <== 0; // 64 * 8 = 0x0200

    signal digestBits[256] <== Sha256Bytes(128)(padded, 128);
    component toBytes = ShaBitsToBytes();
    toBytes.bits <== digestBits;
    component limbs = SwiyuDigestBytesToLimbs();
    limbs.digest <== toBytes.bytes;
    hi <== limbs.hi;
    lo <== limbs.lo;
}

/// Status-only dense baseline.  This is intentionally not a second SD-JWT
/// circuit: it isolates exactly the fixed depth-17 status relation selected by
/// the swiyu profile.  The private index is bound by its leaf and left/right
/// path; the public epoch is included in the authenticated snapshot root.
template SwiyuDenseStatusBenchmark() {
    signal input statusIndex;
    signal input statusValue;
    signal input siblings[17][32];
    signal input listLength;
    signal input querySalt[32];

    signal input snapshotEpoch;
    signal input expectedSnapshotRootHi;
    signal input expectedSnapshotRootLo;
    signal input expectedQueryHandleHi;
    signal input expectedQueryHandleLo;
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
    component queryHandle = SwiyuStatusQueryHandle(1);
    queryHandle.query <== statusIndex;
    queryHandle.salt <== querySalt;
    queryHandle.hi === expectedQueryHandleHi;
    queryHandle.lo === expectedQueryHandleLo;
    valid <== 1;
}

/// SHA-256(u16be(28) || "swiyu-sparse-status-empty-v1" || 0x00).
template SwiyuSparseStatusEmptyLeaf() {
    var DOMAIN[28] = [
        115,119,105,121,117,45,115,112,97,114,115,101,45,115,
        116,97,116,117,115,45,101,109,112,116,121,45,118,49
    ];
    var MESSAGE_LEN = 31;
    signal output digest[32];

    signal padded[64];
    padded[0] <== 0; padded[1] <== 28;
    for (var i = 0; i < 28; i++) padded[2 + i] <== DOMAIN[i];
    padded[30] <== 0;
    padded[MESSAGE_LEN] <== 128;
    for (var i = MESSAGE_LEN + 1; i < 62; i++) padded[i] <== 0;
    padded[62] <== 0;
    padded[63] <== 248; // 31 * 8 = 0x00f8

    signal digestBits[256] <== Sha256Bytes(64)(padded, 64);
    component toBytes = ShaBitsToBytes();
    toBytes.bits <== digestBits;
    digest <== toBytes.bytes;
}

/// SHA-256(u16be(27) || "swiyu-sparse-status-node-v1" || left || right).
template SwiyuSparseStatusNode() {
    var DOMAIN[27] = [
        115,119,105,121,117,45,115,112,97,114,115,101,45,115,
        116,97,116,117,115,45,110,111,100,101,45,118,49
    ];
    var MESSAGE_LEN = 93;
    signal input left[32];
    signal input right[32];
    signal output digest[32];

    signal padded[128];
    padded[0] <== 0; padded[1] <== 27;
    for (var i = 0; i < 27; i++) padded[2 + i] <== DOMAIN[i];
    for (var i = 0; i < 32; i++) padded[29 + i] <== left[i];
    for (var i = 0; i < 32; i++) padded[61 + i] <== right[i];
    padded[MESSAGE_LEN] <== 128;
    for (var i = MESSAGE_LEN + 1; i < 126; i++) padded[i] <== 0;
    padded[126] <== 2;
    padded[127] <== 232; // 93 * 8 = 0x02e8

    signal digestBits[256] <== Sha256Bytes(128)(padded, 128);
    component toBytes = ShaBitsToBytes();
    toBytes.bits <== digestBits;
    digest <== toBytes.bytes;
}

/// SHA-256(u16be(31) || "swiyu-sparse-status-snapshot-v1" ||
///        u64be(epoch) || treeRoot).
template SwiyuSparseStatusSnapshot() {
    var DOMAIN[31] = [
        115,119,105,121,117,45,115,112,97,114,115,101,45,115,
        116,97,116,117,115,45,115,110,97,112,115,104,111,116,45,118,49
    ];
    var MESSAGE_LEN = 73;
    signal input epoch;
    signal input treeRoot[32];
    signal output digest[32];

    component epochBytes = Uint64BE();
    epochBytes.value <== epoch;

    signal padded[128];
    padded[0] <== 0; padded[1] <== 31;
    for (var i = 0; i < 31; i++) padded[2 + i] <== DOMAIN[i];
    for (var i = 0; i < 8; i++) padded[33 + i] <== epochBytes.bytes[i];
    for (var i = 0; i < 32; i++) padded[41 + i] <== treeRoot[i];
    padded[MESSAGE_LEN] <== 128;
    for (var i = MESSAGE_LEN + 1; i < 126; i++) padded[i] <== 0;
    padded[126] <== 2;
    padded[127] <== 72; // 73 * 8 = 0x0248

    signal digestBits[256] <== Sha256Bytes(128)(padded, 128);
    component toBytes = ShaBitsToBytes();
    toBytes.bits <== digestBits;
    digest <== toBytes.bytes;
}

/// Depth-64 sparse-set valid non-membership.  `revoked == 0` selects the
/// canonical empty leaf; the private identifier's 64 bits select every path
/// direction and therefore bind the query to the authenticated public root.
template SwiyuSparseStatusBenchmark() {
    signal input identifier;
    signal input revoked;
    signal input siblings[64][32];
    signal input querySalt[32];

    signal input snapshotEpoch;
    signal input expectedSnapshotRootHi;
    signal input expectedSnapshotRootLo;
    signal input expectedQueryHandleHi;
    signal input expectedQueryHandleLo;
    signal output valid;

    component identifierBits = Num2Bits(64);
    identifierBits.in <== identifier;
    component revokedBit = Num2Bits(1);
    revokedBit.in <== revoked;
    revoked === 0;

    component empty = SwiyuSparseStatusEmptyLeaf();
    signal current[65][32];
    signal left[64][32];
    signal right[64][32];
    for (var i = 0; i < 32; i++) current[0][i] <== empty.digest[i];

    component nodes[64];
    for (var level = 0; level < 64; level++) {
        for (var i = 0; i < 32; i++) {
            left[level][i] <== current[level][i]
                + identifierBits.out[level] * (siblings[level][i] - current[level][i]);
            right[level][i] <== siblings[level][i]
                + identifierBits.out[level] * (current[level][i] - siblings[level][i]);
        }
        nodes[level] = SwiyuSparseStatusNode();
        nodes[level].left <== left[level];
        nodes[level].right <== right[level];
        for (var i = 0; i < 32; i++) current[level + 1][i] <== nodes[level].digest[i];
    }

    component snapshot = SwiyuSparseStatusSnapshot();
    snapshot.epoch <== snapshotEpoch;
    snapshot.treeRoot <== current[64];
    component root = SwiyuDigestBytesToLimbs();
    root.digest <== snapshot.digest;
    root.hi === expectedSnapshotRootHi;
    root.lo === expectedSnapshotRootLo;
    component queryHandle = SwiyuStatusQueryHandle(2);
    queryHandle.query <== identifier;
    queryHandle.salt <== querySalt;
    queryHandle.hi === expectedQueryHandleHi;
    queryHandle.lo === expectedQueryHandleLo;
    valid <== 1;
}

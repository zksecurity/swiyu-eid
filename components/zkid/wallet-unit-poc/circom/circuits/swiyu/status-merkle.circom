pragma circom 2.2.3;

include "@zk-email/circuits/lib/sha.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

template ShaBitsToBytes() {
    signal input bits[256];
    signal output bytes[32];
    component byteValue[32];
    for (var i = 0; i < 32; i++) {
        byteValue[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) byteValue[i].in[7 - j] <== bits[i * 8 + j];
        bytes[i] <== byteValue[i].out;
    }
}

template Uint32BE() {
    signal input value;
    signal output bytes[4];
    component bits = Num2Bits(32);
    bits.in <== value;
    component byteValue[4];
    for (var i = 0; i < 4; i++) {
        byteValue[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) byteValue[i].in[j] <== bits.out[(3 - i) * 8 + j];
        bytes[i] <== byteValue[i].out;
    }
}

template Uint64BE() {
    signal input value;
    signal output bytes[8];
    component bits = Num2Bits(64);
    bits.in <== value;
    component byteValue[8];
    for (var i = 0; i < 8; i++) {
        byteValue[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) byteValue[i].in[j] <== bits.out[(7 - i) * 8 + j];
        bytes[i] <== byteValue[i].out;
    }
}

/// SHA-256( u16be(20) || "swiyu-status-leaf-v1" || u32be(index) || status )
template SwiyuStatusLeaf() {
    var DOMAIN[20] = [
        115,119,105,121,117,45,115,116,97,116,117,115,45,108,101,97,102,45,118,49
    ];
    var MESSAGE_LEN = 27;
    signal input index;
    signal input status;
    signal output digest[32];

    component indexBytes = Uint32BE();
    indexBytes.value <== index;
    component statusBits = Num2Bits(2);
    statusBits.in <== status;

    signal padded[64];
    padded[0] <== 0; padded[1] <== 20;
    for (var i = 0; i < 20; i++) padded[2 + i] <== DOMAIN[i];
    for (var i = 0; i < 4; i++) padded[22 + i] <== indexBytes.bytes[i];
    padded[26] <== status;
    padded[MESSAGE_LEN] <== 128;
    for (var i = MESSAGE_LEN + 1; i < 62; i++) padded[i] <== 0;
    padded[62] <== 0;
    padded[63] <== 216; // 27 * 8

    signal digestBits[256] <== Sha256Bytes(64)(padded, 64);
    component toBytes = ShaBitsToBytes();
    toBytes.bits <== digestBits;
    digest <== toBytes.bytes;
}

/// SHA-256( u16be(20) || "swiyu-status-node-v1" || left || right )
template SwiyuStatusNode() {
    var DOMAIN[20] = [
        115,119,105,121,117,45,115,116,97,116,117,115,45,110,111,100,101,45,118,49
    ];
    var MESSAGE_LEN = 86;
    signal input left[32];
    signal input right[32];
    signal output digest[32];

    signal padded[128];
    padded[0] <== 0; padded[1] <== 20;
    for (var i = 0; i < 20; i++) padded[2 + i] <== DOMAIN[i];
    for (var i = 0; i < 32; i++) padded[22 + i] <== left[i];
    for (var i = 0; i < 32; i++) padded[54 + i] <== right[i];
    padded[MESSAGE_LEN] <== 128;
    for (var i = MESSAGE_LEN + 1; i < 126; i++) padded[i] <== 0;
    padded[126] <== 2;
    padded[127] <== 176; // 86 * 8 = 0x02b0

    signal digestBits[256] <== Sha256Bytes(128)(padded, 128);
    component toBytes = ShaBitsToBytes();
    toBytes.bits <== digestBits;
    digest <== toBytes.bytes;
}

/// SHA-256( u16be(24) || "swiyu-status-snapshot-v1" ||
///          u32be(entryCount) || u64be(epoch) || treeRoot )
template SwiyuStatusSnapshot() {
    var DOMAIN[24] = [
        115,119,105,121,117,45,115,116,97,116,117,115,
        45,115,110,97,112,115,104,111,116,45,118,49
    ];
    var MESSAGE_LEN = 70;
    signal input treeRoot[32];
    signal input entryCount;
    signal input epoch;
    signal output digest[32];

    component countBytes = Uint32BE(); countBytes.value <== entryCount;
    component epochBytes = Uint64BE(); epochBytes.value <== epoch;

    signal padded[128];
    padded[0] <== 0; padded[1] <== 24;
    for (var i = 0; i < 24; i++) padded[2 + i] <== DOMAIN[i];
    for (var i = 0; i < 4; i++) padded[26 + i] <== countBytes.bytes[i];
    for (var i = 0; i < 8; i++) padded[30 + i] <== epochBytes.bytes[i];
    for (var i = 0; i < 32; i++) padded[38 + i] <== treeRoot[i];
    padded[MESSAGE_LEN] <== 128;
    for (var i = MESSAGE_LEN + 1; i < 126; i++) padded[i] <== 0;
    padded[126] <== 2;
    padded[127] <== 48; // 70 * 8 = 0x0230

    signal digestBits[256] <== Sha256Bytes(128)(padded, 128);
    component toBytes = ShaBitsToBytes();
    toBytes.bits <== digestBits;
    digest <== toBytes.bytes;
}

/// Fixed-index dense Merkle authentication compatible with
/// openac-sdk/status-designs/fixed-index-merkle.ts.  `siblings` are raw
/// 32-byte SHA digests ordered from leaf level upward.
template SwiyuStatusMerkle(depth) {
    signal input statusIndex;
    signal input statusValue;
    signal input siblings[depth][32];
    signal input listLength;
    signal input epoch;
    signal output treeRoot[32];
    signal output snapshotRoot[32];

    component indexBits = Num2Bits(depth);
    indexBits.in <== statusIndex;
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
    // The profile tree is always padded to exactly 2^depth leaves.  Binding the
    // actual entry count separately permits existing swiyu lists of any size
    // while keeping one verifying key and one fixed witness shape.
    component bucketMax = LessEqThan(32);
    bucketMax.in[0] <== listLength;
    bucketMax.in[1] <== 2 ** depth;
    bucketMax.out === 1;

    component statusBits = Num2Bits(2);
    statusBits.in <== statusValue;
    statusValue === 0;

    component leaf = SwiyuStatusLeaf();
    leaf.index <== statusIndex;
    leaf.status <== statusValue;

    signal current[depth + 1][32];
    signal left[depth][32];
    signal right[depth][32];
    for (var i = 0; i < 32; i++) current[0][i] <== leaf.digest[i];

    component nodes[depth];
    for (var level = 0; level < depth; level++) {
        for (var i = 0; i < 32; i++) {
            left[level][i] <== current[level][i] + indexBits.out[level] * (siblings[level][i] - current[level][i]);
            right[level][i] <== siblings[level][i] + indexBits.out[level] * (current[level][i] - siblings[level][i]);
        }
        nodes[level] = SwiyuStatusNode();
        nodes[level].left <== left[level];
        nodes[level].right <== right[level];
        for (var i = 0; i < 32; i++) current[level + 1][i] <== nodes[level].digest[i];
    }
    for (var i = 0; i < 32; i++) treeRoot[i] <== current[depth][i];

    component snapshot = SwiyuStatusSnapshot();
    snapshot.treeRoot <== treeRoot;
    snapshot.entryCount <== listLength;
    snapshot.epoch <== epoch;
    snapshotRoot <== snapshot.digest;
}

/// Opaque, per-epoch binding of the signed private status URI to the SHA
/// snapshot root.  The fixed 256-byte record is:
///   u16be(23) || "swiyu-status-profile-v0" || u8(uriLen) || uri[160] ||
///   snapshotRoot[32] || zero-fill.
template SwiyuStatusProfileCommitment(maxUriLen) {
    assert(maxUriLen == 160);
    var DOMAIN[23] = [
        115,119,105,121,117,45,115,116,97,116,117,115,
        45,112,114,111,102,105,108,101,45,118,48
    ];
    var RECORD_LEN = 256;
    var SHA_MAX = 320;
    signal input uri[maxUriLen];
    signal input uriLength;
    signal input snapshotRoot[32];
    signal output hashHi;
    signal output hashLo;

    component uriLenBits = Num2Bits(8);
    uriLenBits.in <== uriLength;

    signal padded[SHA_MAX];
    padded[0] <== 0; padded[1] <== 23;
    for (var i = 0; i < 23; i++) padded[2 + i] <== DOMAIN[i];
    padded[25] <== uriLength;
    for (var i = 0; i < maxUriLen; i++) padded[26 + i] <== uri[i];
    for (var i = 0; i < 32; i++) padded[186 + i] <== snapshotRoot[i];
    for (var i = 218; i < RECORD_LEN; i++) padded[i] <== 0;
    padded[RECORD_LEN] <== 128;
    for (var i = RECORD_LEN + 1; i < SHA_MAX - 8; i++) padded[i] <== 0;
    for (var i = SHA_MAX - 8; i < SHA_MAX - 2; i++) padded[i] <== 0;
    padded[SHA_MAX - 2] <== 8;
    padded[SHA_MAX - 1] <== 0; // 256 * 8 = 0x0800

    signal digest[256] <== Sha256Bytes(SHA_MAX)(padded, SHA_MAX);
    component hi = Bits2Num(128);
    component lo = Bits2Num(128);
    for (var i = 0; i < 128; i++) {
        hi.in[127 - i] <== digest[i];
        lo.in[127 - i] <== digest[128 + i];
    }
    hashHi <== hi.out;
    hashLo <== lo.out;
}

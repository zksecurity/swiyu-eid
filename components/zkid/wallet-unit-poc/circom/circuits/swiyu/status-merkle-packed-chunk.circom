pragma circom 2.2.3;

include "status-merkle.circom";

/// SHA-256(u16be(21) || "swiyu-status-chunk-v2" ||
///          u32be(chunkIndex) || packedChunk[64]).
template SwiyuPackedStatusChunkLeafV2() {
    var DOMAIN[21] = [
        115,119,105,121,117,45,115,116,97,116,117,115,
        45,99,104,117,110,107,45,118,50
    ];
    var MESSAGE_LEN = 91;
    signal input chunkIndex;
    signal input packedChunk[64];
    signal output digest[32];

    component indexBytes = Uint32BE();
    indexBytes.value <== chunkIndex;
    component chunkBytes[64];
    for (var i = 0; i < 64; i++) {
        chunkBytes[i] = Num2Bits(8);
        chunkBytes[i].in <== packedChunk[i];
    }

    signal padded[128];
    padded[0] <== 0; padded[1] <== 21;
    for (var i = 0; i < 21; i++) padded[2 + i] <== DOMAIN[i];
    for (var i = 0; i < 4; i++) padded[23 + i] <== indexBytes.bytes[i];
    for (var i = 0; i < 64; i++) padded[27 + i] <== packedChunk[i];
    padded[MESSAGE_LEN] <== 128;
    for (var i = MESSAGE_LEN + 1; i < 126; i++) padded[i] <== 0;
    padded[126] <== 2;
    padded[127] <== 216; // 91 * 8 = 0x02d8

    signal digestBits[256] <== Sha256Bytes(128)(padded, 128);
    component toBytes = ShaBitsToBytes();
    toBytes.bits <== digestBits;
    digest <== toBytes.bytes;
}

/// SHA-256(u16be(21) || "swiyu-status-node3-v2" || child0 || child1 || child2).
template SwiyuPackedStatusNodeV2() {
    var DOMAIN[21] = [
        115,119,105,121,117,45,115,116,97,116,117,115,
        45,110,111,100,101,51,45,118,50
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

/// SHA-256(u16be(24) || "swiyu-status-snapshot-v2" ||
///          u32be(entryCount) || u64be(epoch) || treeRoot).
template SwiyuPackedStatusSnapshotV2() {
    var DOMAIN[24] = [
        115,119,105,121,117,45,115,116,97,116,117,115,
        45,115,110,97,112,115,104,111,116,45,118,50
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

/// Fixed six-level ternary path over 64-byte chunks of the authenticated
/// packed 2-bit Status List. Four statuses occupy each byte, least-significant
/// pair first. The selected status is derived from `statusIndex`; neither the
/// chunk, byte, nor 2-bit slot can be chosen independently.
template SwiyuPackedStatusChunkMerkleV2() {
    var DEPTH = 6;
    var CHUNK_BYTES = 64;
    var STATUSES_PER_CHUNK = 256;
    var MAX_ENTRIES = 131072;

    signal input statusIndex;
    signal input statusValue;
    signal input packedChunk[CHUNK_BYTES];
    signal input siblings[DEPTH][2][32];
    signal input listLength;
    signal input epoch;
    signal output treeRoot[32];
    signal output snapshotRoot[32];

    component indexRange = Num2Bits(32); indexRange.in <== statusIndex;
    component lengthRange = Num2Bits(32); lengthRange.in <== listLength;
    component epochRange = Num2Bits(64); epochRange.in <== epoch;
    component lengthPositive = GreaterThan(32);
    lengthPositive.in[0] <== listLength;
    lengthPositive.in[1] <== 0;
    lengthPositive.out === 1;
    component lengthCap = LessEqThan(32);
    lengthCap.in[0] <== listLength;
    lengthCap.in[1] <== MAX_ENTRIES;
    lengthCap.out === 1;
    component indexInList = LessThan(32);
    indexInList.in[0] <== statusIndex;
    indexInList.in[1] <== listLength;
    indexInList.out === 1;

    // The signed Status List's authenticated capacity is exactly four entries
    // per decompressed byte. No fractional final byte is accepted.
    signal packedByteLength <-- listLength \ 4;
    listLength === packedByteLength * 4;
    component packedLengthRange = Num2Bits(16);
    packedLengthRange.in <== packedByteLength;

    signal chunkIndex <-- statusIndex \ STATUSES_PER_CHUNK;
    signal localStatusIndex <-- statusIndex % STATUSES_PER_CHUNK;
    statusIndex === chunkIndex * STATUSES_PER_CHUNK + localStatusIndex;
    component chunkIndexRange = Num2Bits(10); chunkIndexRange.in <== chunkIndex;
    component localIndexRange = Num2Bits(8); localIndexRange.in <== localStatusIndex;

    signal byteOffset <-- localStatusIndex \ 4;
    signal statusSlot <-- localStatusIndex % 4;
    localStatusIndex === byteOffset * 4 + statusSlot;
    component byteOffsetRange = Num2Bits(6); byteOffsetRange.in <== byteOffset;
    component statusSlotRange = Num2Bits(2); statusSlotRange.in <== statusSlot;

    // Authenticate canonical zero padding in a partial final chunk. For every
    // byte whose first 2-bit entry is beyond listLength, the byte must be zero.
    signal byteStartStatus[CHUNK_BYTES];
    component realByte[CHUNK_BYTES];
    for (var i = 0; i < CHUNK_BYTES; i++) {
        byteStartStatus[i] <== chunkIndex * STATUSES_PER_CHUNK + i * 4;
        realByte[i] = LessThan(32);
        realByte[i].in[0] <== byteStartStatus[i];
        realByte[i].in[1] <== listLength;
        (1 - realByte[i].out) * packedChunk[i] === 0;
    }

    // Select one byte without dynamic array indexing, then select its exact
    // LSB-first two-bit slot.
    component byteMatch[CHUNK_BYTES];
    signal selectedByteTerms[CHUNK_BYTES];
    signal selectedByteSum[CHUNK_BYTES + 1];
    selectedByteSum[0] <== 0;
    for (var i = 0; i < CHUNK_BYTES; i++) {
        byteMatch[i] = IsEqual();
        byteMatch[i].in[0] <== byteOffset;
        byteMatch[i].in[1] <== i;
        selectedByteTerms[i] <== byteMatch[i].out * packedChunk[i];
        selectedByteSum[i + 1] <== selectedByteSum[i] + selectedByteTerms[i];
    }
    component selectedByteBits = Num2Bits(8);
    selectedByteBits.in <== selectedByteSum[CHUNK_BYTES];
    component slotMatch[4];
    signal slotValues[4];
    signal selectedStatusTerms[4];
    signal selectedStatusSum[5];
    selectedStatusSum[0] <== 0;
    for (var slot = 0; slot < 4; slot++) {
        slotMatch[slot] = IsEqual();
        slotMatch[slot].in[0] <== statusSlot;
        slotMatch[slot].in[1] <== slot;
        slotValues[slot] <== selectedByteBits.out[slot * 2]
            + 2 * selectedByteBits.out[slot * 2 + 1];
        selectedStatusTerms[slot] <== slotMatch[slot].out * slotValues[slot];
        selectedStatusSum[slot + 1] <== selectedStatusSum[slot]
            + selectedStatusTerms[slot];
    }
    component statusRange = Num2Bits(2); statusRange.in <== statusValue;
    statusValue === selectedStatusSum[4];
    statusValue === 0;

    component leaf = SwiyuPackedStatusChunkLeafV2();
    leaf.chunkIndex <== chunkIndex;
    leaf.packedChunk <== packedChunk;

    signal quotient[DEPTH + 1];
    signal trit[DEPTH];
    component tritBits[DEPTH];
    quotient[0] <== chunkIndex;
    for (var level = 0; level < DEPTH; level++) {
        trit[level] <-- quotient[level] % 3;
        quotient[level + 1] <-- quotient[level] \ 3;
        quotient[level] === quotient[level + 1] * 3 + trit[level];
        tritBits[level] = Num2Bits(2);
        tritBits[level].in <== trit[level];
        tritBits[level].out[0] * tritBits[level].out[1] === 0;
    }
    quotient[DEPTH] === 0;

    signal current[DEPTH + 1][32];
    signal children[DEPTH][3][32];
    signal middle01[DEPTH][32];
    for (var i = 0; i < 32; i++) current[0][i] <== leaf.digest[i];
    component nodes[DEPTH];
    for (var level = 0; level < DEPTH; level++) {
        for (var i = 0; i < 32; i++) {
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
        nodes[level] = SwiyuPackedStatusNodeV2();
        nodes[level].children <== children[level];
        for (var i = 0; i < 32; i++) {
            current[level + 1][i] <== nodes[level].digest[i];
        }
    }
    for (var i = 0; i < 32; i++) treeRoot[i] <== current[DEPTH][i];

    component snapshot = SwiyuPackedStatusSnapshotV2();
    snapshot.treeRoot <== treeRoot;
    snapshot.entryCount <== listLength;
    snapshot.epoch <== epoch;
    snapshotRoot <== snapshot.digest;
}

pragma circom 2.2.3;

include "@zk-email/circuits/lib/sha.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

/// SHA-256 commitment to verifier-resolved lookup metadata and the exact
/// challenge.  The 448-byte v1 record has no host-dependent serialization:
///
///   0..21    "swiyu-age18-status-v1\0"
///   22..53   challengeHash as canonical 32-byte big-endian field element
///   54       iss length; 55..166 iss zero-padded to 112 bytes
///   167      kid length; 168..279 kid zero-padded to 112 bytes
///   280      vct length; 281..392 vct zero-padded to 112 bytes
///   393..447 zero
///
/// nbf and exp stay authenticated private inputs and are checked directly by
/// the circuit; they are intentionally not duplicated in this public lookup
/// commitment.
template SwiyuMetadataCommitment(maxStringLen) {
    assert(maxStringLen == 112);
    var PREIMAGE_LEN = 448;
    var SHA_MAX = 512;
    var PREFIX_LEN = 22;
    var PREFIX[PREFIX_LEN] = [
        115,119,105,121,117,45,97,103,101,49,56,45,115,116,97,116,117,115,45,118,49,0
    ];

    signal input challengeHash;
    signal input iss[maxStringLen];
    signal input issLength;
    signal input kid[maxStringLen];
    signal input kidLength;
    signal input vct[maxStringLen];
    signal input vctLength;
    signal output hashHi;
    signal output hashLo;

    component issLenBits = Num2Bits(7); issLenBits.in <== issLength;
    component kidLenBits = Num2Bits(7); kidLenBits.in <== kidLength;
    component vctLenBits = Num2Bits(7); vctLenBits.in <== vctLength;
    component issFits = LessEqThan(7); issFits.in[0] <== issLength; issFits.in[1] <== maxStringLen; issFits.out === 1;
    component kidFits = LessEqThan(7); kidFits.in[0] <== kidLength; kidFits.in[1] <== maxStringLen; kidFits.out === 1;
    component vctFits = LessEqThan(7); vctFits.in[0] <== vctLength; vctFits.in[1] <== maxStringLen; vctFits.out === 1;

    component challengeBits = Num2Bits(256);
    challengeBits.in <== challengeHash;
    var Q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;
    var Q_HI = Q >> 128;
    var Q_LO = Q & ((2 ** 128) - 1);
    component challengeHigh = Bits2Num(128);
    component challengeLow = Bits2Num(128);
    for (var i = 0; i < 128; i++) {
        challengeLow.in[i] <== challengeBits.out[i];
        challengeHigh.in[i] <== challengeBits.out[128 + i];
    }
    component challengeHighLt = LessThan(129);
    challengeHighLt.in[0] <== challengeHigh.out;
    challengeHighLt.in[1] <== Q_HI;
    component challengeHighEq = IsEqual();
    challengeHighEq.in[0] <== challengeHigh.out;
    challengeHighEq.in[1] <== Q_HI;
    component challengeLowLt = LessThan(129);
    challengeLowLt.in[0] <== challengeLow.out;
    challengeLowLt.in[1] <== Q_LO;
    signal equalHighAndLowLess <== challengeHighEq.out * challengeLowLt.out;
    challengeHighLt.out + equalHighAndLowLess === 1;

    component challengeByte[32];
    for (var i = 0; i < 32; i++) {
        challengeByte[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) {
            challengeByte[i].in[j] <== challengeBits.out[(31 - i) * 8 + j];
        }
    }

    signal padded[SHA_MAX];
    var cursor = 0;
    for (var i = 0; i < PREFIX_LEN; i++) {
        padded[cursor] <== PREFIX[i];
        cursor++;
    }
    for (var i = 0; i < 32; i++) {
        padded[cursor] <== challengeByte[i].out;
        cursor++;
    }
    padded[cursor] <== issLength; cursor++;
    for (var i = 0; i < maxStringLen; i++) { padded[cursor] <== iss[i]; cursor++; }
    padded[cursor] <== kidLength; cursor++;
    for (var i = 0; i < maxStringLen; i++) { padded[cursor] <== kid[i]; cursor++; }
    padded[cursor] <== vctLength; cursor++;
    for (var i = 0; i < maxStringLen; i++) { padded[cursor] <== vct[i]; cursor++; }

    for (var i = cursor; i < PREIMAGE_LEN; i++) padded[i] <== 0;

    // SHA-256 padding for exactly 448 bytes (3584 bits = 0x0e00).
    padded[PREIMAGE_LEN] <== 128;
    for (var i = PREIMAGE_LEN + 1; i < SHA_MAX - 8; i++) padded[i] <== 0;
    for (var i = SHA_MAX - 8; i < SHA_MAX - 2; i++) padded[i] <== 0;
    padded[SHA_MAX - 2] <== 14;
    padded[SHA_MAX - 1] <== 0;

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

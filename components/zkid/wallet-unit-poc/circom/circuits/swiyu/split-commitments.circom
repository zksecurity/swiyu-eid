pragma circom 2.2.3;

include "@zk-email/circuits/lib/sha.circom";
include "circomlib/circuits/bitify.circom";

template SwiyuDigestBitsToLimbs() {
    signal input digest[256];
    signal output hi;
    signal output lo;
    component high = Bits2Num(128);
    component low = Bits2Num(128);
    for (var i = 0; i < 128; i++) {
        high.in[127 - i] <== digest[i];
        low.in[127 - i] <== digest[128 + i];
    }
    hi <== high.out;
    lo <== low.out;
}

template SwiyuLimb128ToBytes() {
    signal input limb;
    signal output bytes[16];
    component bits = Num2Bits(128);
    bits.in <== limb;
    component octets[16];
    for (var i = 0; i < 16; i++) {
        octets[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) {
            octets[i].in[j] <== bits.out[(15 - i) * 8 + j];
        }
        bytes[i] <== octets[i].out;
    }
}

template SwiyuScalarToBytes32() {
    signal input scalar;
    signal output bytes[32];
    component bits = Num2Bits(256);
    bits.in <== scalar;
    component octets[32];
    for (var i = 0; i < 32; i++) {
        octets[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) {
            octets[i].in[j] <== bits.out[(31 - i) * 8 + j];
        }
        bytes[i] <== octets[i].out;
    }
}

/// Stable lookup hash authenticated by Prepare:
/// SHA-256(u16be(15) || "swiyu-lookup-v1" || len(iss) || iss[112] ||
///        len(kid) || kid[112] || len(vct) || vct[112]).
template SwiyuLookupStaticCommitment(maxStringLen) {
    assert(maxStringLen == 112);
    var DOMAIN[15] = [115,119,105,121,117,45,108,111,111,107,117,112,45,118,49];
    var MESSAGE_LEN = 356;
    var SHA_LEN = 384;
    signal input iss[maxStringLen];
    signal input issLength;
    signal input kid[maxStringLen];
    signal input kidLength;
    signal input vct[maxStringLen];
    signal input vctLength;
    signal output hashHi;
    signal output hashLo;

    component issLen = Num2Bits(7); issLen.in <== issLength;
    component kidLen = Num2Bits(7); kidLen.in <== kidLength;
    component vctLen = Num2Bits(7); vctLen.in <== vctLength;

    signal padded[SHA_LEN];
    padded[0] <== 0; padded[1] <== 15;
    for (var i = 0; i < 15; i++) padded[2 + i] <== DOMAIN[i];
    padded[17] <== issLength;
    for (var i = 0; i < maxStringLen; i++) padded[18 + i] <== iss[i];
    padded[130] <== kidLength;
    for (var i = 0; i < maxStringLen; i++) padded[131 + i] <== kid[i];
    padded[243] <== vctLength;
    for (var i = 0; i < maxStringLen; i++) padded[244 + i] <== vct[i];
    padded[MESSAGE_LEN] <== 128;
    for (var i = MESSAGE_LEN + 1; i < SHA_LEN - 8; i++) padded[i] <== 0;
    for (var i = SHA_LEN - 8; i < SHA_LEN - 2; i++) padded[i] <== 0;
    padded[SHA_LEN - 2] <== 11;
    padded[SHA_LEN - 1] <== 32; // 356 * 8 = 0x0b20

    signal digest[256] <== Sha256Bytes(SHA_LEN)(padded, SHA_LEN);
    component limbs = SwiyuDigestBitsToLimbs();
    limbs.digest <== digest;
    hashHi <== limbs.hi;
    hashLo <== limbs.lo;
}

/// Stable private status-URI hash authenticated by Prepare.
template SwiyuStatusUriCommitment(maxUriLen) {
    assert(maxUriLen == 160);
    var DOMAIN[19] = [115,119,105,121,117,45,115,116,97,116,117,115,45,117,114,105,45,118,49];
    var MESSAGE_LEN = 182;
    var SHA_LEN = 192;
    signal input uri[maxUriLen];
    signal input uriLength;
    signal output hashHi;
    signal output hashLo;

    component uriLen = Num2Bits(8); uriLen.in <== uriLength;
    signal padded[SHA_LEN];
    padded[0] <== 0; padded[1] <== 19;
    for (var i = 0; i < 19; i++) padded[2 + i] <== DOMAIN[i];
    padded[21] <== uriLength;
    for (var i = 0; i < maxUriLen; i++) padded[22 + i] <== uri[i];
    padded[MESSAGE_LEN] <== 128;
    for (var i = MESSAGE_LEN + 1; i < SHA_LEN - 8; i++) padded[i] <== 0;
    for (var i = SHA_LEN - 8; i < SHA_LEN - 2; i++) padded[i] <== 0;
    padded[SHA_LEN - 2] <== 5;
    padded[SHA_LEN - 1] <== 176; // 182 * 8 = 0x05b0

    signal digest[256] <== Sha256Bytes(SHA_LEN)(padded, SHA_LEN);
    component limbs = SwiyuDigestBitsToLimbs();
    limbs.digest <== digest;
    hashHi <== limbs.hi;
    hashLo <== limbs.lo;
}

/// Challenge-bound public metadata derived from the stable Prepare lookup hash.
template SwiyuPreparedMetadataCommitment() {
    var DOMAIN[16] = [115,119,105,121,117,45,115,101,115,115,105,111,110,45,118,49];
    var MESSAGE_LEN = 82;
    signal input challengeHash;
    signal input lookupHashHi;
    signal input lookupHashLo;
    signal output hashHi;
    signal output hashLo;

    component challenge = SwiyuScalarToBytes32(); challenge.scalar <== challengeHash;
    component lookupHi = SwiyuLimb128ToBytes(); lookupHi.limb <== lookupHashHi;
    component lookupLo = SwiyuLimb128ToBytes(); lookupLo.limb <== lookupHashLo;
    signal padded[128];
    padded[0] <== 0; padded[1] <== 16;
    for (var i = 0; i < 16; i++) padded[2 + i] <== DOMAIN[i];
    for (var i = 0; i < 32; i++) padded[18 + i] <== challenge.bytes[i];
    for (var i = 0; i < 16; i++) padded[50 + i] <== lookupHi.bytes[i];
    for (var i = 0; i < 16; i++) padded[66 + i] <== lookupLo.bytes[i];
    padded[MESSAGE_LEN] <== 128;
    for (var i = MESSAGE_LEN + 1; i < 126; i++) padded[i] <== 0;
    padded[126] <== 2;
    padded[127] <== 144; // 82 * 8 = 0x0290

    signal digest[256] <== Sha256Bytes(128)(padded, 128);
    component limbs = SwiyuDigestBitsToLimbs(); limbs.digest <== digest;
    hashHi <== limbs.hi; hashLo <== limbs.lo;
}

/// Snapshot binding derived from the stable private URI hash and fresh snapshot.
template SwiyuPreparedStatusCommitment() {
    var DOMAIN[20] = [115,119,105,121,117,45,115,116,97,116,117,115,45,98,105,110,100,45,118,49];
    var MESSAGE_LEN = 86;
    signal input uriHashHi;
    signal input uriHashLo;
    signal input snapshotRoot[32];
    signal output hashHi;
    signal output hashLo;

    component uriHi = SwiyuLimb128ToBytes(); uriHi.limb <== uriHashHi;
    component uriLo = SwiyuLimb128ToBytes(); uriLo.limb <== uriHashLo;
    signal padded[128];
    padded[0] <== 0; padded[1] <== 20;
    for (var i = 0; i < 20; i++) padded[2 + i] <== DOMAIN[i];
    for (var i = 0; i < 16; i++) padded[22 + i] <== uriHi.bytes[i];
    for (var i = 0; i < 16; i++) padded[38 + i] <== uriLo.bytes[i];
    for (var i = 0; i < 32; i++) padded[54 + i] <== snapshotRoot[i];
    padded[MESSAGE_LEN] <== 128;
    for (var i = MESSAGE_LEN + 1; i < 126; i++) padded[i] <== 0;
    padded[126] <== 2;
    padded[127] <== 176; // 86 * 8 = 0x02b0

    signal digest[256] <== Sha256Bytes(128)(padded, 128);
    component limbs = SwiyuDigestBitsToLimbs(); limbs.digest <== digest;
    hashHi <== limbs.hi; hashLo <== limbs.lo;
}

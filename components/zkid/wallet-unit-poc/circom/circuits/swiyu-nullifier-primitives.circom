pragma circom 2.2.3;

include "@zk-email/circuits/lib/sha.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

/// Convert the SHA gadget's big-endian bit string into 32 bytes.
template SwiyuNullifierShaBitsToBytes() {
    signal input bits[256];
    signal output bytes[32];
    component octet[32];
    for (var i = 0; i < 32; i++) {
        octet[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) octet[i].in[7 - j] <== bits[i * 8 + j];
        bytes[i] <== octet[i].out;
    }
}

template SwiyuNullifierDigestToLimbs() {
    signal input bytes[32];
    signal output hashHi;
    signal output hashLo;
    component hi = Bits2Num(128);
    component lo = Bits2Num(128);
    component byteBits[32];
    for (var i = 0; i < 32; i++) {
        byteBits[i] = Num2Bits(8);
        byteBits[i].in <== bytes[i];
        for (var j = 0; j < 8; j++) {
            if (i < 16) hi.in[(15 - i) * 8 + j] <== byteBits[i].out[j];
            if (i >= 16) lo.in[(31 - i) * 8 + j] <== byteBits[i].out[j];
        }
    }
    hashHi <== hi.out;
    hashLo <== lo.out;
}

template SwiyuNullifierLimb128ToBytes() {
    signal input limb;
    signal output bytes[16];
    component bits = Num2Bits(128);
    bits.in <== limb;
    component octet[16];
    for (var i = 0; i < 16; i++) {
        octet[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) octet[i].in[j] <== bits.out[(15 - i) * 8 + j];
        bytes[i] <== octet[i].out;
    }
}

/// SHA-256(u16be(13) || "swy-nf-sec-v1" || holderSecret).
///
/// The issuer signs `expectedCommitment` as part of the credential. The
/// one-block relation below prevents a holder from choosing a fresh nullifier
/// secret for every presentation.
template SwiyuNullifierSecretCommitment() {
    var DOMAIN[13] = [115,119,121,45,110,102,45,115,101,99,45,118,49];
    var MESSAGE_LEN = 47;
    signal input holderSecret[32];
    signal input expectedCommitment[32];
    signal output digest[32];

    component secretByte[32];
    component commitmentByte[32];
    signal secretSum[33];
    secretSum[0] <== 0;
    for (var i = 0; i < 32; i++) {
        secretByte[i] = Num2Bits(8); secretByte[i].in <== holderSecret[i];
        commitmentByte[i] = Num2Bits(8); commitmentByte[i].in <== expectedCommitment[i];
        secretSum[i + 1] <== secretSum[i] + holderSecret[i];
    }
    // Misuse resistance: an all-zero wallet secret is never accepted. This
    // does not replace the SDK's CSPRNG requirement.
    component secretIsZero = IsZero();
    secretIsZero.in <== secretSum[32];
    secretIsZero.out === 0;

    signal padded[64];
    padded[0] <== 0; padded[1] <== 13;
    for (var i = 0; i < 13; i++) padded[2 + i] <== DOMAIN[i];
    for (var i = 0; i < 32; i++) padded[15 + i] <== holderSecret[i];
    padded[MESSAGE_LEN] <== 128;
    for (var i = MESSAGE_LEN + 1; i < 62; i++) padded[i] <== 0;
    padded[62] <== 1; padded[63] <== 120; // 47 * 8 = 0x0178

    signal digestBits[256] <== Sha256Bytes(64)(padded, 64);
    component toBytes = SwiyuNullifierShaBitsToBytes();
    toBytes.bits <== digestBits;
    for (var i = 0; i < 32; i++) {
        digest[i] <== toBytes.bytes[i];
        digest[i] === expectedCommitment[i];
    }
}

/// SHA-256(u16be(14) || "swy-nf-cred-v1" || holderSecret ||
///            credentialUid || credentialBindingHash).
///
/// This is computed in reusable Prepare after `credentialUid`, the secret
/// commitment and lookup hash have been authenticated by the issuer relation.
template SwiyuNullifierCredentialSeed() {
    var DOMAIN[14] = [115,119,121,45,110,102,45,99,114,101,100,45,118,49];
    var MESSAGE_LEN = 112;
    signal input holderSecret[32];
    signal input credentialUid[32];
    signal input credentialBindingHashHi;
    signal input credentialBindingHashLo;
    signal output hashHi;
    signal output hashLo;

    component secretByte[32];
    component uidByte[32];
    for (var i = 0; i < 32; i++) {
        secretByte[i] = Num2Bits(8); secretByte[i].in <== holderSecret[i];
        uidByte[i] = Num2Bits(8); uidByte[i].in <== credentialUid[i];
    }
    component bindingHi = SwiyuNullifierLimb128ToBytes(); bindingHi.limb <== credentialBindingHashHi;
    component bindingLo = SwiyuNullifierLimb128ToBytes(); bindingLo.limb <== credentialBindingHashLo;

    signal padded[128];
    padded[0] <== 0; padded[1] <== 14;
    for (var i = 0; i < 14; i++) padded[2 + i] <== DOMAIN[i];
    for (var i = 0; i < 32; i++) padded[16 + i] <== holderSecret[i];
    for (var i = 0; i < 32; i++) padded[48 + i] <== credentialUid[i];
    for (var i = 0; i < 16; i++) padded[80 + i] <== bindingHi.bytes[i];
    for (var i = 0; i < 16; i++) padded[96 + i] <== bindingLo.bytes[i];
    padded[MESSAGE_LEN] <== 128;
    for (var i = MESSAGE_LEN + 1; i < 126; i++) padded[i] <== 0;
    padded[126] <== 3; padded[127] <== 128; // 112 * 8 = 0x0380

    signal digestBits[256] <== Sha256Bytes(128)(padded, 128);
    component toBytes = SwiyuNullifierShaBitsToBytes(); toBytes.bits <== digestBits;
    component limbs = SwiyuNullifierDigestToLimbs(); limbs.bytes <== toBytes.bytes;
    hashHi <== limbs.hashHi;
    hashLo <== limbs.hashLo;
}

/// Canonical issuer-authenticated record for the nullifier attributes:
/// SHA-256(u16be(14) || "swy-nf-attr-v1" || credentialUid ||
///            secretCommitment || credentialBindingHash).
///
/// The 112-byte record is exposed as one complete 128-byte SHA-256 padded
/// block pair so `ES256(128)` can authenticate the exact tuple without another
/// variable-layout JSON parser in this composable core. The zk-email ES256
/// gadget consumes SHA-padded bytes and a padded length; it does not append the
/// 0x80 delimiter or bit length itself.
template SwiyuNullifierIssuerRecord() {
    var DOMAIN[14] = [115,119,121,45,110,102,45,97,116,116,114,45,118,49];
    var MESSAGE_LEN = 112;
    signal input credentialUid[32];
    signal input secretCommitment[32];
    signal input credentialBindingHashHi;
    signal input credentialBindingHashLo;
    signal output padded[128];

    component uidByte[32];
    component commitmentByte[32];
    for (var i = 0; i < 32; i++) {
        uidByte[i] = Num2Bits(8); uidByte[i].in <== credentialUid[i];
        commitmentByte[i] = Num2Bits(8); commitmentByte[i].in <== secretCommitment[i];
    }
    component bindingHi = SwiyuNullifierLimb128ToBytes(); bindingHi.limb <== credentialBindingHashHi;
    component bindingLo = SwiyuNullifierLimb128ToBytes(); bindingLo.limb <== credentialBindingHashLo;

    padded[0] <== 0; padded[1] <== 14;
    for (var i = 0; i < 14; i++) padded[2 + i] <== DOMAIN[i];
    for (var i = 0; i < 32; i++) padded[16 + i] <== credentialUid[i];
    for (var i = 0; i < 32; i++) padded[48 + i] <== secretCommitment[i];
    for (var i = 0; i < 16; i++) padded[80 + i] <== bindingHi.bytes[i];
    for (var i = 0; i < 16; i++) padded[96 + i] <== bindingLo.bytes[i];
    padded[MESSAGE_LEN] <== 128;
    for (var i = MESSAGE_LEN + 1; i < 126; i++) padded[i] <== 0;
    padded[126] <== 3; padded[127] <== 128; // 112 * 8 = 0x0380
}

/// SHA-256(u16be(13) || "swy-nf-val-v1" || credentialSeed || scopeDigest).
template SwiyuScopedNullifier() {
    var DOMAIN[13] = [115,119,121,45,110,102,45,118,97,108,45,118,49];
    var MESSAGE_LEN = 79;
    signal input credentialSeedHi;
    signal input credentialSeedLo;
    signal input scopeDigestHi;
    signal input scopeDigestLo;
    signal output hashHi;
    signal output hashLo;

    component seedHi = SwiyuNullifierLimb128ToBytes(); seedHi.limb <== credentialSeedHi;
    component seedLo = SwiyuNullifierLimb128ToBytes(); seedLo.limb <== credentialSeedLo;
    component scopeHi = SwiyuNullifierLimb128ToBytes(); scopeHi.limb <== scopeDigestHi;
    component scopeLo = SwiyuNullifierLimb128ToBytes(); scopeLo.limb <== scopeDigestLo;

    signal padded[128];
    padded[0] <== 0; padded[1] <== 13;
    for (var i = 0; i < 13; i++) padded[2 + i] <== DOMAIN[i];
    for (var i = 0; i < 16; i++) padded[15 + i] <== seedHi.bytes[i];
    for (var i = 0; i < 16; i++) padded[31 + i] <== seedLo.bytes[i];
    for (var i = 0; i < 16; i++) padded[47 + i] <== scopeHi.bytes[i];
    for (var i = 0; i < 16; i++) padded[63 + i] <== scopeLo.bytes[i];
    padded[MESSAGE_LEN] <== 128;
    for (var i = MESSAGE_LEN + 1; i < 126; i++) padded[i] <== 0;
    padded[126] <== 2; padded[127] <== 120; // 79 * 8 = 0x0278

    signal digestBits[256] <== Sha256Bytes(128)(padded, 128);
    component toBytes = SwiyuNullifierShaBitsToBytes(); toBytes.bits <== digestBits;
    component limbs = SwiyuNullifierDigestToLimbs(); limbs.bytes <== toBytes.bytes;
    hashHi <== limbs.hashHi;
    hashLo <== limbs.hashLo;
}

pragma circom 2.2.3;

include "ecdsa/ecdsa.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "swiyu/status-merkle-packed-chunk.circom";
include "swiyu/split-commitments.circom";
include "swiyu/p256.circom";

/// Versioned A/B of residence Show. Only the status authentication profile is
/// changed; the holder, freshness, residence, allow-list, and linkage relation
/// is byte-for-byte equivalent in meaning to the legacy ternary control.
template SwiyuResidenceShowPackedChunkV2() {
    var STATUS_DEPTH = 6;
    signal input holderKeyX;
    signal input holderKeyY;
    signal input packedResidence;
    signal input credentialNbf;
    signal input credentialExp;
    signal input statusIndex;
    signal input lookupHashHi;
    signal input lookupHashLo;
    signal input statusUriHashHi;
    signal input statusUriHashLo;

    signal input holderSigR;
    signal input holderSigSInverse;
    signal input statusValue;
    signal input statusChunk[64];
    signal input statusSiblings[STATUS_DEPTH][2][32];
    signal input statusEpoch;
    signal input statusListLength;

    signal input challengeHash;
    signal input allowedCount;
    signal input allowedMunicipalityCodes[16];
    signal input minimumResidenceDays;
    signal input currentTime;
    signal input expectedMetadataHashHi;
    signal input expectedMetadataHashLo;
    signal input expectedStatusSnapshotHashHi;
    signal input expectedStatusSnapshotHashLo;

    signal output splitShared[10];
    signal output expressionResult;
    splitShared[0] <== holderKeyX;
    splitShared[1] <== holderKeyY;
    splitShared[2] <== packedResidence;
    splitShared[3] <== credentialNbf;
    splitShared[4] <== credentialExp;
    splitShared[5] <== statusIndex;
    splitShared[6] <== lookupHashHi;
    splitShared[7] <== lookupHashLo;
    splitShared[8] <== statusUriHashHi;
    splitShared[9] <== statusUriHashLo;

    component packedBits = Num2Bits(30); packedBits.in <== packedResidence;
    component municipalityFromBits = Bits2Num(13);
    component sinceFromBits = Bits2Num(17);
    for (var i = 0; i < 13; i++) municipalityFromBits.in[i] <== packedBits.out[i];
    for (var i = 0; i < 17; i++) sinceFromBits.in[i] <== packedBits.out[13 + i];
    signal municipalityBfs <== municipalityFromBits.out;
    signal residenceSinceDay1900 <== sinceFromBits.out;
    component municipalityPositive = GreaterEqThan(13);
    municipalityPositive.in[0] <== municipalityBfs;
    municipalityPositive.in[1] <== 1;
    municipalityPositive.out === 1;
    component municipalityMax = LessEqThan(13);
    municipalityMax.in[0] <== municipalityBfs;
    municipalityMax.in[1] <== 6999;
    municipalityMax.out === 1;

    component holderPoint = AssertP256Point();
    holderPoint.x <== holderKeyX;
    holderPoint.y <== holderKeyY;
    component holderSignature = ECDSA();
    holderSignature.s_inverse <== holderSigSInverse;
    holderSignature.r <== holderSigR;
    holderSignature.m <== challengeHash;
    holderSignature.pubKeyX <== holderKeyX;
    holderSignature.pubKeyY <== holderKeyY;

    component nbfBeforeNow = LessEqThan(64);
    nbfBeforeNow.in[0] <== credentialNbf;
    nbfBeforeNow.in[1] <== currentTime;
    nbfBeforeNow.out === 1;
    component nowBeforeExp = LessThan(64);
    nowBeforeExp.in[0] <== currentTime;
    nowBeforeExp.in[1] <== credentialExp;
    nowBeforeExp.out === 1;
    component nowBits = Num2Bits(64); nowBits.in <== currentTime;

    signal unixDay <-- currentTime \ 86400;
    signal secondsInDay <== currentTime - unixDay * 86400;
    component unixDayBits = Num2Bits(17); unixDayBits.in <== unixDay;
    component secondBits = Num2Bits(17); secondBits.in <== secondsInDay;
    component secondBound = LessThan(17);
    secondBound.in[0] <== secondsInDay;
    secondBound.in[1] <== 86400;
    secondBound.out === 1;
    signal currentDay1900 <== unixDay + 25567;
    component currentDayBits = Num2Bits(18); currentDayBits.in <== currentDay1900;
    component supportedDateMax = LessEqThan(18);
    supportedDateMax.in[0] <== currentDay1900;
    supportedDateMax.in[1] <== 109572;
    supportedDateMax.out === 1;

    component minimumBits = Num2Bits(12); minimumBits.in <== minimumResidenceDays;
    component minimumPositive = GreaterEqThan(12);
    minimumPositive.in[0] <== minimumResidenceDays;
    minimumPositive.in[1] <== 1;
    minimumPositive.out === 1;
    component minimumMax = LessEqThan(12);
    minimumMax.in[0] <== minimumResidenceDays;
    minimumMax.in[1] <== 3650;
    minimumMax.out === 1;
    signal eligibleDay <== residenceSinceDay1900 + minimumResidenceDays;
    component eligibleDayBits = Num2Bits(18); eligibleDayBits.in <== eligibleDay;
    component durationSatisfied = LessEqThan(18);
    durationSatisfied.in[0] <== eligibleDay;
    durationSatisfied.in[1] <== currentDay1900;
    durationSatisfied.out === 1;

    component countBits = Num2Bits(5); countBits.in <== allowedCount;
    component countMin = GreaterEqThan(5);
    countMin.in[0] <== allowedCount;
    countMin.in[1] <== 1;
    countMin.out === 1;
    component countMax = LessEqThan(5);
    countMax.in[0] <== allowedCount;
    countMax.in[1] <== 16;
    countMax.out === 1;
    component enabled[16];
    component equal[16];
    signal matches[17];
    matches[0] <== 0;
    for (var i = 0; i < 16; i++) {
        enabled[i] = LessThan(5);
        enabled[i].in[0] <== i;
        enabled[i].in[1] <== allowedCount;
        equal[i] = IsEqual();
        equal[i].in[0] <== municipalityBfs;
        equal[i].in[1] <== allowedMunicipalityCodes[i];
        (1 - enabled[i].out) * allowedMunicipalityCodes[i] === 0;
        matches[i + 1] <== matches[i] + enabled[i].out * equal[i].out;
    }
    expressionResult <== matches[16];
    expressionResult === 1;

    component statusProof = SwiyuPackedStatusChunkMerkleV2();
    statusProof.statusIndex <== statusIndex;
    statusProof.statusValue <== statusValue;
    statusProof.packedChunk <== statusChunk;
    statusProof.siblings <== statusSiblings;
    statusProof.listLength <== statusListLength;
    statusProof.epoch <== statusEpoch;
    component statusBinding = SwiyuPreparedStatusCommitment();
    statusBinding.uriHashHi <== statusUriHashHi;
    statusBinding.uriHashLo <== statusUriHashLo;
    statusBinding.snapshotRoot <== statusProof.snapshotRoot;
    statusBinding.hashHi === expectedStatusSnapshotHashHi;
    statusBinding.hashLo === expectedStatusSnapshotHashLo;

    component metadata = SwiyuPreparedMetadataCommitment();
    metadata.challengeHash <== challengeHash;
    metadata.lookupHashHi <== lookupHashHi;
    metadata.lookupHashLo <== lookupHashLo;
    metadata.hashHi === expectedMetadataHashHi;
    metadata.hashLo === expectedMetadataHashLo;
}

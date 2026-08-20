pragma circom 2.2.3;

include "ecdsa/ecdsa.circom";
include "circomlib/circuits/comparators.circom";
include "swiyu/status-merkle.circom";
include "swiyu/split-commitments.circom";
include "swiyu/p256.circom";

/// Online proof that an issuer-authenticated Swiss residence canton belongs
/// to a verifier-published allow-list of one to four cantons.
template SwiyuCantonShowSplit(statusDepth) {
    signal input holderKeyX;
    signal input holderKeyY;
    signal input cantonCode;
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
    signal input statusSiblings[statusDepth][32];
    signal input statusEpoch;
    signal input statusListLength;

    signal input challengeHash;
    signal input allowedCount;
    signal input allowedCantonCodes[4];
    signal input currentTime;
    signal input expectedMetadataHashHi;
    signal input expectedMetadataHashLo;
    signal input expectedStatusSnapshotHashHi;
    signal input expectedStatusSnapshotHashLo;

    signal output splitShared[10];
    signal output expressionResult;
    splitShared[0] <== holderKeyX;
    splitShared[1] <== holderKeyY;
    splitShared[2] <== cantonCode;
    splitShared[3] <== credentialNbf;
    splitShared[4] <== credentialExp;
    splitShared[5] <== statusIndex;
    splitShared[6] <== lookupHashHi;
    splitShared[7] <== lookupHashLo;
    splitShared[8] <== statusUriHashHi;
    splitShared[9] <== statusUriHashLo;

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

    component statusProof = SwiyuStatusMerkle(statusDepth);
    statusProof.statusIndex <== statusIndex;
    statusProof.statusValue <== statusValue;
    statusProof.siblings <== statusSiblings;
    statusProof.listLength <== statusListLength;
    statusProof.epoch <== statusEpoch;
    component statusBinding = SwiyuPreparedStatusCommitment();
    statusBinding.uriHashHi <== statusUriHashHi;
    statusBinding.uriHashLo <== statusUriHashLo;
    statusBinding.snapshotRoot <== statusProof.snapshotRoot;
    statusBinding.hashHi === expectedStatusSnapshotHashHi;
    statusBinding.hashLo === expectedStatusSnapshotHashLo;

    component countMin = GreaterEqThan(3);
    countMin.in[0] <== allowedCount;
    countMin.in[1] <== 1;
    countMin.out === 1;
    component countMax = LessEqThan(3);
    countMax.in[0] <== allowedCount;
    countMax.in[1] <== 4;
    countMax.out === 1;
    component countBits = Num2Bits(3); countBits.in <== allowedCount;

    component enabled[4];
    component equal[4];
    signal matches[5];
    matches[0] <== 0;
    for (var i = 0; i < 4; i++) {
        enabled[i] = LessThan(3);
        enabled[i].in[0] <== i;
        enabled[i].in[1] <== allowedCount;
        equal[i] = IsEqual();
        equal[i].in[0] <== cantonCode;
        equal[i].in[1] <== allowedCantonCodes[i];
        (1 - enabled[i].out) * allowedCantonCodes[i] === 0;
        matches[i + 1] <== matches[i] + enabled[i].out * equal[i].out;
    }
    expressionResult <== matches[4];
    expressionResult === 1;

    component metadata = SwiyuPreparedMetadataCommitment();
    metadata.challengeHash <== challengeHash;
    metadata.lookupHashHi <== lookupHashHi;
    metadata.lookupHashLo <== lookupHashLo;
    metadata.hashHi === expectedMetadataHashHi;
    metadata.hashLo === expectedMetadataHashLo;
}

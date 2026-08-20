pragma circom 2.2.3;

include "ecdsa/ecdsa.circom";
include "circomlib/circuits/comparators.circom";
include "swiyu/status-merkle-packed-chunk.circom";
include "swiyu/split-commitments.circom";
include "swiyu/p256.circom";

/// Versioned A/B of the age Show relation using the authenticated packed
/// Status List byte array. The legacy depth-17 binary circuit remains intact.
template SwiyuAge18ShowPackedChunkV2() {
    var STATUS_DEPTH = 6;
    signal input holderKeyX;
    signal input holderKeyY;
    signal input birthdateNumeric;
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
    signal input cutoffDate;
    signal input currentTime;
    signal input expectedMetadataHashHi;
    signal input expectedMetadataHashLo;
    signal input expectedStatusSnapshotHashHi;
    signal input expectedStatusSnapshotHashLo;

    signal output splitShared[10];
    signal output expressionResult;
    splitShared[0] <== holderKeyX;
    splitShared[1] <== holderKeyY;
    splitShared[2] <== birthdateNumeric;
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

    component agePredicate = LessEqThan(32);
    agePredicate.in[0] <== birthdateNumeric;
    agePredicate.in[1] <== cutoffDate;
    component cutoffBits = Num2Bits(32); cutoffBits.in <== cutoffDate;
    expressionResult <== agePredicate.out;
    expressionResult === 1;

    component metadata = SwiyuPreparedMetadataCommitment();
    metadata.challengeHash <== challengeHash;
    metadata.lookupHashHi <== lookupHashHi;
    metadata.lookupHashLo <== lookupHashLo;
    metadata.hashHi === expectedMetadataHashHi;
    metadata.hashLo === expectedMetadataHashLo;
}

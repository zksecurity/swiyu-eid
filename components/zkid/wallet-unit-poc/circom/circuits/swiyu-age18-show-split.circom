pragma circom 2.2.3;

include "ecdsa/ecdsa.circom";
include "circomlib/circuits/comparators.circom";
include "swiyu/status-merkle.circom";
include "swiyu/split-commitments.circom";
include "swiyu/p256.circom";

/// Online stage for the sound Prepare/Show benchmark.
///
/// The first ten outputs and the constant result output are reclassified by
/// the native wrapper as hidden Spartan shared-witness rows. Reusing the exact
/// allocated rows in the Circom R1CS binds every online value to Prepare's
/// issuer-authenticated outputs before the two proof commitments are compared.
template SwiyuAge18ShowSplit(statusDepth) {
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
    signal input statusSiblings[statusDepth][32];
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

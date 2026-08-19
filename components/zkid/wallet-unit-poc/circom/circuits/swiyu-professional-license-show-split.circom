pragma circom 2.2.3;

include "ecdsa/ecdsa.circom";
include "circomlib/circuits/comparators.circom";
include "swiyu/status-merkle.circom";
include "swiyu/split-commitments.circom";
include "swiyu/p256.circom";

/// Online proof that an issuer-authenticated professional credential remains
/// valid through a verifier-selected service date without revealing its exact
/// expiry, status-list position, holder key, or credential lookup tuple.
///
/// The shared output layout intentionally matches SwiyuAge18Status Prepare.
/// The exact rows are committed by Spartan and constrained by both relations.
template SwiyuProfessionalLicenseShowSplit(statusDepth) {
    signal input holderKeyX;
    signal input holderKeyY;
    signal input unusedPreparedPredicateValue;
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
    signal input currentTime;
    signal input requiredValidUntil;
    signal input expectedMetadataHashHi;
    signal input expectedMetadataHashLo;
    signal input expectedStatusSnapshotHashHi;
    signal input expectedStatusSnapshotHashLo;

    signal output splitShared[10];
    signal output expressionResult;
    splitShared[0] <== holderKeyX;
    splitShared[1] <== holderKeyY;
    splitShared[2] <== unusedPreparedPredicateValue;
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

    // `exp` is already constrained to the issuer-signed JSON value by Prepare.
    // Enforce ordinary current validity and the stronger business policy that
    // the licence covers the verifier's complete required service period.
    component nbfBeforeNow = LessEqThan(64);
    nbfBeforeNow.in[0] <== credentialNbf;
    nbfBeforeNow.in[1] <== currentTime;
    nbfBeforeNow.out === 1;
    component nowBeforeExp = LessThan(64);
    nowBeforeExp.in[0] <== currentTime;
    nowBeforeExp.in[1] <== credentialExp;
    nowBeforeExp.out === 1;
    // JWT `exp` is exclusive, so equality at the requested end instant is not
    // enough: the credential must expire strictly after the complete period.
    component validThrough = LessThan(64);
    validThrough.in[0] <== requiredValidUntil;
    validThrough.in[1] <== credentialExp;
    expressionResult <== validThrough.out;
    expressionResult === 1;
    component nowBits = Num2Bits(64); nowBits.in <== currentTime;
    component requiredBits = Num2Bits(64); requiredBits.in <== requiredValidUntil;
    component currentBeforeRequired = LessThan(64);
    currentBeforeRequired.in[0] <== currentTime;
    currentBeforeRequired.in[1] <== requiredValidUntil;
    currentBeforeRequired.out === 1;

    // The credential must occupy an exact VALID (00) entry in the authenticated
    // dense status snapshot; URI and root are bound to public verifier context.
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

    component metadata = SwiyuPreparedMetadataCommitment();
    metadata.challengeHash <== challengeHash;
    metadata.lookupHashHi <== lookupHashHi;
    metadata.lookupHashLo <== lookupHashLo;
    metadata.hashHi === expectedMetadataHashHi;
    metadata.hashLo === expectedMetadataHashLo;
}

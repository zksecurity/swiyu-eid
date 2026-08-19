pragma circom 2.2.3;

include "swiyu-age18-show-packed-chunk.circom";
include "swiyu-nullifier-show.circom";

/// Versioned packed-status A/B for the integrated age/nullifier Show relation.
template SwiyuNullifierAge18ShowPackedChunkV2() {
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
    signal input credentialSeedHi;
    signal input credentialSeedLo;
    signal input scopeDigestHi;
    signal input scopeDigestLo;
    signal input expectedNullifierHi;
    signal input expectedNullifierLo;

    signal output splitShared[12];
    signal output expressionResult;

    component age = SwiyuAge18ShowPackedChunkV2();
    age.holderKeyX <== holderKeyX; age.holderKeyY <== holderKeyY;
    age.birthdateNumeric <== birthdateNumeric; age.credentialNbf <== credentialNbf;
    age.credentialExp <== credentialExp; age.statusIndex <== statusIndex;
    age.lookupHashHi <== lookupHashHi; age.lookupHashLo <== lookupHashLo;
    age.statusUriHashHi <== statusUriHashHi; age.statusUriHashLo <== statusUriHashLo;
    age.holderSigR <== holderSigR; age.holderSigSInverse <== holderSigSInverse;
    age.statusValue <== statusValue; age.statusChunk <== statusChunk;
    age.statusSiblings <== statusSiblings;
    age.statusEpoch <== statusEpoch; age.statusListLength <== statusListLength;
    age.challengeHash <== challengeHash; age.cutoffDate <== cutoffDate;
    age.currentTime <== currentTime;
    age.expectedMetadataHashHi <== expectedMetadataHashHi;
    age.expectedMetadataHashLo <== expectedMetadataHashLo;
    age.expectedStatusSnapshotHashHi <== expectedStatusSnapshotHashHi;
    age.expectedStatusSnapshotHashLo <== expectedStatusSnapshotHashLo;

    component nf = SwiyuNullifierShow();
    nf.credentialSeedHi <== credentialSeedHi; nf.credentialSeedLo <== credentialSeedLo;
    nf.scopeDigestHi <== scopeDigestHi; nf.scopeDigestLo <== scopeDigestLo;
    nf.expectedNullifierHi <== expectedNullifierHi; nf.expectedNullifierLo <== expectedNullifierLo;

    for (var i = 0; i < 10; i++) splitShared[i] <== age.splitShared[i];
    splitShared[10] <== nf.splitShared[0];
    splitShared[11] <== nf.splitShared[1];
    expressionResult <== age.expressionResult * nf.expressionResult;
    expressionResult === 1;
}

pragma circom 2.2.3;

include "swiyu-age18-status.circom";
include "swiyu-nullifier-prepare.circom";

/// Integrated age-over-18 + scoped-nullifier Prepare experiment.
///
/// The ordinary swiyu compact-JWS relation authenticates the age credential.
/// Until the production credential schema carries `credential_uid` and
/// `secret_commitment` inside that same JWS, this experiment authenticates the
/// nullifier attributes with a second ES256 signature by the same issuer. It
/// is sound, but the extra signature is an integration boundary and its cost
/// must not be attributed to an inevitable nullifier hash.
template SwiyuNullifierAge18Prepare() {
    var MAX_MESSAGE = 896;
    var MAX_STRING = 112;
    var MAX_URI = 160;
    var MAX_KEY_B64 = 44;
    var STATUS_DEPTH = 17;

    signal input issuerPubKeyX;
    signal input issuerPubKeyY;
    signal input challengeHash;
    signal input cutoffDate;
    signal input currentTime;
    signal input expectedMetadataHashHi;
    signal input expectedMetadataHashLo;
    signal input expectedStatusSnapshotHashHi;
    signal input expectedStatusSnapshotHashLo;
    signal input message[MAX_MESSAGE];
    signal input messageLength;
    signal input periodIndex;
    signal input headerJsonLength;
    signal input payloadJsonLength;
    signal input issuerSigR;
    signal input issuerSigSInverse;
    signal input disclosurePadded[128];
    signal input disclosureLength;
    signal input disclosureJsonLength;
    signal input disclosureSaltLength;
    signal input holderSigR;
    signal input holderSigSInverse;
    signal input iss[MAX_STRING];
    signal input issLength;
    signal input kid[MAX_STRING];
    signal input kidLength;
    signal input vct[MAX_STRING];
    signal input vctLength;
    signal input holderXB64[MAX_KEY_B64];
    signal input holderYB64[MAX_KEY_B64];
    signal input statusUri[MAX_URI];
    signal input statusUriLength;
    signal input nbfDigitLength;
    signal input expDigitLength;
    signal input statusIndexDigitLength;
    signal input disclosureDigestB64[43];
    signal input statusValue;
    signal input statusSiblings[STATUS_DEPTH][32];
    signal input statusEpoch;
    signal input statusListLength;
    signal input headerAlgKeyStart;
    signal input headerTypKeyStart;
    signal input headerKidKeyStart;
    signal input headerProfileVersionKeyStart;
    signal input payloadIssKeyStart;
    signal input payloadVctKeyStart;
    signal input payloadNbfKeyStart;
    signal input payloadExpKeyStart;
    signal input payloadCnfKeyStart;
    signal input payloadCnfClose;
    signal input payloadJwkKeyStart;
    signal input payloadJwkClose;
    signal input payloadKtyKeyStart;
    signal input payloadCrvKeyStart;
    signal input payloadXKeyStart;
    signal input payloadYKeyStart;
    signal input payloadStatusKeyStart;
    signal input payloadStatusClose;
    signal input payloadStatusListKeyStart;
    signal input payloadStatusListClose;
    signal input payloadStatusUriKeyStart;
    signal input payloadStatusIdxKeyStart;
    signal input payloadSdAlgKeyStart;
    signal input payloadSdKeyStart;
    signal input payloadSdClose;
    signal input payloadDigestStart;

    signal input nullifierIssuerSigR;
    signal input nullifierIssuerSigSInverse;
    signal input nullifierHolderSecret[32];
    signal input credentialUid[32];
    signal input secretCommitment[32];

    signal output splitShared[12];
    signal output expressionResult;

    component age = SwiyuAge18Status(896, 256, 600, 17, 0, 1, 1);
    age.issuerPubKeyX <== issuerPubKeyX; age.issuerPubKeyY <== issuerPubKeyY;
    age.challengeHash <== challengeHash; age.cutoffDate <== cutoffDate; age.currentTime <== currentTime;
    age.expectedMetadataHashHi <== expectedMetadataHashHi; age.expectedMetadataHashLo <== expectedMetadataHashLo;
    age.expectedStatusSnapshotHashHi <== expectedStatusSnapshotHashHi;
    age.expectedStatusSnapshotHashLo <== expectedStatusSnapshotHashLo;
    age.message <== message; age.messageLength <== messageLength; age.periodIndex <== periodIndex;
    age.headerJsonLength <== headerJsonLength; age.payloadJsonLength <== payloadJsonLength;
    age.issuerSigR <== issuerSigR; age.issuerSigSInverse <== issuerSigSInverse;
    age.disclosurePadded <== disclosurePadded; age.disclosureLength <== disclosureLength;
    age.disclosureJsonLength <== disclosureJsonLength; age.disclosureSaltLength <== disclosureSaltLength;
    age.holderSigR <== holderSigR; age.holderSigSInverse <== holderSigSInverse;
    age.iss <== iss; age.issLength <== issLength; age.kid <== kid; age.kidLength <== kidLength;
    age.vct <== vct; age.vctLength <== vctLength;
    age.holderXB64 <== holderXB64; age.holderYB64 <== holderYB64;
    age.statusUri <== statusUri; age.statusUriLength <== statusUriLength;
    age.nbfDigitLength <== nbfDigitLength; age.expDigitLength <== expDigitLength;
    age.statusIndexDigitLength <== statusIndexDigitLength; age.disclosureDigestB64 <== disclosureDigestB64;
    age.statusValue <== statusValue; age.statusSiblings <== statusSiblings;
    age.statusEpoch <== statusEpoch; age.statusListLength <== statusListLength;
    age.headerAlgKeyStart <== headerAlgKeyStart; age.headerTypKeyStart <== headerTypKeyStart;
    age.headerKidKeyStart <== headerKidKeyStart;
    age.headerProfileVersionKeyStart <== headerProfileVersionKeyStart;
    age.payloadIssKeyStart <== payloadIssKeyStart; age.payloadVctKeyStart <== payloadVctKeyStart;
    age.payloadNbfKeyStart <== payloadNbfKeyStart; age.payloadExpKeyStart <== payloadExpKeyStart;
    age.payloadCnfKeyStart <== payloadCnfKeyStart; age.payloadCnfClose <== payloadCnfClose;
    age.payloadJwkKeyStart <== payloadJwkKeyStart; age.payloadJwkClose <== payloadJwkClose;
    age.payloadKtyKeyStart <== payloadKtyKeyStart; age.payloadCrvKeyStart <== payloadCrvKeyStart;
    age.payloadXKeyStart <== payloadXKeyStart; age.payloadYKeyStart <== payloadYKeyStart;
    age.payloadStatusKeyStart <== payloadStatusKeyStart; age.payloadStatusClose <== payloadStatusClose;
    age.payloadStatusListKeyStart <== payloadStatusListKeyStart;
    age.payloadStatusListClose <== payloadStatusListClose;
    age.payloadStatusUriKeyStart <== payloadStatusUriKeyStart;
    age.payloadStatusIdxKeyStart <== payloadStatusIdxKeyStart;
    age.payloadSdAlgKeyStart <== payloadSdAlgKeyStart; age.payloadSdKeyStart <== payloadSdKeyStart;
    age.payloadSdClose <== payloadSdClose; age.payloadDigestStart <== payloadDigestStart;

    component nf = SwiyuNullifierAuthenticatedPrepare();
    nf.issuerPubKeyX <== issuerPubKeyX; nf.issuerPubKeyY <== issuerPubKeyY;
    nf.issuerSigR <== nullifierIssuerSigR; nf.issuerSigSInverse <== nullifierIssuerSigSInverse;
    nf.holderSecret <== nullifierHolderSecret; nf.credentialUid <== credentialUid;
    nf.secretCommitment <== secretCommitment;
    // Reuse the digest already computed for issuer ES256 verification. This
    // binds the auxiliary attestation to the exact protected JWS bytes and
    // removes a second six-block SHA over a semantic row projection.
    nf.credentialBindingHashHi <== age.credentialDigest[0];
    nf.credentialBindingHashLo <== age.credentialDigest[1];

    for (var i = 0; i < 10; i++) splitShared[i] <== age.splitShared[i];
    splitShared[10] <== nf.splitShared[0];
    splitShared[11] <== nf.splitShared[1];
    expressionResult <== age.expressionResult * nf.expressionResult;
    expressionResult === 1;
}

pragma circom 2.2.3;

include "utils/es256.circom";
include "swiyu/p256.circom";
include "swiyu-nullifier-primitives.circom";

/// Standalone authenticated Prepare relation for the generic nullifier core.
///
/// Full predicate profiles should instantiate `SwiyuNullifierPrepareBinding`
/// after their ordinary compact-JWS parser has extracted `credentialUid` and
/// `secretCommitment`. This standalone wrapper instead verifies an auxiliary
/// issuer ES256 signature over the same fixed tuple, which makes the core
/// independently benchmarkable without pretending that caller-supplied fields
/// are authenticated.
template SwiyuNullifierPrepareBinding() {
    signal input holderSecret[32];
    signal input credentialUid[32];
    signal input secretCommitment[32];
    signal input credentialBindingHashHi;
    signal input credentialBindingHashLo;
    signal output credentialSeedHi;
    signal output credentialSeedLo;

    component secretBinding = SwiyuNullifierSecretCommitment();
    secretBinding.holderSecret <== holderSecret;
    secretBinding.expectedCommitment <== secretCommitment;

    component seed = SwiyuNullifierCredentialSeed();
    seed.holderSecret <== holderSecret;
    seed.credentialUid <== credentialUid;
    seed.credentialBindingHashHi <== credentialBindingHashHi;
    seed.credentialBindingHashLo <== credentialBindingHashLo;
    credentialSeedHi <== seed.hashHi;
    credentialSeedLo <== seed.hashLo;
}

template SwiyuNullifierAuthenticatedPrepare() {
    signal input issuerPubKeyX;
    signal input issuerPubKeyY;
    signal input issuerSigR;
    signal input issuerSigSInverse;
    signal input holderSecret[32];
    signal input credentialUid[32];
    signal input secretCommitment[32];
    signal input credentialBindingHashHi;
    signal input credentialBindingHashLo;

    signal output splitShared[2];
    signal output expressionResult;

    component issuerPoint = AssertP256Point();
    issuerPoint.x <== issuerPubKeyX;
    issuerPoint.y <== issuerPubKeyY;

    component issuerRecord = SwiyuNullifierIssuerRecord();
    issuerRecord.credentialUid <== credentialUid;
    issuerRecord.secretCommitment <== secretCommitment;
    issuerRecord.credentialBindingHashHi <== credentialBindingHashHi;
    issuerRecord.credentialBindingHashLo <== credentialBindingHashLo;

    component issuerSignature = ES256(128);
    issuerSignature.message <== issuerRecord.padded;
    // Sha256Bytes expects the already-padded length, not the raw preimage
    // length. issuerRecord.padded is SHA-256(raw 112-byte issuer record).
    issuerSignature.messageLength <== 128;
    issuerSignature.sig_r <== issuerSigR;
    issuerSignature.sig_s_inverse <== issuerSigSInverse;
    issuerSignature.pubKeyX <== issuerPubKeyX;
    issuerSignature.pubKeyY <== issuerPubKeyY;

    component binding = SwiyuNullifierPrepareBinding();
    binding.holderSecret <== holderSecret;
    binding.credentialUid <== credentialUid;
    binding.secretCommitment <== secretCommitment;
    binding.credentialBindingHashHi <== credentialBindingHashHi;
    binding.credentialBindingHashLo <== credentialBindingHashLo;
    splitShared[0] <== binding.credentialSeedHi;
    splitShared[1] <== binding.credentialSeedLo;
    expressionResult <== 1;
}

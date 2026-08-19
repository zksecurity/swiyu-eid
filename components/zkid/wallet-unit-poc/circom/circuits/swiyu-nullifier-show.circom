pragma circom 2.2.3;

include "swiyu-nullifier-primitives.circom";

/// Generic per-presentation nullifier decorator.
///
/// The native Spartan wrapper must classify `splitShared` as hidden shared
/// rows and compare its proof-embedded commitment with Prepare. An enclosing
/// profile additionally constrains its eligibility predicate, holder binding,
/// current status and verifier challenge in this same Show relation.
template SwiyuNullifierShow() {
    signal input credentialSeedHi;
    signal input credentialSeedLo;
    signal input scopeDigestHi;
    signal input scopeDigestLo;
    signal input expectedNullifierHi;
    signal input expectedNullifierLo;

    signal output splitShared[2];
    signal output expressionResult;
    splitShared[0] <== credentialSeedHi;
    splitShared[1] <== credentialSeedLo;

    component nullifier = SwiyuScopedNullifier();
    nullifier.credentialSeedHi <== credentialSeedHi;
    nullifier.credentialSeedLo <== credentialSeedLo;
    nullifier.scopeDigestHi <== scopeDigestHi;
    nullifier.scopeDigestLo <== scopeDigestLo;
    nullifier.hashHi === expectedNullifierHi;
    nullifier.hashLo === expectedNullifierLo;
    expressionResult <== 1;
}

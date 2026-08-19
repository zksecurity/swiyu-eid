pragma circom 2.2.3;

include "../swiyu-nullifier-age18-show.circom";

component main {public[
    challengeHash,
    cutoffDate,
    currentTime,
    expectedMetadataHashHi,
    expectedMetadataHashLo,
    expectedStatusSnapshotHashHi,
    expectedStatusSnapshotHashLo,
    scopeDigestHi,
    scopeDigestLo,
    expectedNullifierHi,
    expectedNullifierLo
]} = SwiyuNullifierAge18Show();

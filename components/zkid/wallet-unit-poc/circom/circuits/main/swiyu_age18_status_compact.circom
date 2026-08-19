// auto-generated-style entry point for the measured compact swiyu profile
pragma circom 2.2.3;

include "../swiyu-age18-status.circom";

// 256 header bytes + separator + 600 payload bytes fit in 857 signed bytes;
// SHA-256 padding therefore fits in 896 bytes (14 blocks).
// The 600-byte payload bound also leaves 450 decoded slots, enough for the
// full 160-byte URI selector in the checked issuer-shaped credential.
component main {public[issuerPubKeyX, issuerPubKeyY, challengeHash, cutoffDate, currentTime, expectedMetadataHashHi, expectedMetadataHashLo, expectedStatusSnapshotHashHi, expectedStatusSnapshotHashLo]} = SwiyuAge18Status(896, 256, 600, 17, 1, 1, 0);

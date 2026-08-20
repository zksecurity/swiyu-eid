pragma circom 2.2.3;

include "../swiyu-residence-show-packed-chunk.circom";

component main {public[challengeHash, allowedCount, allowedMunicipalityCodes, minimumResidenceDays, currentTime, expectedMetadataHashHi, expectedMetadataHashLo, expectedStatusSnapshotHashHi, expectedStatusSnapshotHashLo]} = SwiyuResidenceShowPackedChunkV2();

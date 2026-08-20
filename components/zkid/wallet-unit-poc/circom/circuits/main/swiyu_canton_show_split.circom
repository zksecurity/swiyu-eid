pragma circom 2.2.3;

include "../swiyu-canton-show-split.circom";

component main {public[challengeHash, allowedCount, allowedCantonCodes, currentTime, expectedMetadataHashHi, expectedMetadataHashLo, expectedStatusSnapshotHashHi, expectedStatusSnapshotHashLo]} = SwiyuCantonShowSplit(17);

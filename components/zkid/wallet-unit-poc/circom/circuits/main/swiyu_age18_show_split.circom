pragma circom 2.2.3;

include "../swiyu-age18-show-split.circom";

component main {public[challengeHash, cutoffDate, currentTime, expectedMetadataHashHi, expectedMetadataHashLo, expectedStatusSnapshotHashHi, expectedStatusSnapshotHashLo]} = SwiyuAge18ShowSplit(17);

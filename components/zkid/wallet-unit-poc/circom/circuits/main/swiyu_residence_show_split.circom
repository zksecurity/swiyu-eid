pragma circom 2.2.3;

include "../swiyu-residence-show-split.circom";

component main {public[challengeHash, allowedCount, allowedMunicipalityCodes, minimumResidenceDays, currentTime, expectedMetadataHashHi, expectedMetadataHashLo, expectedStatusSnapshotHashHi, expectedStatusSnapshotHashLo]} = SwiyuResidenceShowSplit(11);

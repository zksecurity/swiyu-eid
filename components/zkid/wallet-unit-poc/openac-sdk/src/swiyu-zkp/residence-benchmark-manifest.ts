/**
 * Frozen semantic inputs shared by the residence ZK fixture, SDK host adapter,
 * and ordinary SD-JWT control. This is benchmark provenance, not a production
 * municipality-directory configuration.
 */
import type { ResidenceEligibilityPolicy } from "./residence-eligibility.js";

export const SWIYU_BENCHMARK_RESIDENCE = Object.freeze({
  vct: "urn:ch:swiyu-lab:residence-eligibility:v1",
  policyId: "ch.residence-benefit.eligibility",
  policyVersion: "2025-01-01",
  selectedMunicipalityBfs: 261,
  residenceSince: "2023-01-01",
  disclosureSalt: "AQIDBAUGBwgJCgsMDQ4PEA",
  policy: Object.freeze({
    allowedMunicipalityBfs: Object.freeze([261, 351] as const),
    minimumResidenceDays: 365,
    municipalityDirectoryAsOf: "2025-01-01",
    municipalityDirectorySha256: "2a510d6f7de86e40a8d584daba5985422728317619f1e9225bf3c3e28c40905c",
  }) satisfies Readonly<ResidenceEligibilityPolicy>,
});

/**
 * Frozen authenticated status snapshot shared by the native witness and the
 * SDK-host residence benchmark. The epoch is the statuslist+jwt `iat`, thirty
 * seconds before the benchmark's frozen currentTime.
 */
export const SWIYU_BENCHMARK_RESIDENCE_STATUS = Object.freeze({
  listLength: 65_536,
  epoch: 1_749_999_970,
  statusValue: 0 as const,
  legacyTreeProfile: "fixed-index-status-ternary-merkle-v1" as const,
  snapshotRoot: "0c5ff2d21a2425ba5f5497b19a04feace17592249fdb1902805a4829f0ea1162",
  packedV2: Object.freeze({
    treeProfile: "packed-status-chunk-ternary-merkle-v2" as const,
    chunkBytes: 64,
    treeDepth: 6,
    snapshotRoot: "8c9b118e9feea73867dfe6bf8e28bb19acacfe5da1d45961b5691993019035c2",
  }),
});

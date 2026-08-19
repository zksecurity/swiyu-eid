import { describe, expect, it } from "vitest";

import {
  assertResidenceEligible,
  buildResidenceEligibilityPublicInputs,
  computeSwiyuResidencePolicyChallengeHash,
  packSwiyuResidence,
  residenceDateToDay1900,
  unpackSwiyuResidence,
  validateResidenceEligibilityPolicy,
} from "../../src/swiyu-zkp/residence-eligibility.js";
const policy = {
  challengeHash: 7n,
  currentTime: BigInt(Date.UTC(2026, 0, 1) / 1_000),
  allowedMunicipalityBfs: [261, 351, 6621] as const,
  minimumResidenceDays: 365,
  municipalityDirectoryAsOf: "2026-01-01",
  municipalityDirectorySha256: "11".repeat(32),
};

describe("residence eligibility host API", () => {
  it("matches Gregorian boundaries and the circuit epoch", () => {
    expect(residenceDateToDay1900("1900-01-01")).toBe(0);
    expect(residenceDateToDay1900("1900-03-01")).toBe(59);
    expect(residenceDateToDay1900("1970-01-01")).toBe(25_567);
    expect(residenceDateToDay1900("2000-02-29") + 1)
      .toBe(residenceDateToDay1900("2000-03-01"));
    expect(residenceDateToDay1900("2100-02-28") + 1)
      .toBe(residenceDateToDay1900("2100-03-01"));
    expect(residenceDateToDay1900("2199-12-31")).toBe(109_572);
  });

  it("rejects invalid or non-canonical dates", () => {
    for (const value of [
      "1899-12-31", "2200-01-01", "2001-02-29", "2100-02-29",
      "2026-04-31", "2026-1-01", "2026-01-1", "2026-01-01Z",
    ]) expect(() => residenceDateToDay1900(value)).toThrow();
  });

  it("round-trips the exact 13+17 bit shared-row packing", () => {
    const packed = packSwiyuResidence(261, "2021-06-15");
    expect(unpackSwiyuResidence(packed)).toEqual({
      municipalityBfs: 261,
      residenceSinceDay1900: residenceDateToDay1900("2021-06-15"),
    });
    expect(() => packSwiyuResidence(0, "2021-06-15")).toThrow("1..6999");
    expect(() => unpackSwiyuResidence(1n << 30n)).toThrow("30-bit");
  });

  it("encodes a canonical 16-slot public policy in circuit order", () => {
    const inputs = buildResidenceEligibilityPublicInputs({
      ...policy,
      preparedLookup: { hashHi: 1n, hashLo: 2n },
      preparedStatusCommitment: { hashHi: 3n, hashLo: 4n },
    });
    const values = [
      inputs.challengeHash,
      BigInt(inputs.allowedCount),
      ...inputs.allowedMunicipalityCodes,
      BigInt(inputs.minimumResidenceDays),
      inputs.currentTime,
      inputs.expectedMetadataHashHi,
      inputs.expectedMetadataHashLo,
      inputs.expectedStatusSnapshotHashHi,
      inputs.expectedStatusSnapshotHashLo,
    ];
    expect(values).toHaveLength(24);
    expect(values.slice(0, 6)).toEqual([7n, 3n, 261n, 351n, 6621n, 0n]);
    expect(values.slice(18, 20)).toEqual([365n, policy.currentTime]);

    expect(inputs.allowedMunicipalityCodes).toHaveLength(16);
    expect(inputs.allowedMunicipalityCodes.slice(0, 4)).toEqual([261n, 351n, 6621n, 0n]);
  });

  it("rejects ambiguous, oversized, and out-of-range verifier policies", () => {
    const invalid = [
      { allowedMunicipalityBfs: [], minimumResidenceDays: 365 },
      { allowedMunicipalityBfs: [351, 261], minimumResidenceDays: 365 },
      { allowedMunicipalityBfs: [261, 261], minimumResidenceDays: 365 },
      { allowedMunicipalityBfs: [0], minimumResidenceDays: 365 },
      { allowedMunicipalityBfs: [7000], minimumResidenceDays: 365 },
      { allowedMunicipalityBfs: [261], minimumResidenceDays: 0 },
      { allowedMunicipalityBfs: [261], minimumResidenceDays: 3651 },
      { allowedMunicipalityBfs: Array.from({ length: 17 }, (_, i) => i + 1), minimumResidenceDays: 365 },
    ];
    for (const candidate of invalid) {
      expect(() => validateResidenceEligibilityPolicy({
        municipalityDirectoryAsOf: "2026-01-01",
        municipalityDirectorySha256: "11".repeat(32),
        ...candidate,
      } as never)).toThrow();
    }
    expect(() => validateResidenceEligibilityPolicy({
      ...policy,
      municipalityDirectoryAsOf: "2026-1-1",
    })).toThrow("canonical");
    expect(() => validateResidenceEligibilityPolicy({
      ...policy,
      municipalityDirectorySha256: "not-a-hash",
    })).toThrow("SHA-256");
  });

  it("uses an inclusive whole-UTC-day duration boundary", () => {
    const boundaryPolicy = {
      allowedMunicipalityBfs: [261] as const,
      minimumResidenceDays: 365,
      municipalityDirectoryAsOf: "2026-01-01",
      municipalityDirectorySha256: "11".repeat(32),
    };
    const exactBoundary = BigInt(Date.UTC(2026, 0, 1, 0, 0, 0) / 1_000);
    expect(() => assertResidenceEligible(
      261,
      "2025-01-01",
      exactBoundary,
      boundaryPolicy,
    )).not.toThrow();
    expect(() => assertResidenceEligible(
      261,
      "2025-01-02",
      exactBoundary + 86_399n,
      boundaryPolicy,
    )).toThrow("duration");
    expect(() => assertResidenceEligible(
      351,
      "2020-01-01",
      exactBoundary,
      boundaryPolicy,
    )).toThrow("municipality");
  });

  it("rejects a municipality directory edition from after policy currentTime", () => {
    const earlierTime = BigInt(Date.UTC(2025, 11, 31) / 1_000);
    expect(() => buildResidenceEligibilityPublicInputs({
      ...policy,
      currentTime: earlierTime,
      preparedLookup: { hashHi: 1n, hashLo: 2n },
      preparedStatusCommitment: { hashHi: 3n, hashLo: 4n },
    })).toThrow("must not be later");
    expect(() => assertResidenceEligible(
      261,
      "2020-01-01",
      earlierTime,
      policy,
    )).toThrow("must not be later");
  });

  it("binds the pinned directory edition and artifact into the session", () => {
    const first = computeSwiyuResidencePolicyChallengeHash(7n, policy);
    expect(computeSwiyuResidencePolicyChallengeHash(7n, {
      ...policy,
      municipalityDirectoryAsOf: "2026-01-02",
    })).not.toBe(first);
    expect(computeSwiyuResidencePolicyChallengeHash(7n, {
      ...policy,
      municipalityDirectorySha256: "22".repeat(32),
    })).not.toBe(first);
    expect(computeSwiyuResidencePolicyChallengeHash(8n, policy)).not.toBe(first);
  });
});

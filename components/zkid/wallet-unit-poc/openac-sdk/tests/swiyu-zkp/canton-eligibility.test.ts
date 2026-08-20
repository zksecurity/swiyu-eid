import { describe, expect, it } from "vitest";
import {
  assertCantonEligible,
  buildCantonEligibilityPublicInputs,
  encodeSwissCanton,
} from "../../src/swiyu-zkp/canton-eligibility.js";

describe("canton eligibility host API", () => {
  const request = {
    challengeHash: 7n,
    currentTime: 1_750_000_000n,
    preparedLookup: { hashHi: 11n, hashLo: 12n },
    preparedStatusUri: { hashHi: 21n, hashLo: 22n },
    statusSnapshotRoot: "00".repeat(32),
    allowedCantons: ["ZH", "BE"] as const,
  };

  it("encodes a canonical fixed-width transparent allow-list", () => {
    const inputs = buildCantonEligibilityPublicInputs(request);
    expect(inputs.allowedCount).toBe(2);
    expect(inputs.allowedCantonCodes).toEqual([
      encodeSwissCanton("ZH"),
      encodeSwissCanton("BE"),
      0n,
      0n,
    ]);
  });

  it("rejects duplicate or oversized verifier policies", () => {
    expect(() => buildCantonEligibilityPublicInputs({
      ...request,
      allowedCantons: ["ZH", "ZH"],
    })).toThrow("unique");
    expect(() => buildCantonEligibilityPublicInputs({
      ...request,
      allowedCantons: ["ZH", "BE", "GE", "VD", "TI"],
    })).toThrow("one to four");
    expect(() => buildCantonEligibilityPublicInputs({
      ...request,
      allowedCantons: [] as never,
    })).toThrow("one to four");
    expect(() => buildCantonEligibilityPublicInputs({
      ...request,
      allowedCantons: ["ZZ"] as never,
    })).toThrow("canonical");
  });

  it("preflights the same membership policy proved in zero knowledge", () => {
    expect(() => assertCantonEligible("ZH", request)).not.toThrow();
    expect(() => assertCantonEligible("GE", request)).toThrow("not eligible");
  });
});

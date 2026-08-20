import {
  computeSwiyuPreparedSessionCommitment,
  computeSwiyuPreparedStatusCommitment,
  type SwiyuHashLimbs,
} from "./commitments.js";

export const SWISS_CANTONS = [
  "AG", "AI", "AR", "BE", "BL", "BS", "FR", "GE", "GL", "GR", "JU", "LU", "NE",
  "NW", "OW", "SG", "SH", "SO", "SZ", "TG", "TI", "UR", "VD", "VS", "ZG", "ZH",
] as const;

export type SwissCanton = typeof SWISS_CANTONS[number];

export interface CantonEligibilityPolicy {
  /** A transparent verifier policy. The circuit supports one to four cantons. */
  allowedCantons: readonly [SwissCanton, ...SwissCanton[]];
}

export interface CantonEligibilityPublicRequest extends CantonEligibilityPolicy {
  challengeHash: bigint;
  currentTime: bigint;
  preparedLookup: SwiyuHashLimbs;
  preparedStatusUri: SwiyuHashLimbs;
  statusSnapshotRoot: string;
}

export interface CantonEligibilityPublicInputs {
  challengeHash: bigint;
  allowedCount: number;
  allowedCantonCodes: readonly [bigint, bigint, bigint, bigint];
  currentTime: bigint;
  expectedMetadataHashHi: bigint;
  expectedMetadataHashLo: bigint;
  expectedStatusSnapshotHashHi: bigint;
  expectedStatusSnapshotHashLo: bigint;
}

export function encodeSwissCanton(canton: SwissCanton): bigint {
  return BigInt(canton.charCodeAt(0) * 256 + canton.charCodeAt(1));
}

/** Build the exact eleven public values consumed by the canton Show circuit. */
export function buildCantonEligibilityPublicInputs(
  request: CantonEligibilityPublicRequest,
): CantonEligibilityPublicInputs {
  if (request.allowedCantons.length < 1 || request.allowedCantons.length > 4) {
    throw new Error("canton eligibility requires one to four allowed cantons");
  }
  if (request.allowedCantons.some((canton) =>
    !(SWISS_CANTONS as readonly string[]).includes(canton))) {
    throw new Error("allowed cantons must use canonical Swiss canton codes");
  }
  if (new Set(request.allowedCantons).size !== request.allowedCantons.length) {
    throw new Error("allowed cantons must be unique");
  }
  if (request.currentTime < 0n || request.currentTime >= 1n << 64n) {
    throw new Error("current time must fit in an unsigned 64-bit integer");
  }
  const metadata = computeSwiyuPreparedSessionCommitment(
    request.challengeHash,
    request.preparedLookup,
  );
  const status = computeSwiyuPreparedStatusCommitment(
    request.preparedStatusUri,
    request.statusSnapshotRoot,
  );
  const codes = request.allowedCantons.map(encodeSwissCanton);
  while (codes.length < 4) codes.push(0n);
  const allowedCantonCodes: [bigint, bigint, bigint, bigint] = [
    codes[0]!, codes[1]!, codes[2]!, codes[3]!,
  ];
  return {
    challengeHash: request.challengeHash,
    allowedCount: request.allowedCantons.length,
    allowedCantonCodes,
    currentTime: request.currentTime,
    expectedMetadataHashHi: metadata.hashHi,
    expectedMetadataHashLo: metadata.hashLo,
    expectedStatusSnapshotHashHi: status.hashHi,
    expectedStatusSnapshotHashLo: status.hashLo,
  };
}

/** Host-side policy preflight; the circuit independently enforces the result. */
export function assertCantonEligible(
  residentCanton: SwissCanton,
  policy: CantonEligibilityPolicy,
): void {
  if (!policy.allowedCantons.includes(residentCanton)) {
    throw new Error("resident canton is not eligible under the verifier policy");
  }
}

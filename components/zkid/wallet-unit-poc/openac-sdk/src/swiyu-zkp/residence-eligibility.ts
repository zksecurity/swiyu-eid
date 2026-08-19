import { sha256 } from "@noble/hashes/sha2";
import {
  computeSwiyuPreparedSessionCommitment,
  type SwiyuHashLimbs,
} from "./commitments.js";
import { assertFieldElement, bigEndianBytesToBigInt } from "./encoding.js";
import { SWIYU_P256_SCALAR_ORDER } from "./constants.js";

const encoder = new TextEncoder();

export const SWIYU_RESIDENCE_MAX_MUNICIPALITIES = 16;
export const SWIYU_RESIDENCE_MAX_BFS_CODE = 6_999;
export const SWIYU_RESIDENCE_MAX_DURATION_DAYS = 3_650;
export const SWIYU_RESIDENCE_DAY_BITS = 17n;
export const SWIYU_RESIDENCE_MUNICIPALITY_BITS = 13n;
export const SWIYU_DAYS_1900_TO_UNIX_EPOCH = 25_567n;

export type ResidenceMunicipalityCodes = readonly [number, ...number[]];

export interface ResidenceEligibilityPolicy {
  /**
   * Official BFS municipality identifiers from a verifier-pinned edition of
   * the Swiss official municipality directory. They must be strictly sorted.
   */
  allowedMunicipalityBfs: ResidenceMunicipalityCodes;
  /** Whole UTC days of uninterrupted main residence required by the policy. */
  minimumResidenceDays: number;
  /** Effective date of the verifier-pinned official BFS municipality directory. */
  municipalityDirectoryAsOf: string;
  /** SHA-256 of the canonical pinned directory artifact, lowercase hexadecimal. */
  municipalityDirectorySha256: string;
}

export interface ResidenceEligibilityPublicRequest
  extends ResidenceEligibilityPolicy {
  challengeHash: bigint;
  currentTime: bigint;
  preparedLookup: SwiyuHashLimbs;
  /** Derived only after authenticating the statuslist+jwt in production. */
  preparedStatusCommitment: SwiyuHashLimbs;
}

export type ResidenceMunicipalityCodeSlots = readonly [
  bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint,
  bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint,
];

export interface ResidenceEligibilityPublicInputs {
  challengeHash: bigint;
  allowedCount: number;
  allowedMunicipalityCodes: ResidenceMunicipalityCodeSlots;
  minimumResidenceDays: number;
  currentTime: bigint;
  expectedMetadataHashHi: bigint;
  expectedMetadataHashLo: bigint;
  expectedStatusSnapshotHashHi: bigint;
  expectedStatusSnapshotHashLo: bigint;
}

/**
 * Domain-separated verifier challenge binding for directory provenance. The
 * allow-list and duration are already direct Show public inputs; this layer
 * prevents the off-circuit directory edition/hash from becoming commentary.
 */
export function computeSwiyuResidencePolicyChallengeHash(
  baseChallengeHash: bigint,
  policy: ResidenceEligibilityPolicy,
): bigint {
  validateResidenceEligibilityPolicy(policy);
  if (baseChallengeHash < 0n || baseChallengeHash >= SWIYU_P256_SCALAR_ORDER) {
    throw new Error("base challenge hash must be a canonical P-256 scalar");
  }
  const asOf = encoder.encode(policy.municipalityDirectoryAsOf);
  const artifact = hex32(policy.municipalityDirectorySha256);
  const digest = sha256(concat(
    domain("swiyu-residence-policy-v1"),
    bigEndian32(baseChallengeHash),
    Uint8Array.of(asOf.length),
    asOf,
    artifact,
  ));
  return bigEndianBytesToBigInt(digest) % SWIYU_P256_SCALAR_ORDER;
}

/** Exact YYYY-MM-DD -> elapsed days since 1900-01-01 conversion used in-circuit. */
export function residenceDateToDay1900(value: string): number {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!match) throw new Error("residence date must use canonical YYYY-MM-DD spelling");
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (year < 1900 || year > 2199) {
    throw new Error("residence date year must be in 1900..2199");
  }
  if (month < 1 || month > 12) throw new Error("residence date month is invalid");
  const monthLengths = [31, isLeapYear(year) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (day < 1 || day > monthLengths[month - 1]!) {
    throw new Error("residence date day is invalid");
  }
  const completedYear = year - 1;
  const leapDaysBeforeYear =
    Math.floor(completedYear / 4) - Math.floor(1899 / 4)
    - (Math.floor(completedYear / 100) - Math.floor(1899 / 100))
    + (Math.floor(completedYear / 400) - Math.floor(1899 / 400));
  const daysBeforeMonth = monthLengths
    .slice(0, month - 1)
    .reduce((sum, length) => sum + length, 0);
  return (year - 1900) * 365 + leapDaysBeforeYear + daysBeforeMonth + day - 1;
}

/** Pack the two authenticated claims into the relation's 30-bit shared row. */
export function packSwiyuResidence(
  municipalityBfs: number,
  residenceSince: string,
): bigint {
  assertBfsCode(municipalityBfs, "municipality BFS code");
  return BigInt(municipalityBfs)
    + (BigInt(residenceDateToDay1900(residenceSince)) << SWIYU_RESIDENCE_MUNICIPALITY_BITS);
}

export function unpackSwiyuResidence(packed: bigint): {
  municipalityBfs: number;
  residenceSinceDay1900: number;
} {
  if (packed < 0n || packed >= 1n << 30n) {
    throw new Error("packed residence must fit the circuit's 30-bit shared row");
  }
  const municipalityBfs = Number(packed & ((1n << SWIYU_RESIDENCE_MUNICIPALITY_BITS) - 1n));
  const residenceSinceDay1900 = Number(packed >> SWIYU_RESIDENCE_MUNICIPALITY_BITS);
  assertBfsCode(municipalityBfs, "packed municipality BFS code");
  if (residenceSinceDay1900 > residenceDateToDay1900("2199-12-31")) {
    throw new Error("packed residence date is outside 1900..2199");
  }
  return { municipalityBfs, residenceSinceDay1900 };
}

/** Build the exact 24 public values consumed by the residence Show circuit. */
export function buildResidenceEligibilityPublicInputs(
  request: ResidenceEligibilityPublicRequest,
): ResidenceEligibilityPublicInputs {
  validateResidenceEligibilityPolicy(request);
  if (request.currentTime < 0n || request.currentTime >= 1n << 64n) {
    throw new Error("current time must fit in an unsigned 64-bit integer");
  }
  const currentDay1900 = request.currentTime / 86_400n + SWIYU_DAYS_1900_TO_UNIX_EPOCH;
  if (currentDay1900 > BigInt(residenceDateToDay1900("2199-12-31"))) {
    throw new Error("current time is outside the circuit's supported date range");
  }
  assertDirectoryNotFuture(request.municipalityDirectoryAsOf, currentDay1900);
  const metadata = computeSwiyuPreparedSessionCommitment(
    request.challengeHash,
    request.preparedLookup,
  );
  assertFieldElement(
    request.preparedStatusCommitment.hashHi,
    "prepared status commitment high limb",
  );
  assertFieldElement(
    request.preparedStatusCommitment.hashLo,
    "prepared status commitment low limb",
  );
  const codes = request.allowedMunicipalityBfs.map(BigInt);
  while (codes.length < SWIYU_RESIDENCE_MAX_MUNICIPALITIES) codes.push(0n);
  return {
    challengeHash: request.challengeHash,
    allowedCount: request.allowedMunicipalityBfs.length,
    allowedMunicipalityCodes: codes as unknown as ResidenceMunicipalityCodeSlots,
    minimumResidenceDays: request.minimumResidenceDays,
    currentTime: request.currentTime,
    expectedMetadataHashHi: metadata.hashHi,
    expectedMetadataHashLo: metadata.hashLo,
    expectedStatusSnapshotHashHi: request.preparedStatusCommitment.hashHi,
    expectedStatusSnapshotHashLo: request.preparedStatusCommitment.hashLo,
  };
}

/** Host-side policy preflight; the circuit independently enforces the result. */
export function assertResidenceEligible(
  municipalityBfs: number,
  residenceSince: string,
  currentTime: bigint,
  policy: ResidenceEligibilityPolicy,
): void {
  validateResidenceEligibilityPolicy(policy);
  assertBfsCode(municipalityBfs, "municipality BFS code");
  if (!policy.allowedMunicipalityBfs.includes(municipalityBfs)) {
    throw new Error("municipality is not eligible under the residence policy");
  }
  if (currentTime < 0n) throw new Error("current time must be non-negative");
  const currentDay1900 = currentTime / 86_400n + SWIYU_DAYS_1900_TO_UNIX_EPOCH;
  assertDirectoryNotFuture(policy.municipalityDirectoryAsOf, currentDay1900);
  const eligibleDay = BigInt(residenceDateToDay1900(residenceSince) + policy.minimumResidenceDays);
  if (eligibleDay > currentDay1900) {
    throw new Error("minimum uninterrupted residence duration is not satisfied");
  }
}

export function validateResidenceEligibilityPolicy(
  policy: ResidenceEligibilityPolicy,
): void {
  const codes = policy.allowedMunicipalityBfs;
  if (codes.length < 1 || codes.length > SWIYU_RESIDENCE_MAX_MUNICIPALITIES) {
    throw new Error("residence eligibility requires one to sixteen municipalities");
  }
  codes.forEach((code) => assertBfsCode(code, "allowed municipality BFS code"));
  for (let index = 1; index < codes.length; index++) {
    if (codes[index - 1]! >= codes[index]!) {
      throw new Error("allowed municipality BFS codes must be unique and strictly increasing");
    }
  }
  if (
    !Number.isInteger(policy.minimumResidenceDays)
    || policy.minimumResidenceDays < 1
    || policy.minimumResidenceDays > SWIYU_RESIDENCE_MAX_DURATION_DAYS
  ) {
    throw new Error("minimum residence duration must be an integer in 1..3650 days");
  }
  residenceDateToDay1900(policy.municipalityDirectoryAsOf);
  if (!/^[0-9a-f]{64}$/.test(policy.municipalityDirectorySha256)) {
    throw new Error("municipality directory artifact hash must be a lowercase SHA-256 digest");
  }
}

function assertDirectoryNotFuture(asOf: string, currentDay1900: bigint): void {
  if (BigInt(residenceDateToDay1900(asOf)) > currentDay1900) {
    throw new Error("municipality directory edition must not be later than policy currentTime");
  }
}

function assertBfsCode(value: number, label: string): void {
  if (!Number.isInteger(value) || value < 1 || value > SWIYU_RESIDENCE_MAX_BFS_CODE) {
    throw new Error(`${label} must be an integer in 1..6999`);
  }
}

function isLeapYear(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function domain(value: string): Uint8Array {
  const bytes = encoder.encode(value);
  return concat(Uint8Array.of(bytes.length >>> 8, bytes.length & 0xff), bytes);
}

function bigEndian32(value: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let remaining = value;
  for (let index = 31; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function hex32(value: string): Uint8Array {
  const result = new Uint8Array(32);
  for (let index = 0; index < result.length; index += 1) {
    result[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return result;
}

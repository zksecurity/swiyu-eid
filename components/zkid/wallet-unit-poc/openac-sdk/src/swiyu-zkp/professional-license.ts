import {
  computeSwiyuPreparedLookupCommitment,
  computeSwiyuPreparedSessionCommitment,
  computeSwiyuPreparedStatusCommitment,
  computeSwiyuPreparedStatusUriCommitment,
  type SwiyuHashLimbs,
} from "./commitments.js";
import type { SwiyuLookupHints } from "./types.js";

export const SWIYU_PROFESSIONAL_LICENSE_VCT =
  "urn:ch:professional-license:v1";

export interface ProfessionalLicensePolicyRequest {
  lookup: Pick<SwiyuLookupHints, "issuer" | "kid" | "vct">;
  statusUri: string;
  statusRoot: string;
  challengeHash: bigint;
  currentTime: bigint;
  requiredValidUntil: bigint;
  acceptedVct?: string;
}

export interface ProfessionalLicensePublicContext {
  challengeHash: bigint;
  currentTime: bigint;
  requiredValidUntil: bigint;
  expectedMetadata: SwiyuHashLimbs;
  expectedStatusSnapshot: SwiyuHashLimbs;
}

export interface ProfessionalLicensePreparedValues {
  holderKeyX: bigint;
  holderKeyY: bigint;
  preparedPredicateValue: bigint;
  credentialNbf: bigint;
  credentialExp: bigint;
  statusIndex: bigint;
  lookupHashHi: bigint;
  lookupHashLo: bigint;
  statusUriHashHi: bigint;
  statusUriHashLo: bigint;
}

export interface ProfessionalLicenseOnlineWitness {
  holderSigR: bigint;
  holderSigSInverse: bigint;
  statusValue: bigint;
  statusSiblings: readonly (readonly bigint[])[];
  statusEpoch: bigint;
  statusListLength: bigint;
}

export type ProfessionalLicenseShowInputs = ProfessionalLicenseOnlineWitness & {
  holderKeyX: bigint;
  holderKeyY: bigint;
  unusedPreparedPredicateValue: bigint;
  credentialNbf: bigint;
  credentialExp: bigint;
  statusIndex: bigint;
  lookupHashHi: bigint;
  lookupHashLo: bigint;
  statusUriHashHi: bigint;
  statusUriHashLo: bigint;
  challengeHash: bigint;
  currentTime: bigint;
  requiredValidUntil: bigint;
  expectedMetadataHashHi: bigint;
  expectedMetadataHashLo: bigint;
  expectedStatusSnapshotHashHi: bigint;
  expectedStatusSnapshotHashLo: bigint;
};

/**
 * Construct the verifier-owned public statement for a professional licence.
 *
 * The VCT check happens before hashing, so the public session commitment can
 * only be satisfied by Prepare's issuer-authenticated lookup tuple for the
 * accepted professional-licence profile. The circuit separately proves that
 * issuer-signed `exp > requiredValidUntil` (JWT expiry is exclusive) and that
 * the hidden status entry is
 * exactly VALID in `statusRoot`.
 */
export function buildProfessionalLicensePublicContext(
  request: Readonly<ProfessionalLicensePolicyRequest>,
): ProfessionalLicensePublicContext {
  const acceptedVct = request.acceptedVct ?? SWIYU_PROFESSIONAL_LICENSE_VCT;
  if (request.lookup.vct !== acceptedVct) {
    throw new Error(`credential VCT is not accepted: expected ${acceptedVct}`);
  }
  assertUint64(request.currentTime, "currentTime");
  assertUint64(request.requiredValidUntil, "requiredValidUntil");
  if (request.requiredValidUntil <= request.currentTime) {
    throw new Error("requiredValidUntil must be strictly after currentTime");
  }
  const lookup = computeSwiyuPreparedLookupCommitment(request.lookup);
  const uri = computeSwiyuPreparedStatusUriCommitment(request.statusUri);
  return {
    challengeHash: request.challengeHash,
    currentTime: request.currentTime,
    requiredValidUntil: request.requiredValidUntil,
    expectedMetadata: computeSwiyuPreparedSessionCommitment(
      request.challengeHash,
      lookup,
    ),
    expectedStatusSnapshot: computeSwiyuPreparedStatusCommitment(
      uri,
      request.statusRoot,
    ),
  };
}

/** Exact typed input ABI for `SwiyuProfessionalLicenseShowSplit`. */
export function buildProfessionalLicenseShowInputs(
  prepared: Readonly<ProfessionalLicensePreparedValues>,
  online: Readonly<ProfessionalLicenseOnlineWitness>,
  context: Readonly<ProfessionalLicensePublicContext>,
): ProfessionalLicenseShowInputs {
  return {
    ...online,
    holderKeyX: prepared.holderKeyX,
    holderKeyY: prepared.holderKeyY,
    unusedPreparedPredicateValue: prepared.preparedPredicateValue,
    credentialNbf: prepared.credentialNbf,
    credentialExp: prepared.credentialExp,
    statusIndex: prepared.statusIndex,
    lookupHashHi: prepared.lookupHashHi,
    lookupHashLo: prepared.lookupHashLo,
    statusUriHashHi: prepared.statusUriHashHi,
    statusUriHashLo: prepared.statusUriHashLo,
    challengeHash: context.challengeHash,
    currentTime: context.currentTime,
    requiredValidUntil: context.requiredValidUntil,
    expectedMetadataHashHi: context.expectedMetadata.hashHi,
    expectedMetadataHashLo: context.expectedMetadata.hashLo,
    expectedStatusSnapshotHashHi: context.expectedStatusSnapshot.hashHi,
    expectedStatusSnapshotHashLo: context.expectedStatusSnapshot.hashLo,
  };
}

function assertUint64(value: bigint, label: string): void {
  if (typeof value !== "bigint" || value < 0n || value >= 1n << 64n) {
    throw new Error(`${label} must be an unsigned 64-bit integer`);
  }
}

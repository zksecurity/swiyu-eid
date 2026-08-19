import { p256 } from "@noble/curves/nist.js";
import type { EcdsaPublicKey } from "../types.js";
import { SWIYU_AGE18_STATUS_PROFILE } from "./constants.js";
import { hashSwiyuChallenge } from "./challenge.js";
import {
  computeSwiyuMetadataCommitment,
} from "./commitments.js";
import { parseSwiyuIsoDate } from "./date.js";
import {
  bigEndianBytesToBigInt,
  bigintToLittleEndian32,
  concatBytes,
  decodeBase64urlStrict,
  assertFieldElement,
} from "./encoding.js";
import type {
  SwiyuChallenge,
  SwiyuLookupHints,
  SwiyuPublicContext,
  SwiyuStatusCommitment,
} from "./types.js";

export const SWIYU_PUBLIC_VALUE_NAMES = [
  "expressionResult",
  "issuerPubKeyX",
  "issuerPubKeyY",
  "challengeHash",
  "cutoffDate",
  "currentTime",
  "expectedMetadataHashHi",
  "expectedMetadataHashLo",
  "expectedStatusSnapshotHashHi",
  "expectedStatusSnapshotHashLo",
] as const;

export function buildSwiyuPublicContext(
  issuerPublicKey: EcdsaPublicKey,
  lookup: SwiyuLookupHints,
  challenge: SwiyuChallenge,
  statusCommitment: SwiyuStatusCommitment,
): SwiyuPublicContext {
  if (challenge.profile !== SWIYU_AGE18_STATUS_PROFILE) {
    throw new Error("challenge profile does not select the swiyu age/status relation");
  }
  if (issuerPublicKey.kty !== "EC" || issuerPublicKey.crv !== "P-256") {
    throw new Error("issuer public key must be a P-256 JWK");
  }
  if (issuerPublicKey.kid !== lookup.kid) {
    throw new Error("resolved issuer key must carry the exact proof lookup kid");
  }
  const x = bigEndianBytesToBigInt(
    decodeBase64urlStrict(issuerPublicKey.x, "issuer public key x", 32),
  );
  const y = bigEndianBytesToBigInt(
    decodeBase64urlStrict(issuerPublicKey.y, "issuer public key y", 32),
  );
  try {
    p256.ProjectivePoint.fromAffine({ x, y }).assertValidity();
  } catch (error) {
    throw new Error("resolved issuer key is not a valid P-256 point", {
      cause: error,
    });
  }
  const challengeHash = hashSwiyuChallenge(challenge).scalar;
  const cutoffDate = parseSwiyuIsoDate(challenge.cutoffDate, "cutoff_date");
  const metadata = computeSwiyuMetadataCommitment(lookup, challengeHash);
  assertFieldElement(statusCommitment.hashHi, "status snapshot commitment high limb");
  assertFieldElement(statusCommitment.hashLo, "status snapshot commitment low limb");
  return {
    expressionResult: 1n,
    issuerPubKeyX: x,
    issuerPubKeyY: y,
    challengeHash,
    cutoffDate,
    currentTime: challenge.currentTime,
    expectedMetadataHashHi: metadata.hashHi,
    expectedMetadataHashLo: metadata.hashLo,
    expectedStatusSnapshotHashHi: statusCommitment.hashHi,
    expectedStatusSnapshotHashLo: statusCommitment.hashLo,
  };
}

export function swiyuPublicContextScalars(context: SwiyuPublicContext): bigint[] {
  return [
    context.expressionResult,
    context.issuerPubKeyX,
    context.issuerPubKeyY,
    context.challengeHash,
    context.cutoffDate,
    context.currentTime,
    context.expectedMetadataHashHi,
    context.expectedMetadataHashLo,
    context.expectedStatusSnapshotHashHi,
    context.expectedStatusSnapshotHashLo,
  ];
}

/** 10 × canonical little-endian 32-byte Spartan public values. */
export function encodeSwiyuExpectedPublicContext(
  context: SwiyuPublicContext,
): Uint8Array {
  return concatBytes(
    swiyuPublicContextScalars(context).map(bigintToLittleEndian32),
  );
}

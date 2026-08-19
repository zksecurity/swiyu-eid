import { sha256 } from "@noble/hashes/sha2";
import {
  bigEndianBytesToBigInt,
  bytesAsBigints,
} from "./encoding.js";
import type { SwiyuHashLimbs } from "./commitments.js";
import {
  SWIYU_P256_SCALAR_ORDER,
} from "./constants.js";

const encoder = new TextEncoder();
const UINT128_LIMIT = 1n << 128n;
const UINT64_LIMIT = 1n << 64n;

export const SWIYU_NULLIFIER_VERSION = 1 as const;
export const SWIYU_NULLIFIER_SECRET_BYTES = 32 as const;
export const SWIYU_NULLIFIER_CREDENTIAL_UID_BYTES = 32 as const;
export const SWIYU_NULLIFIER_AGE18_PROFILE =
  "swiyu.age-over-18.scoped-nullifier.v1" as const;

export interface SwiyuNullifierCredentialMaterial {
  /** Wallet-generated secret which never leaves the proving device. */
  holderSecret: Uint8Array;
  /** Issuer-assigned random credential identifier. This is not a person ID. */
  credentialUid: Uint8Array;
  /** SHA-256 digest of the exact issuer-authenticated compact-JWS signing input. */
  credentialBindingHash: Readonly<SwiyuHashLimbs>;
}

export interface SwiyuNullifierScope {
  registryNamespaceId: Uint8Array;
  verifierOriginHash: Uint8Array;
  programId: Uint8Array;
  claimTypeId: Uint8Array;
  epoch: bigint;
  eligibilityPolicyDigest: Uint8Array;
}

export interface SwiyuNullifierScopeIdentifiers {
  registryNamespace: string;
  verifierOrigin: string;
  program: string;
  claimType: string;
  epoch: bigint;
  eligibilityPolicy: string;
}

export interface SwiyuRandomValuesSource {
  getRandomValues<T extends Uint8Array>(array: T): T;
}

export interface SwiyuNullifierPrepareWitness {
  holderSecret: bigint[];
  credentialUid: bigint[];
  secretCommitment: bigint[];
  credentialBindingHashHi: bigint;
  credentialBindingHashLo: bigint;
  issuerSigR: bigint;
  issuerSigSInverse: bigint;
}

export interface SwiyuNullifierShowWitness {
  credentialSeedHi: bigint;
  credentialSeedLo: bigint;
  scopeDigestHi: bigint;
  scopeDigestLo: bigint;
  expectedNullifierHi: bigint;
  expectedNullifierLo: bigint;
}

/** The issuer signs this commitment inside the credential nullifier profile. */
export function computeSwiyuNullifierSecretCommitment(
  holderSecret: Uint8Array,
): Uint8Array {
  return sha256(concat(
    domain("swy-nf-sec-v1"),
    assertSwiyuNullifierHolderSecret(holderSecret),
  ));
}

/** Generate a non-zero 256-bit wallet secret from the platform CSPRNG. */
export function generateSwiyuNullifierHolderSecret(
  source: SwiyuRandomValuesSource = globalThis.crypto,
): Uint8Array {
  if (!source || typeof source.getRandomValues !== "function") {
    throw new Error("a cryptographically secure getRandomValues source is required");
  }
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const secret = source.getRandomValues(new Uint8Array(32));
    if (secret.some((byte) => byte !== 0)) return secret;
  }
  throw new Error("CSPRNG repeatedly returned the forbidden all-zero holder secret");
}

export function assertSwiyuNullifierHolderSecret(holderSecret: Uint8Array): Uint8Array {
  const secret = exact32(holderSecret, "holder secret");
  if (!secret.some((byte) => byte !== 0)) {
    throw new Error("holder secret must not be all zero");
  }
  return secret;
}

/**
 * Hidden stable seed carried from Prepare to Show through Spartan's shared
 * witness commitment. A credential UID change intentionally creates a new
 * seed: the construction guarantees one claim per credential, not per person.
 */
export function computeSwiyuNullifierCredentialSeed(
  material: Readonly<SwiyuNullifierCredentialMaterial>,
): Uint8Array {
  return sha256(
    concat(
      domain("swy-nf-cred-v1"),
      assertSwiyuNullifierHolderSecret(material.holderSecret),
      exact32(material.credentialUid, "credential UID"),
      limbsToBytes(material.credentialBindingHash, "credential binding hash"),
    ),
  );
}

/**
 * Fixed issuer record used by the current standalone and integrated research
 * profiles. The integrated age experiment uses this auxiliary issuer
 * signature until a production VCT authenticates the UID and commitment in
 * the original compact JWS.
 */
export function buildSwiyuNullifierIssuerRecord(request: Readonly<{
  credentialUid: Uint8Array;
  secretCommitment: Uint8Array;
  credentialBindingHash: Readonly<SwiyuHashLimbs>;
}>): Uint8Array {
  const record = concat(
    domain("swy-nf-attr-v1"),
    exact32(request.credentialUid, "credential UID"),
    exact32(request.secretCommitment, "secret commitment"),
    limbsToBytes(request.credentialBindingHash, "credential binding hash"),
  );
  if (record.length !== 112) throw new Error("internal nullifier issuer-record length mismatch");
  return record;
}

/**
 * Canonical verifier-controlled scope. No session nonce or claim payload is
 * included: those must be challenge-bound separately or each retry would
 * receive a fresh nullifier.
 */
export function computeSwiyuNullifierScopeDigest(
  scope: Readonly<SwiyuNullifierScope>,
): Uint8Array {
  if (scope.epoch < 0n || scope.epoch >= UINT64_LIMIT) {
    throw new Error("nullifier epoch must fit an unsigned 64-bit integer");
  }
  return sha256(
    concat(
      domain("swy-nf-scope-v1"),
      exact32(scope.registryNamespaceId, "registry namespace ID"),
      exact32(scope.verifierOriginHash, "verifier origin hash"),
      exact32(scope.programId, "program ID"),
      exact32(scope.claimTypeId, "claim type ID"),
      u64be(scope.epoch),
      exact32(scope.eligibilityPolicyDigest, "eligibility policy digest"),
    ),
  );
}

/** Hash every human-readable verifier scope identifier into its fixed slot. */
export function buildSwiyuNullifierScope(
  identifiers: Readonly<SwiyuNullifierScopeIdentifiers>,
): SwiyuNullifierScope {
  return Object.freeze({
    registryNamespaceId: hashSwiyuNullifierIdentifier(
      identifiers.registryNamespace,
      "registry namespace",
    ),
    verifierOriginHash: hashSwiyuNullifierIdentifier(
      identifiers.verifierOrigin,
      "verifier origin",
    ),
    programId: hashSwiyuNullifierIdentifier(identifiers.program, "program"),
    claimTypeId: hashSwiyuNullifierIdentifier(identifiers.claimType, "claim type"),
    epoch: identifiers.epoch,
    eligibilityPolicyDigest: hashSwiyuNullifierIdentifier(
      identifiers.eligibilityPolicy,
      "eligibility policy",
    ),
  });
}

export function computeSwiyuScopedNullifier(
  credentialSeed: Uint8Array,
  scopeDigest: Uint8Array,
): Uint8Array {
  return sha256(
    concat(
      domain("swy-nf-val-v1"),
      exact32(credentialSeed, "credential seed"),
      exact32(scopeDigest, "scope digest"),
    ),
  );
}

/**
 * Holder-authorized challenge for the integrated age/nullifier profile.
 * The base challenge already binds nonce, audience, callback, state, age
 * policy, time, and status snapshot; this domain-separated layer additionally
 * binds the canonical nullifier scope and profile version.
 */
export function computeSwiyuNullifierChallengeHash(
  baseChallengeHash: bigint,
  scopeDigest: Uint8Array,
): { digest: Uint8Array; scalar: bigint } {
  if (baseChallengeHash < 0n || baseChallengeHash >= SWIYU_P256_SCALAR_ORDER) {
    throw new Error("base challenge hash must be a canonical P-256 scalar");
  }
  const digest = sha256(concat(
    domain("swy-nf-chal-v1"),
    bigEndian32(baseChallengeHash),
    exact32(scopeDigest, "scope digest"),
  ));
  return {
    digest,
    scalar: bigEndianBytesToBigInt(digest) % SWIYU_P256_SCALAR_ORDER,
  };
}

export function swiyuNullifierDigestLimbs(digest: Uint8Array): SwiyuHashLimbs {
  const bytes = exact32(digest, "SHA-256 digest");
  return Object.freeze({
    hashHi: bigEndianBytesToBigInt(bytes.slice(0, 16)),
    hashLo: bigEndianBytesToBigInt(bytes.slice(16, 32)),
  });
}

export function buildSwiyuNullifierPrepareWitness(request: Readonly<{
  material: Readonly<SwiyuNullifierCredentialMaterial>;
  issuerSigR: bigint;
  issuerSigSInverse: bigint;
}>): SwiyuNullifierPrepareWitness {
  assertPositiveScalar(request.issuerSigR, "issuer signature r");
  assertPositiveScalar(request.issuerSigSInverse, "issuer signature s inverse");
  return {
    holderSecret: bytesAsBigints(exact32(request.material.holderSecret, "holder secret")),
    credentialUid: bytesAsBigints(exact32(request.material.credentialUid, "credential UID")),
    secretCommitment: bytesAsBigints(
      computeSwiyuNullifierSecretCommitment(request.material.holderSecret),
    ),
    credentialBindingHashHi: assertLimb(
      request.material.credentialBindingHash.hashHi,
      "credential binding hash high limb",
    ),
    credentialBindingHashLo: assertLimb(
      request.material.credentialBindingHash.hashLo,
      "credential binding hash low limb",
    ),
    issuerSigR: request.issuerSigR,
    issuerSigSInverse: request.issuerSigSInverse,
  };
}

export function buildSwiyuNullifierShowWitness(request: Readonly<{
  credentialSeed: Uint8Array;
  scopeDigest: Uint8Array;
}>): SwiyuNullifierShowWitness {
  const seed = swiyuNullifierDigestLimbs(request.credentialSeed);
  const scope = swiyuNullifierDigestLimbs(request.scopeDigest);
  const nullifier = swiyuNullifierDigestLimbs(
    computeSwiyuScopedNullifier(request.credentialSeed, request.scopeDigest),
  );
  return {
    credentialSeedHi: seed.hashHi,
    credentialSeedLo: seed.hashLo,
    scopeDigestHi: scope.hashHi,
    scopeDigestLo: scope.hashLo,
    expectedNullifierHi: nullifier.hashHi,
    expectedNullifierLo: nullifier.hashLo,
  };
}

/** Hash a configured textual identifier before placing it in the fixed scope. */
export function hashSwiyuNullifierIdentifier(value: string, label: string): Uint8Array {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
  const bytes = encoder.encode(value);
  if (bytes.length > 1_024) throw new Error(`${label} must not exceed 1024 UTF-8 bytes`);
  return sha256(concat(domain("swy-nf-id-v1"), u16be(bytes.length), bytes));
}

function domain(value: string): Uint8Array {
  const bytes = encoder.encode(value);
  return concat(u16be(bytes.length), bytes);
}

function limbsToBytes(value: Readonly<SwiyuHashLimbs>, label: string): Uint8Array {
  return concat(
    bigEndian16(assertLimb(value.hashHi, `${label} high limb`)),
    bigEndian16(assertLimb(value.hashLo, `${label} low limb`)),
  );
}

function assertLimb(value: bigint, label: string): bigint {
  if (typeof value !== "bigint" || value < 0n || value >= UINT128_LIMIT) {
    throw new Error(`${label} must fit an unsigned 128-bit integer`);
  }
  return value;
}

function assertPositiveScalar(value: bigint, label: string): void {
  if (typeof value !== "bigint" || value <= 0n) throw new Error(`${label} must be positive`);
}

function exact32(value: Uint8Array, label: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new Error(`${label} must contain exactly 32 bytes`);
  }
  return value;
}

function u16be(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new Error("length must fit an unsigned 16-bit integer");
  }
  return Uint8Array.of(value >>> 8, value & 0xff);
}

function u64be(value: bigint): Uint8Array {
  const output = new Uint8Array(8);
  let remaining = value;
  for (let index = 7; index >= 0; index -= 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

function bigEndian16(value: bigint): Uint8Array {
  const output = new Uint8Array(16);
  let remaining = value;
  for (let index = 15; index >= 0; index -= 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

function bigEndian32(value: bigint): Uint8Array {
  const output = new Uint8Array(32);
  let remaining = value;
  for (let index = 31; index >= 0; index -= 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

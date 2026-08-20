import { p256 } from "@noble/curves/nist.js";
import { InputError, ProofError } from "../errors.js";
import type { EcdsaPublicKey } from "../types.js";
import { hexToBytes } from "../status-designs/hashing.js";
import { base64urlEncode, modInverse, P256_SCALAR_ORDER } from "../utils.js";
import {
  SWIYU_AGE18_STATUS_CIRCUIT,
  SWIYU_AGE18_STATUS_PROFILE,
  SWIYU_PROOF_ENVELOPE_VERSION,
} from "./constants.js";
import { hashSwiyuChallenge } from "./challenge.js";
import {
  computeSwiyuStatusProfileCommitment,
  validateAuthoritativeStatusSnapshot,
  validatePrivateStatusSnapshot,
} from "./commitments.js";
import { parseSwiyuIsoDate } from "./date.js";
import {
  bigEndianBytesToBigInt,
  bigintToLittleEndian32,
  bytesAsBigints,
  decodeBase64urlStrict,
  equalBytes,
} from "./encoding.js";
import { parseSwiyuCompactSdJwt, type ParsedSwiyuCredential } from "./parser.js";
import {
  buildSwiyuPublicContext,
  encodeSwiyuExpectedPublicContext as encodeContext,
  swiyuPublicContextScalars,
} from "./public-context.js";
import { verifySwiyuDenseStatusWitness } from "./status.js";
import {
  resolveSwiyuStatusListJwt,
  type SwiyuBoundedZlibInflater,
} from "./status-list-resolver.js";
import type {
  SwiyuCircuitInputs,
  SwiyuLookupHints,
  SwiyuPrepareRequest,
  SwiyuPreparedCredential,
  SwiyuProofBackend,
  SwiyuProofEnvelope,
  SwiyuShowRequest,
  SwiyuVerificationResult,
  SwiyuVerifyRequest,
  SwiyuWitnessGenerator,
  SwiyuPrivateStatusSnapshot,
  SwiyuDenseStatusWitness,
} from "./types.js";

interface WalletDependencies {
  witnessGenerator: SwiyuWitnessGenerator;
  proofBackend: SwiyuProofBackend;
}

const preparedStates = new WeakMap<SwiyuPreparedCredential, ParsedSwiyuCredential>();

class PreparedCredential implements SwiyuPreparedCredential {
  readonly profile = SWIYU_AGE18_STATUS_PROFILE;
  readonly circuitId = SWIYU_AGE18_STATUS_CIRCUIT;
  readonly lookup: ParsedSwiyuCredential["lookup"];

  constructor(parsed: ParsedSwiyuCredential) {
    this.lookup = Object.freeze({ ...parsed.lookup });
    preparedStates.set(this, parsed);
    Object.freeze(this);
  }
}

/** Verify and cache the immutable credential portion; no proof is emitted yet. */
export function prepareSwiyuCredential(
  request: SwiyuPrepareRequest,
): SwiyuPreparedCredential {
  return new PreparedCredential(
    parseSwiyuCompactSdJwt(request.compactSdJwt, request.issuerPublicKey),
  );
}

export interface SwiyuCredentialStatusProvisioningRequest {
  /** Credential previously authenticated by `prepareSwiyuCredential`. */
  prepared: SwiyuPreparedCredential;
  /** Locally fetched issuer-signed Swiss `statuslist+jwt`. */
  compactStatusListJwt: string;
  /** Trust-checked key for the status-list JWT signer. */
  statusListIssuerPublicKey: EcdsaPublicKey;
  /** Unix seconds at which the cached list is checked for freshness. */
  currentTime: bigint;
  /** Platform-specific bounded zlib adapter. */
  inflateZlib: SwiyuBoundedZlibInflater;
}

export interface SwiyuProvisionedCredentialStatus {
  /** Wallet-only URI/root material consumed by `show`. */
  statusSnapshot: Readonly<SwiyuPrivateStatusSnapshot>;
  /** Exact fixed-depth witness for the status index signed into the credential. */
  statusWitness: Readonly<SwiyuDenseStatusWitness>;
}

/**
 * Verify and cache the status material needed by `show`.
 *
 * The expected issuer, private status-list URI, and index come only from the
 * already-authenticated credential. No caller-supplied index can select a
 * different list entry, and `show` performs no status-list lookup.
 */
export function provisionSwiyuCredentialStatus(
  request: SwiyuCredentialStatusProvisioningRequest,
): SwiyuProvisionedCredentialStatus {
  const parsed = preparedStates.get(request.prepared);
  if (!parsed) {
    throw new InputError(
      "INVALID_JWT",
      "prepared credential was not created by this swiyu profile implementation",
    );
  }
  const resolved = resolveSwiyuStatusListJwt({
    compactJwt: request.compactStatusListJwt,
    issuerPublicKey: request.statusListIssuerPublicKey,
    expectedIssuer: parsed.lookup.issuer,
    expectedSubject: parsed.statusUri,
    currentTime: request.currentTime,
    inflateZlib: request.inflateZlib,
  });
  const witness = resolved.tree.witness(parsed.statusIndex);
  return Object.freeze({
    statusSnapshot: resolved.privateSnapshot,
    statusWitness: Object.freeze({
      ...witness,
      siblings: Object.freeze([...witness.siblings]),
    }),
  });
}

/** Two-stage wallet API backed by one fresh, session-bound proof relation. */
export class SwiyuZkpWallet {
  constructor(private readonly dependencies: WalletDependencies) {}

  prepare(request: SwiyuPrepareRequest): SwiyuPreparedCredential {
    return prepareSwiyuCredential(request);
  }

  async show(request: SwiyuShowRequest): Promise<SwiyuProofEnvelope> {
    const parsed = preparedStates.get(request.prepared);
    if (!parsed) {
      throw new InputError(
        "INVALID_JWT",
        "prepared credential was not created by this swiyu profile implementation",
      );
    }
    if (
      request.prepared.profile !== SWIYU_AGE18_STATUS_PROFILE ||
      request.prepared.circuitId !== SWIYU_AGE18_STATUS_CIRCUIT
    ) {
      throw new Error("prepared credential profile or circuit id is not supported");
    }
    if (request.challenge.statusListSnapshot !== request.statusSnapshot.id) {
      throw new Error("show challenge is bound to a different status snapshot");
    }
    validatePrivateStatusSnapshot(request.statusSnapshot);
    if (request.statusSnapshot.uri !== parsed.statusUri) {
      throw new Error("credential status URI does not match the resolved policy snapshot");
    }
    if (request.statusWitness.index !== parsed.statusIndex) {
      throw new Error("status witness index does not match the signed credential index");
    }
    if (
      request.challenge.currentTime < parsed.nbf ||
      request.challenge.currentTime >= parsed.exp
    ) {
      throw new Error("credential is not valid at the challenge current_time");
    }
    const cutoffDate = parseSwiyuIsoDate(request.challenge.cutoffDate, "cutoff_date");
    if (parsed.birthdateNumeric > cutoffDate) {
      throw new Error("birthdate does not satisfy the age cutoff");
    }
    verifySwiyuDenseStatusWitness(
      request.statusWitness,
      request.statusSnapshot,
    );

    const lookup: SwiyuLookupHints = Object.freeze({ ...parsed.lookup });
    const statusCommitment = computeSwiyuStatusProfileCommitment(
      request.statusSnapshot,
    );
    const publicContext = buildSwiyuPublicContext(
      parsed.issuerPublicKey,
      lookup,
      request.challenge,
      statusCommitment,
    );
    const challenge = hashSwiyuChallenge(request.challenge);
    const holderSignatureBytes = await request.holderSigner.signChallengeDigest(
      new Uint8Array(challenge.digest),
      Object.freeze({ ...request.challenge }),
    );
    const holderSignature = parseHolderSignature(holderSignatureBytes);
    verifyHolderSignature(
      holderSignature,
      challenge.digest,
      parsed.holderPublicKey,
    );

    const inputs: SwiyuCircuitInputs = {
      ...parsed.baseInputs,
      challengeHash: publicContext.challengeHash,
      cutoffDate: publicContext.cutoffDate,
      currentTime: publicContext.currentTime,
      expectedMetadataHashHi: publicContext.expectedMetadataHashHi,
      expectedMetadataHashLo: publicContext.expectedMetadataHashLo,
      expectedStatusSnapshotHashHi:
        publicContext.expectedStatusSnapshotHashHi,
      expectedStatusSnapshotHashLo:
        publicContext.expectedStatusSnapshotHashLo,
      holderSigR: holderSignature.r,
      holderSigSInverse: modInverse(holderSignature.s, P256_SCALAR_ORDER),
      // `verifySwiyuDenseStatusWitness` has already required the selected
      // 2-bit swiyu status to be VALID (0).
      statusValue: 0,
      statusSiblings: request.statusWitness.siblings.map((sibling) =>
        bytesAsBigints(hexToBytes(sibling)),
      ),
      statusEpoch: request.statusSnapshot.epoch,
      statusListLength: request.statusSnapshot.listLength,
    };

    let witness: Uint8Array;
    try {
      witness = await this.dependencies.witnessGenerator.calculateSwiyuWitnessWtns(
        inputs,
      );
    } catch (error) {
      throw new ProofError(
        "WITNESS_GENERATION_FAILED",
        `swiyu witness generation failed: ${error instanceof Error ? error.message : String(error)}`,
        error,
      );
    }
    if (!(witness instanceof Uint8Array) || witness.length === 0) {
      throw new ProofError(
        "WITNESS_GENERATION_FAILED",
        "swiyu witness generator returned an empty or invalid witness",
      );
    }

    let proofResult;
    try {
      proofResult = await this.dependencies.proofBackend.proveFromWitness(
        request.provingKey,
        witness,
      );
    } catch (error) {
      throw new ProofError(
        "PROOF_GENERATION_FAILED",
        `swiyu proof generation failed: ${error instanceof Error ? error.message : String(error)}`,
        error,
      );
    }
    if (!(proofResult.proof instanceof Uint8Array) || proofResult.proof.length === 0) {
      throw new ProofError(
        "PROOF_GENERATION_FAILED",
        "swiyu proof backend returned an empty proof",
      );
    }
    assertPublicValues(
      proofResult.publicValues,
      swiyuPublicContextScalars(publicContext),
    );

    // Deliberately exclude birthdate, holder key, disclosure, status URI,
    // status index/path/root and the raw session tuple from the envelope.
    return Object.freeze({
      version: SWIYU_PROOF_ENVELOPE_VERSION,
      profile: SWIYU_AGE18_STATUS_PROFILE,
      circuitId: SWIYU_AGE18_STATUS_CIRCUIT,
      proof: base64urlEncode(proofResult.proof),
      lookup,
    });
  }
}

export class SwiyuZkpVerifier {
  constructor(private readonly proofBackend: SwiyuProofBackend) {}

  async verify(request: SwiyuVerifyRequest): Promise<SwiyuVerificationResult> {
    try {
      const { envelope } = request;
      if (
        envelope.version !== SWIYU_PROOF_ENVELOPE_VERSION ||
        envelope.profile !== SWIYU_AGE18_STATUS_PROFILE ||
        envelope.circuitId !== SWIYU_AGE18_STATUS_CIRCUIT
      ) {
        throw new Error("proof envelope profile, circuit, or version is unsupported");
      }
      if (
        request.statusSnapshot.id !== request.challenge.statusListSnapshot
      ) {
        throw new Error("proof envelope is bound to a different status snapshot");
      }
      validateAuthoritativeStatusSnapshot(request.statusSnapshot);
      if (request.challenge.currentTime >= request.statusSnapshot.validBefore) {
        throw new Error("authoritative status snapshot is stale at current_time");
      }
      const context = buildSwiyuPublicContext(
        request.issuerPublicKey,
        envelope.lookup,
        request.challenge,
        request.statusSnapshot.commitment,
      );
      const expectedBytes = encodeContext(context);
      const proof = decodeBase64urlStrict(envelope.proof, "swiyu proof");
      const result = await this.proofBackend.verify(
        proof,
        request.verifyingKey,
        expectedBytes,
      );
      if (!result.valid) {
        return { valid: false, error: result.error ?? "proof verification failed" };
      }
      assertPublicValues(result.publicValues, swiyuPublicContextScalars(context));
      return { valid: true };
    } catch (error) {
      return {
        valid: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }
}

function parseHolderSignature(bytes: Uint8Array) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 64) {
    throw new InputError(
      "INVALID_SIGNATURE",
      "holder signer must return a 64-byte compact P-256 signature",
    );
  }
  try {
    return p256.Signature.fromCompact(
      Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(""),
    );
  } catch (error) {
    throw new InputError(
      "INVALID_SIGNATURE",
      "holder signer returned an invalid compact P-256 signature",
      error,
    );
  }
}

function verifyHolderSignature(
  signature: ReturnType<typeof parseHolderSignature>,
  digest: Uint8Array,
  publicKey: EcdsaPublicKey,
): void {
  const x = bigEndianBytesToBigInt(
    decodeBase64urlStrict(publicKey.x, "holder public key x", 32),
  );
  const y = bigEndianBytesToBigInt(
    decodeBase64urlStrict(publicKey.y, "holder public key y", 32),
  );
  const point = p256.ProjectivePoint.fromAffine({ x, y });
  if (!p256.verify(signature.toDERRawBytes(), digest, point.toRawBytes())) {
    throw new InputError(
      "INVALID_SIGNATURE",
      "holder signature does not match the signed cnf key and fresh challenge",
    );
  }
}

function assertPublicValues(
  actual: readonly Uint8Array[],
  expected: readonly bigint[],
): void {
  if (!Array.isArray(actual) || actual.length !== expected.length) {
    throw new Error(
      `proof backend returned ${actual.length} public values; expected ${expected.length}`,
    );
  }
  for (let index = 0; index < expected.length; index++) {
    const expectedBytes = bigintToLittleEndian32(expected[index]!);
    if (
      !(actual[index] instanceof Uint8Array) ||
      !equalBytes(actual[index]!, expectedBytes)
    ) {
      throw new Error(
        `proof public value ${index} does not match the expected verifier context`,
      );
    }
  }
}

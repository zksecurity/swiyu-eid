import { sha256 } from "@noble/hashes/sha2";
import { base64urlEncode } from "../utils.js";
import {
  computeSwiyuPreparedLookupCommitment,
  computeSwiyuPreparedSessionCommitment,
  type SwiyuHashLimbs,
} from "./commitments.js";
import { hashSwiyuChallenge } from "./challenge.js";
import { parseSwiyuIsoDate } from "./date.js";
import {
  bigintToLittleEndian32,
  concatBytes,
  decodeBase64urlStrict,
} from "./encoding.js";
import {
  buildSwiyuNullifierScope,
  computeSwiyuNullifierChallengeHash,
  computeSwiyuNullifierScopeDigest,
  swiyuNullifierDigestLimbs,
  type SwiyuNullifierScopeIdentifiers,
} from "./nullifier.js";
import type { SwiyuNullifierRegistry } from "./nullifier-registry.js";
import {
  SwiyuSplitZkpVerifier,
  SwiyuSplitZkpWallet,
  type SwiyuSplitChallenge,
  type SwiyuSplitPreparedCredential,
  type SwiyuSplitProofEnvelope,
} from "./split-proof.js";
import type {
  SwiyuChallenge,
  SwiyuKeyMaterial,
  SwiyuLookupHints,
} from "./types.js";

export const SWIYU_NULLIFIER_AGE18_PREPARE_CIRCUIT =
  "swiyu_nullifier_age18_prepare" as const;
export const SWIYU_NULLIFIER_AGE18_SHOW_CIRCUIT =
  "swiyu_nullifier_age18_show_packed_chunk_v2" as const;
export const SWIYU_NULLIFIER_AGE18_SPLIT_PROFILE =
  "swiyu.age-over-18.scoped-nullifier.v1" as const;

export const SWIYU_NULLIFIER_AGE18_SPLIT_DESCRIPTOR = Object.freeze({
  profile: SWIYU_NULLIFIER_AGE18_SPLIT_PROFILE,
  prepareCircuitId: SWIYU_NULLIFIER_AGE18_PREPARE_CIRCUIT,
  showCircuitId: SWIYU_NULLIFIER_AGE18_SHOW_CIRCUIT,
});

export type SwiyuNullifierAge18Challenge = SwiyuSplitChallenge<
  typeof SWIYU_NULLIFIER_AGE18_SPLIT_PROFILE,
  typeof SWIYU_NULLIFIER_AGE18_PREPARE_CIRCUIT,
  typeof SWIYU_NULLIFIER_AGE18_SHOW_CIRCUIT
>;
export type SwiyuNullifierAge18PreparedCredential = SwiyuSplitPreparedCredential<
  typeof SWIYU_NULLIFIER_AGE18_SPLIT_PROFILE,
  typeof SWIYU_NULLIFIER_AGE18_PREPARE_CIRCUIT,
  typeof SWIYU_NULLIFIER_AGE18_SHOW_CIRCUIT
>;

type BaseEnvelope = SwiyuSplitProofEnvelope<
  typeof SWIYU_NULLIFIER_AGE18_SPLIT_PROFILE,
  typeof SWIYU_NULLIFIER_AGE18_PREPARE_CIRCUIT,
  typeof SWIYU_NULLIFIER_AGE18_SHOW_CIRCUIT
>;

export interface SwiyuNullifierAge18ProofEnvelope extends BaseEnvelope {
  /** Public 32-byte nullifier authenticated by the Show proof. */
  nullifier: string;
}

/** Every field is verifier-selected or independently trust-checked. */
export interface SwiyuNullifierAge18VerifierPolicy {
  baseChallenge: Readonly<SwiyuChallenge>;
  scope: Readonly<SwiyuNullifierScopeIdentifiers>;
  acceptedLookup: Readonly<SwiyuLookupHints>;
  /** Root/URI-free commitment returned by the authenticated status resolver. */
  authoritativeStatusCommitment: Readonly<SwiyuHashLimbs>;
}

export function buildSwiyuNullifierAge18Authorization(
  policy: Readonly<SwiyuNullifierAge18VerifierPolicy>,
): Readonly<{ digest: Uint8Array; scalar: bigint; scopeDigest: Uint8Array }> {
  const base = hashSwiyuChallenge(policy.baseChallenge);
  const scopeDigest = computeSwiyuNullifierScopeDigest(
    buildSwiyuNullifierScope(policy.scope),
  );
  const challenge = computeSwiyuNullifierChallengeHash(base.scalar, scopeDigest);
  return Object.freeze({ ...challenge, scopeDigest });
}

export function buildSwiyuNullifierAge18Challenge(
  policy: Readonly<SwiyuNullifierAge18VerifierPolicy>,
): SwiyuNullifierAge18Challenge {
  return Object.freeze({
    ...SWIYU_NULLIFIER_AGE18_SPLIT_DESCRIPTOR,
    challengeHash: buildSwiyuNullifierAge18Authorization(policy).scalar,
    currentTime: policy.baseChallenge.currentTime,
  });
}

export function swiyuNullifierAge18PreparePublicValues(
  issuerPubKeyX: bigint,
  issuerPubKeyY: bigint,
): readonly Uint8Array[] {
  return [issuerPubKeyX, issuerPubKeyY].map(bigintToLittleEndian32);
}

/** Exact eleven public values consumed by the integrated Show circuit. */
export function swiyuNullifierAge18ShowPublicValues(
  policy: Readonly<SwiyuNullifierAge18VerifierPolicy>,
  nullifier: Uint8Array,
): readonly Uint8Array[] {
  const authorization = buildSwiyuNullifierAge18Authorization(policy);
  const lookup = computeSwiyuPreparedLookupCommitment(policy.acceptedLookup);
  const metadata = computeSwiyuPreparedSessionCommitment(
    authorization.scalar,
    lookup,
  );
  const status = policy.authoritativeStatusCommitment;
  const scope = swiyuNullifierDigestLimbs(authorization.scopeDigest);
  const expectedNullifier = swiyuNullifierDigestLimbs(
    require32(nullifier, "nullifier"),
  );
  return [
    authorization.scalar,
    parseSwiyuIsoDate(policy.baseChallenge.cutoffDate, "cutoff_date"),
    policy.baseChallenge.currentTime,
    metadata.hashHi,
    metadata.hashLo,
    status.hashHi,
    status.hashLo,
    scope.hashHi,
    scope.hashLo,
    expectedNullifier.hashHi,
    expectedNullifier.hashLo,
  ].map(bigintToLittleEndian32);
}

export class SwiyuNullifierAge18Wallet {
  constructor(private readonly splitWallet: SwiyuSplitZkpWallet) {}

  prepare(request: Readonly<{
    lookup: Readonly<SwiyuLookupHints>;
    issuerPubKeyX: bigint;
    issuerPubKeyY: bigint;
    prepareWitness: Uint8Array;
    prepareProvingKey: SwiyuKeyMaterial;
  }>): Promise<SwiyuNullifierAge18PreparedCredential> {
    return this.splitWallet.prepare({
      descriptor: SWIYU_NULLIFIER_AGE18_SPLIT_DESCRIPTOR,
      lookup: request.lookup,
      prepareWitness: request.prepareWitness,
      prepareProvingKey: request.prepareProvingKey,
      expectedPreparePublicValues: swiyuNullifierAge18PreparePublicValues(
        request.issuerPubKeyX,
        request.issuerPubKeyY,
      ),
    });
  }

  async show(request: Readonly<{
    prepared: SwiyuNullifierAge18PreparedCredential;
    policy: Readonly<SwiyuNullifierAge18VerifierPolicy>;
    nullifier: Uint8Array;
    showWitness: Uint8Array;
    showProvingKey: SwiyuKeyMaterial;
  }>): Promise<SwiyuNullifierAge18ProofEnvelope> {
    assertLookup(request.prepared.lookup, request.policy.acceptedLookup);
    const nullifier = require32(request.nullifier, "nullifier");
    const envelope = await this.splitWallet.show({
      prepared: request.prepared,
      challenge: buildSwiyuNullifierAge18Challenge(request.policy),
      showWitness: request.showWitness,
      showProvingKey: request.showProvingKey,
      expectedShowPublicValues: swiyuNullifierAge18ShowPublicValues(
        request.policy,
        nullifier,
      ),
    });
    return Object.freeze({ ...envelope, nullifier: base64urlEncode(nullifier) });
  }
}

export class SwiyuNullifierAge18Verifier {
  constructor(
    private readonly splitVerifier: SwiyuSplitZkpVerifier,
    private readonly registry: SwiyuNullifierRegistry,
    private readonly now: () => Date = () => new Date(),
  ) {}

  /** Statelessly verify both linked proofs and derive their registry values. */
  async verify(request: Readonly<{
    envelope: SwiyuNullifierAge18ProofEnvelope;
    policy: Readonly<SwiyuNullifierAge18VerifierPolicy>;
    issuerPubKeyX: bigint;
    issuerPubKeyY: bigint;
    prepareVerifyingKey: SwiyuKeyMaterial;
    showVerifyingKey: SwiyuKeyMaterial;
  }>): Promise<{
    valid: boolean;
    nullifier?: Uint8Array;
    scopeDigest?: Uint8Array;
    proofDigest?: Uint8Array;
    error?: string;
  }> {
    try {
      assertLookup(request.envelope.lookup, request.policy.acceptedLookup);
      const nullifier = decodeBase64urlStrict(
        request.envelope.nullifier,
        "nullifier",
        32,
      );
      const verification = await this.splitVerifier.verify({
        envelope: request.envelope,
        challenge: buildSwiyuNullifierAge18Challenge(request.policy),
        prepareVerifyingKey: request.prepareVerifyingKey,
        showVerifyingKey: request.showVerifyingKey,
        expectedPreparePublicValues: swiyuNullifierAge18PreparePublicValues(
          request.issuerPubKeyX,
          request.issuerPubKeyY,
        ),
        expectedShowPublicValues: swiyuNullifierAge18ShowPublicValues(
          request.policy,
          nullifier,
        ),
      });
      if (!verification.valid) {
        return { valid: false, error: verification.error };
      }
      const scopeDigest = buildSwiyuNullifierAge18Authorization(
        request.policy,
      ).scopeDigest;
      return {
        valid: true,
        scopeDigest,
        nullifier,
        proofDigest: proofEnvelopeDigest(request.envelope),
      };
    } catch (error) {
      return {
        valid: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /** Verify first, then atomically consume the verified nullifier. */
  async verifyAndClaim(request: Parameters<SwiyuNullifierAge18Verifier["verify"]>[0]): Promise<{
    valid: boolean;
    accepted: boolean;
    error?: string;
  }> {
    const verification = await this.verify(request);
    if (
      !verification.valid
      || !verification.scopeDigest
      || !verification.nullifier
      || !verification.proofDigest
    ) {
      return { valid: false, accepted: false, error: verification.error };
    }
    const accepted = await this.registry.insertVerifiedClaim({
      scopeDigest: verification.scopeDigest,
      nullifier: verification.nullifier,
      proofDigest: verification.proofDigest,
      acceptedAt: this.now(),
    });
    return accepted
      ? { valid: true, accepted: true }
      : { valid: true, accepted: false, error: "scoped nullifier was already consumed" };
  }
}

function proofEnvelopeDigest(envelope: SwiyuNullifierAge18ProofEnvelope): Uint8Array {
  return sha256(concatBytes([
    new TextEncoder().encode("swiyu-nullifier-proof-v1\0"),
    decodeBase64urlStrict(envelope.prepareProof, "Prepare proof"),
    decodeBase64urlStrict(envelope.showProof, "Show proof"),
  ]));
}

function require32(value: Uint8Array, label: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new Error(`${label} must contain exactly 32 bytes`);
  }
  return value;
}

function assertLookup(
  actual: Readonly<SwiyuLookupHints>,
  expected: Readonly<SwiyuLookupHints>,
): void {
  if (
    actual.issuer !== expected.issuer
    || actual.kid !== expected.kid
    || actual.vct !== expected.vct
  ) throw new Error("credential issuer, kid, or VCT is not accepted by nullifier policy");
}

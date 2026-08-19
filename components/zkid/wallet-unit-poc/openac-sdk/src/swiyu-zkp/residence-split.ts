import {
  computeSwiyuPreparedLookupCommitment,
} from "./commitments.js";
import { bigintToLittleEndian32 } from "./encoding.js";
import {
  buildResidenceEligibilityPublicInputs,
  computeSwiyuResidencePolicyChallengeHash,
  type ResidenceEligibilityPolicy,
} from "./residence-eligibility.js";
import {
  SwiyuSplitZkpVerifier,
  SwiyuSplitZkpWallet,
  type SwiyuSplitChallenge,
  type SwiyuSplitPreparedCredential,
  type SwiyuSplitProofEnvelope,
} from "./split-proof.js";
import type { SwiyuKeyMaterial, SwiyuLookupHints } from "./types.js";
import { SwiyuResidenceVerifierStatus } from "./residence-status.js";

export const SWIYU_RESIDENCE_ELIGIBILITY_PROFILE =
  "swiyu.residence-eligibility.combined-disclosure.v1" as const;
export const SWIYU_RESIDENCE_PREPARE_CIRCUIT =
  "swiyu_residence_combined_prepare_compact" as const;
export const SWIYU_RESIDENCE_SHOW_CIRCUIT =
  "swiyu_residence_show_packed_chunk_v2" as const;

export const SWIYU_RESIDENCE_SPLIT_DESCRIPTOR = Object.freeze({
  profile: SWIYU_RESIDENCE_ELIGIBILITY_PROFILE,
  prepareCircuitId: SWIYU_RESIDENCE_PREPARE_CIRCUIT,
  showCircuitId: SWIYU_RESIDENCE_SHOW_CIRCUIT,
});

export type SwiyuResidenceChallenge = SwiyuSplitChallenge<
  typeof SWIYU_RESIDENCE_ELIGIBILITY_PROFILE,
  typeof SWIYU_RESIDENCE_PREPARE_CIRCUIT,
  typeof SWIYU_RESIDENCE_SHOW_CIRCUIT
>;
export type SwiyuResidencePreparedCredential = SwiyuSplitPreparedCredential<
  typeof SWIYU_RESIDENCE_ELIGIBILITY_PROFILE,
  typeof SWIYU_RESIDENCE_PREPARE_CIRCUIT,
  typeof SWIYU_RESIDENCE_SHOW_CIRCUIT
>;
export type SwiyuResidenceProofEnvelope = SwiyuSplitProofEnvelope<
  typeof SWIYU_RESIDENCE_ELIGIBILITY_PROFILE,
  typeof SWIYU_RESIDENCE_PREPARE_CIRCUIT,
  typeof SWIYU_RESIDENCE_SHOW_CIRCUIT
>;

/** All values here are selected or trust-checked by the verifier. */
export interface SwiyuResidenceVerifierPolicy extends ResidenceEligibilityPolicy {
  /** Canonical session scalar before residence-policy domain separation. */
  baseChallengeHash: bigint;
  currentTime: bigint;
  acceptedLookup: Readonly<SwiyuLookupHints>;
  /** Authenticated statuslist+jwt result; carries no URI or root. */
  trustedStatus: SwiyuResidenceVerifierStatus;
}

export function buildSwiyuResidenceChallenge(
  policy: Readonly<SwiyuResidenceVerifierPolicy>,
): SwiyuResidenceChallenge {
  assertTrustedStatus(policy);
  return Object.freeze({
    ...SWIYU_RESIDENCE_SPLIT_DESCRIPTOR,
    challengeHash: computeSwiyuResidencePolicyChallengeHash(
      policy.baseChallengeHash,
      policy,
    ),
    currentTime: policy.currentTime,
  });
}

export function swiyuResidencePreparePublicValues(
  issuerPubKeyX: bigint,
  issuerPubKeyY: bigint,
): readonly Uint8Array[] {
  return [issuerPubKeyX, issuerPubKeyY].map(bigintToLittleEndian32);
}

export function swiyuResidenceShowPublicValues(
  policy: Readonly<SwiyuResidenceVerifierPolicy>,
): readonly Uint8Array[] {
  assertTrustedStatus(policy);
  const inputs = buildResidenceEligibilityPublicInputs({
    challengeHash: computeSwiyuResidencePolicyChallengeHash(
      policy.baseChallengeHash,
      policy,
    ),
    currentTime: policy.currentTime,
    preparedLookup: computeSwiyuPreparedLookupCommitment(policy.acceptedLookup),
    preparedStatusCommitment: policy.trustedStatus.preparedStatusCommitment,
    allowedMunicipalityBfs: policy.allowedMunicipalityBfs,
    minimumResidenceDays: policy.minimumResidenceDays,
    municipalityDirectoryAsOf: policy.municipalityDirectoryAsOf,
    municipalityDirectorySha256: policy.municipalityDirectorySha256,
  });
  return [
    inputs.challengeHash,
    BigInt(inputs.allowedCount),
    ...inputs.allowedMunicipalityCodes,
    BigInt(inputs.minimumResidenceDays),
    inputs.currentTime,
    inputs.expectedMetadataHashHi,
    inputs.expectedMetadataHashLo,
    inputs.expectedStatusSnapshotHashHi,
    inputs.expectedStatusSnapshotHashLo,
  ].map(bigintToLittleEndian32);
}

export class SwiyuResidenceEligibilityWallet {
  constructor(private readonly splitWallet: SwiyuSplitZkpWallet) {}

  prepare(request: Readonly<{
    lookup: Readonly<SwiyuLookupHints>;
    issuerPubKeyX: bigint;
    issuerPubKeyY: bigint;
    prepareWitness: Uint8Array;
    prepareProvingKey: SwiyuKeyMaterial;
  }>): Promise<SwiyuResidencePreparedCredential> {
    return this.splitWallet.prepare({
      descriptor: SWIYU_RESIDENCE_SPLIT_DESCRIPTOR,
      lookup: request.lookup,
      prepareWitness: request.prepareWitness,
      prepareProvingKey: request.prepareProvingKey,
      expectedPreparePublicValues: swiyuResidencePreparePublicValues(
        request.issuerPubKeyX,
        request.issuerPubKeyY,
      ),
    });
  }

  show(request: Readonly<{
    prepared: SwiyuResidencePreparedCredential;
    policy: Readonly<SwiyuResidenceVerifierPolicy>;
    showWitness: Uint8Array;
    showProvingKey: SwiyuKeyMaterial;
  }>): Promise<SwiyuResidenceProofEnvelope> {
    assertLookup(request.prepared.lookup, request.policy.acceptedLookup);
    return this.splitWallet.show({
      prepared: request.prepared,
      challenge: buildSwiyuResidenceChallenge(request.policy),
      showWitness: request.showWitness,
      showProvingKey: request.showProvingKey,
      expectedShowPublicValues: swiyuResidenceShowPublicValues(request.policy),
    });
  }
}

export class SwiyuResidenceEligibilityVerifier {
  constructor(private readonly splitVerifier: SwiyuSplitZkpVerifier) {}

  verify(request: Readonly<{
    envelope: SwiyuResidenceProofEnvelope;
    policy: Readonly<SwiyuResidenceVerifierPolicy>;
    issuerPubKeyX: bigint;
    issuerPubKeyY: bigint;
    prepareVerifyingKey: SwiyuKeyMaterial;
    showVerifyingKey: SwiyuKeyMaterial;
  }>): Promise<{ valid: boolean; error?: string }> {
    try {
      assertLookup(request.envelope.lookup, request.policy.acceptedLookup);
      const challenge = buildSwiyuResidenceChallenge(request.policy);
      const expectedShowPublicValues = swiyuResidenceShowPublicValues(request.policy);
      return this.splitVerifier.verify({
        envelope: request.envelope,
        challenge,
        prepareVerifyingKey: request.prepareVerifyingKey,
        showVerifyingKey: request.showVerifyingKey,
        expectedPreparePublicValues: swiyuResidencePreparePublicValues(
          request.issuerPubKeyX,
          request.issuerPubKeyY,
        ),
        expectedShowPublicValues,
      });
    } catch (error) {
      return Promise.resolve({
        valid: false,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
}

function assertLookup(actual: Readonly<SwiyuLookupHints>, expected: Readonly<SwiyuLookupHints>) {
  if (
    actual.issuer !== expected.issuer
    || actual.kid !== expected.kid
    || actual.vct !== expected.vct
  ) throw new Error("credential issuer, kid, or VCT is not accepted by residence policy");
}

function assertTrustedStatus(policy: Readonly<SwiyuResidenceVerifierPolicy>): void {
  const status = policy.trustedStatus;
  if (!SwiyuResidenceVerifierStatus.isAuthenticated(status)) {
    throw new Error("residence policy requires an authenticated ternary status-list result");
  }
  if (status.issuer !== policy.acceptedLookup.issuer) {
    throw new Error("status-list issuer does not match the accepted credential issuer");
  }
  if (
    policy.currentTime < BigInt(status.epoch)
    || policy.currentTime >= status.validBefore
  ) {
    throw new Error("authenticated residence status is not fresh at policy currentTime");
  }
  if (status.listLength < 1 || status.listLength > 131_072) {
    throw new Error("authenticated residence status list exceeds the profile limit");
  }
  if (status.treeProfile !== "packed-status-chunk-ternary-merkle-v2") {
    throw new Error("residence policy requires the packed-status-chunk v2 tree profile");
  }
}

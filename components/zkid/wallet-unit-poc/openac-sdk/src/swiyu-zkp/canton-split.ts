import {
  computeSwiyuPreparedLookupCommitment,
  computeSwiyuPreparedStatusUriCommitment,
} from "./commitments.js";
import { bigintToLittleEndian32 } from "./encoding.js";
import {
  buildCantonEligibilityPublicInputs,
  type CantonEligibilityPolicy,
} from "./canton-eligibility.js";
import {
  SwiyuSplitZkpVerifier,
  SwiyuSplitZkpWallet,
  type SwiyuSplitChallenge,
  type SwiyuSplitPreparedCredential,
  type SwiyuSplitProofEnvelope,
} from "./split-proof.js";
import type { SwiyuKeyMaterial, SwiyuLookupHints } from "./types.js";

export const SWIYU_CANTON_ELIGIBILITY_PROFILE =
  "swiyu.canton-eligibility.prepare-show.v1" as const;
export const SWIYU_CANTON_PREPARE_CIRCUIT =
  "swiyu_canton_prepare_compact" as const;
export const SWIYU_CANTON_SHOW_CIRCUIT =
  "swiyu_canton_show_split" as const;

export const SWIYU_CANTON_SPLIT_DESCRIPTOR = Object.freeze({
  profile: SWIYU_CANTON_ELIGIBILITY_PROFILE,
  prepareCircuitId: SWIYU_CANTON_PREPARE_CIRCUIT,
  showCircuitId: SWIYU_CANTON_SHOW_CIRCUIT,
});

export type SwiyuCantonChallenge = SwiyuSplitChallenge<
  typeof SWIYU_CANTON_ELIGIBILITY_PROFILE,
  typeof SWIYU_CANTON_PREPARE_CIRCUIT,
  typeof SWIYU_CANTON_SHOW_CIRCUIT
>;
export type SwiyuCantonPreparedCredential = SwiyuSplitPreparedCredential<
  typeof SWIYU_CANTON_ELIGIBILITY_PROFILE,
  typeof SWIYU_CANTON_PREPARE_CIRCUIT,
  typeof SWIYU_CANTON_SHOW_CIRCUIT
>;
export type SwiyuCantonProofEnvelope = SwiyuSplitProofEnvelope<
  typeof SWIYU_CANTON_ELIGIBILITY_PROFILE,
  typeof SWIYU_CANTON_PREPARE_CIRCUIT,
  typeof SWIYU_CANTON_SHOW_CIRCUIT
>;

/** All values here are selected or trust-checked by the verifier. */
export interface SwiyuCantonVerifierPolicy extends CantonEligibilityPolicy {
  challengeHash: bigint;
  currentTime: bigint;
  acceptedLookup: Readonly<SwiyuLookupHints>;
  authoritativeStatusUri: string;
  statusSnapshotRoot: string;
}

export function buildSwiyuCantonChallenge(
  policy: Readonly<SwiyuCantonVerifierPolicy>,
): SwiyuCantonChallenge {
  return Object.freeze({
    ...SWIYU_CANTON_SPLIT_DESCRIPTOR,
    challengeHash: policy.challengeHash,
    currentTime: policy.currentTime,
  });
}

export function swiyuCantonPreparePublicValues(
  issuerPubKeyX: bigint,
  issuerPubKeyY: bigint,
): readonly Uint8Array[] {
  return [issuerPubKeyX, issuerPubKeyY].map(bigintToLittleEndian32);
}

export function swiyuCantonShowPublicValues(
  policy: Readonly<SwiyuCantonVerifierPolicy>,
): readonly Uint8Array[] {
  const inputs = buildCantonEligibilityPublicInputs({
    challengeHash: policy.challengeHash,
    currentTime: policy.currentTime,
    preparedLookup: computeSwiyuPreparedLookupCommitment(policy.acceptedLookup),
    preparedStatusUri: computeSwiyuPreparedStatusUriCommitment(
      policy.authoritativeStatusUri,
    ),
    statusSnapshotRoot: policy.statusSnapshotRoot,
    allowedCantons: policy.allowedCantons,
  });
  return [
    inputs.challengeHash,
    BigInt(inputs.allowedCount),
    ...inputs.allowedCantonCodes,
    inputs.currentTime,
    inputs.expectedMetadataHashHi,
    inputs.expectedMetadataHashLo,
    inputs.expectedStatusSnapshotHashHi,
    inputs.expectedStatusSnapshotHashLo,
  ].map(bigintToLittleEndian32);
}

export class SwiyuCantonEligibilityWallet {
  constructor(private readonly splitWallet: SwiyuSplitZkpWallet) {}

  prepare(request: Readonly<{
    lookup: Readonly<SwiyuLookupHints>;
    issuerPubKeyX: bigint;
    issuerPubKeyY: bigint;
    prepareWitness: Uint8Array;
    prepareProvingKey: SwiyuKeyMaterial;
  }>): Promise<SwiyuCantonPreparedCredential> {
    return this.splitWallet.prepare({
      descriptor: SWIYU_CANTON_SPLIT_DESCRIPTOR,
      lookup: request.lookup,
      prepareWitness: request.prepareWitness,
      prepareProvingKey: request.prepareProvingKey,
      expectedPreparePublicValues: swiyuCantonPreparePublicValues(
        request.issuerPubKeyX,
        request.issuerPubKeyY,
      ),
    });
  }

  async show(request: Readonly<{
    prepared: SwiyuCantonPreparedCredential;
    policy: Readonly<SwiyuCantonVerifierPolicy>;
    showWitness: Uint8Array;
    showProvingKey: SwiyuKeyMaterial;
  }>): Promise<SwiyuCantonProofEnvelope> {
    assertLookup(request.prepared.lookup, request.policy.acceptedLookup);
    return this.splitWallet.show({
      prepared: request.prepared,
      challenge: buildSwiyuCantonChallenge(request.policy),
      showWitness: request.showWitness,
      showProvingKey: request.showProvingKey,
      expectedShowPublicValues: swiyuCantonShowPublicValues(request.policy),
    });
  }
}

export class SwiyuCantonEligibilityVerifier {
  constructor(private readonly splitVerifier: SwiyuSplitZkpVerifier) {}

  verify(request: Readonly<{
    envelope: SwiyuCantonProofEnvelope;
    policy: Readonly<SwiyuCantonVerifierPolicy>;
    issuerPubKeyX: bigint;
    issuerPubKeyY: bigint;
    prepareVerifyingKey: SwiyuKeyMaterial;
    showVerifyingKey: SwiyuKeyMaterial;
  }>): Promise<{ valid: boolean; error?: string }> {
    try {
      assertLookup(request.envelope.lookup, request.policy.acceptedLookup);
    } catch (error) {
      return Promise.resolve({
        valid: false,
        error: error instanceof Error ? error.message : String(error),
      });
    }
    return this.splitVerifier.verify({
      envelope: request.envelope,
      challenge: buildSwiyuCantonChallenge(request.policy),
      prepareVerifyingKey: request.prepareVerifyingKey,
      showVerifyingKey: request.showVerifyingKey,
      expectedPreparePublicValues: swiyuCantonPreparePublicValues(
        request.issuerPubKeyX,
        request.issuerPubKeyY,
      ),
      expectedShowPublicValues: swiyuCantonShowPublicValues(request.policy),
    });
  }
}

function assertLookup(actual: Readonly<SwiyuLookupHints>, expected: Readonly<SwiyuLookupHints>) {
  if (
    actual.issuer !== expected.issuer ||
    actual.kid !== expected.kid ||
    actual.vct !== expected.vct
  ) throw new Error("credential issuer, kid, or VCT is not accepted by canton policy");
}

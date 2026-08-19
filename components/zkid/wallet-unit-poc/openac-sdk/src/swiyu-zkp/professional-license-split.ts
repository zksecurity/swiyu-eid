import { bigintToLittleEndian32 } from "./encoding.js";
import {
  SWIYU_PROFESSIONAL_LICENSE_VCT,
  buildProfessionalLicensePublicContext,
} from "./professional-license.js";
import {
  SwiyuSplitZkpVerifier,
  SwiyuSplitZkpWallet,
  type SwiyuSplitChallenge,
  type SwiyuSplitPreparedCredential,
  type SwiyuSplitProofEnvelope,
} from "./split-proof.js";
import type { SwiyuKeyMaterial, SwiyuLookupHints } from "./types.js";

export const SWIYU_PROFESSIONAL_LICENSE_PROFILE =
  "swiyu.professional-license-valid-through.v1" as const;
export const SWIYU_PROFESSIONAL_LICENSE_PREPARE_CIRCUIT =
  "swiyu_professional_license_prepare_compact" as const;
export const SWIYU_PROFESSIONAL_LICENSE_SHOW_CIRCUIT =
  "swiyu_professional_license_show_split" as const;
export const SWIYU_PROFESSIONAL_LICENSE_SPLIT_DESCRIPTOR = Object.freeze({
  profile: SWIYU_PROFESSIONAL_LICENSE_PROFILE,
  prepareCircuitId: SWIYU_PROFESSIONAL_LICENSE_PREPARE_CIRCUIT,
  showCircuitId: SWIYU_PROFESSIONAL_LICENSE_SHOW_CIRCUIT,
});

export type SwiyuProfessionalLicenseChallenge = SwiyuSplitChallenge<
  typeof SWIYU_PROFESSIONAL_LICENSE_PROFILE,
  typeof SWIYU_PROFESSIONAL_LICENSE_PREPARE_CIRCUIT,
  typeof SWIYU_PROFESSIONAL_LICENSE_SHOW_CIRCUIT
> & { requiredValidUntil: bigint };
export type SwiyuProfessionalLicensePreparedCredential = SwiyuSplitPreparedCredential<
  typeof SWIYU_PROFESSIONAL_LICENSE_PROFILE,
  typeof SWIYU_PROFESSIONAL_LICENSE_PREPARE_CIRCUIT,
  typeof SWIYU_PROFESSIONAL_LICENSE_SHOW_CIRCUIT
>;
export type SwiyuProfessionalLicenseProofEnvelope = SwiyuSplitProofEnvelope<
  typeof SWIYU_PROFESSIONAL_LICENSE_PROFILE,
  typeof SWIYU_PROFESSIONAL_LICENSE_PREPARE_CIRCUIT,
  typeof SWIYU_PROFESSIONAL_LICENSE_SHOW_CIRCUIT
>;

export interface SwiyuProfessionalLicenseVerifierPolicy {
  challengeHash: bigint;
  currentTime: bigint;
  requiredValidUntil: bigint;
  acceptedLookup: Readonly<SwiyuLookupHints>;
  authoritativeStatusUri: string;
  statusSnapshotRoot: string;
}

export function buildSwiyuProfessionalLicenseChallenge(
  policy: Readonly<SwiyuProfessionalLicenseVerifierPolicy>,
): SwiyuProfessionalLicenseChallenge {
  return Object.freeze({
    ...SWIYU_PROFESSIONAL_LICENSE_SPLIT_DESCRIPTOR,
    challengeHash: policy.challengeHash,
    currentTime: policy.currentTime,
    requiredValidUntil: policy.requiredValidUntil,
  });
}

export function swiyuProfessionalLicensePreparePublicValues(
  issuerPubKeyX: bigint,
  issuerPubKeyY: bigint,
): readonly Uint8Array[] {
  return [issuerPubKeyX, issuerPubKeyY].map(bigintToLittleEndian32);
}

export function swiyuProfessionalLicenseShowPublicValues(
  policy: Readonly<SwiyuProfessionalLicenseVerifierPolicy>,
): readonly Uint8Array[] {
  assertLookup(policy.acceptedLookup);
  const context = buildProfessionalLicensePublicContext({
    lookup: policy.acceptedLookup,
    statusUri: policy.authoritativeStatusUri,
    statusRoot: policy.statusSnapshotRoot,
    challengeHash: policy.challengeHash,
    currentTime: policy.currentTime,
    requiredValidUntil: policy.requiredValidUntil,
  });
  return [
    context.challengeHash,
    context.currentTime,
    context.requiredValidUntil,
    context.expectedMetadata.hashHi,
    context.expectedMetadata.hashLo,
    context.expectedStatusSnapshot.hashHi,
    context.expectedStatusSnapshot.hashLo,
  ].map(bigintToLittleEndian32);
}

export class SwiyuProfessionalLicenseWallet {
  constructor(private readonly splitWallet: SwiyuSplitZkpWallet) {}

  prepare(request: Readonly<{
    lookup: Readonly<SwiyuLookupHints>;
    issuerPubKeyX: bigint;
    issuerPubKeyY: bigint;
    prepareWitness: Uint8Array;
    prepareProvingKey: SwiyuKeyMaterial;
  }>): Promise<SwiyuProfessionalLicensePreparedCredential> {
    assertLookup(request.lookup);
    return this.splitWallet.prepare({
      descriptor: SWIYU_PROFESSIONAL_LICENSE_SPLIT_DESCRIPTOR,
      lookup: request.lookup,
      prepareWitness: request.prepareWitness,
      prepareProvingKey: request.prepareProvingKey,
      expectedPreparePublicValues: swiyuProfessionalLicensePreparePublicValues(
        request.issuerPubKeyX, request.issuerPubKeyY,
      ),
    });
  }

  async show(request: Readonly<{
    prepared: SwiyuProfessionalLicensePreparedCredential;
    policy: Readonly<SwiyuProfessionalLicenseVerifierPolicy>;
    showWitness: Uint8Array;
    showProvingKey: SwiyuKeyMaterial;
  }>): Promise<SwiyuProfessionalLicenseProofEnvelope> {
    assertLookup(request.policy.acceptedLookup);
    assertSameLookup(request.prepared.lookup, request.policy.acceptedLookup);
    return this.splitWallet.show({
      prepared: request.prepared,
      challenge: buildSwiyuProfessionalLicenseChallenge(request.policy),
      showWitness: request.showWitness,
      showProvingKey: request.showProvingKey,
      expectedShowPublicValues: swiyuProfessionalLicenseShowPublicValues(request.policy),
    });
  }
}

export class SwiyuProfessionalLicenseVerifier {
  constructor(private readonly splitVerifier: SwiyuSplitZkpVerifier) {}

  verify(request: Readonly<{
    envelope: SwiyuProfessionalLicenseProofEnvelope;
    policy: Readonly<SwiyuProfessionalLicenseVerifierPolicy>;
    issuerPubKeyX: bigint;
    issuerPubKeyY: bigint;
    prepareVerifyingKey: SwiyuKeyMaterial;
    showVerifyingKey: SwiyuKeyMaterial;
  }>): Promise<{ valid: boolean; error?: string }> {
    try {
      assertLookup(request.policy.acceptedLookup);
      assertSameLookup(request.envelope.lookup, request.policy.acceptedLookup);
    } catch (error) {
      return Promise.resolve({ valid: false, error: error instanceof Error ? error.message : String(error) });
    }
    return this.splitVerifier.verify({
      envelope: request.envelope,
      challenge: buildSwiyuProfessionalLicenseChallenge(request.policy),
      prepareVerifyingKey: request.prepareVerifyingKey,
      showVerifyingKey: request.showVerifyingKey,
      expectedPreparePublicValues: swiyuProfessionalLicensePreparePublicValues(
        request.issuerPubKeyX, request.issuerPubKeyY,
      ),
      expectedShowPublicValues: swiyuProfessionalLicenseShowPublicValues(request.policy),
    });
  }
}

function assertLookup(lookup: Readonly<SwiyuLookupHints>) {
  if (lookup.vct !== SWIYU_PROFESSIONAL_LICENSE_VCT) {
    throw new Error(`credential VCT is not accepted: expected ${SWIYU_PROFESSIONAL_LICENSE_VCT}`);
  }
}

function assertSameLookup(actual: Readonly<SwiyuLookupHints>, expected: Readonly<SwiyuLookupHints>) {
  if (actual.issuer !== expected.issuer || actual.kid !== expected.kid || actual.vct !== expected.vct) {
    throw new Error("credential issuer, kid, or VCT is not accepted by professional-licence policy");
  }
}

export {
  SWIYU_AGE18_STATUS_PROFILE,
  SWIYU_AGE18_STATUS_CIRCUIT,
  SWIYU_PROOF_ENVELOPE_VERSION,
  SWIYU_MESSAGE_BYTES,
  SWIYU_MAX_B64_HEADER_BYTES,
  SWIYU_MAX_B64_PAYLOAD_BYTES,
  SWIYU_MAX_STATUS_LIST_LENGTH,
  SWIYU_STATUS_DEPTH,
  SWIYU_STRING_SLOT_BYTES,
  SWIYU_PROFILE_VERSION,
  SWIYU_P256_BASE_FIELD,
  SWIYU_P256_SCALAR_ORDER,
  SWIYU_CIRCUIT_FIELD,
} from "./constants.js";
export { parseSwiyuCompactSdJwt } from "./parser.js";
export { parseSwiyuIsoDate } from "./date.js";
export { encodeSwiyuChallenge, hashSwiyuChallenge } from "./challenge.js";
export {
  computeSwiyuMetadataCommitment,
  computeSwiyuStatusProfileCommitment,
  validatePrivateStatusSnapshot,
  validateAuthoritativeStatusSnapshot,
} from "./commitments.js";
export { verifySwiyuDenseStatusWitness } from "./status.js";
export {
  SWIYU_PROFESSIONAL_LICENSE_VCT,
  buildProfessionalLicensePublicContext,
  buildProfessionalLicenseShowInputs,
} from "./professional-license.js";
export type {
  ProfessionalLicensePolicyRequest,
  ProfessionalLicensePublicContext,
  ProfessionalLicensePreparedValues,
  ProfessionalLicenseOnlineWitness,
  ProfessionalLicenseShowInputs,
} from "./professional-license.js";
export {
  SWIYU_PROFESSIONAL_LICENSE_PROFILE,
  SWIYU_PROFESSIONAL_LICENSE_PREPARE_CIRCUIT,
  SWIYU_PROFESSIONAL_LICENSE_SHOW_CIRCUIT,
  SWIYU_PROFESSIONAL_LICENSE_SPLIT_DESCRIPTOR,
  buildSwiyuProfessionalLicenseChallenge,
  swiyuProfessionalLicensePreparePublicValues,
  swiyuProfessionalLicenseShowPublicValues,
  SwiyuProfessionalLicenseWallet,
  SwiyuProfessionalLicenseVerifier,
} from "./professional-license-split.js";
export type {
  SwiyuProfessionalLicenseChallenge,
  SwiyuProfessionalLicensePreparedCredential,
  SwiyuProfessionalLicenseProofEnvelope,
  SwiyuProfessionalLicenseVerifierPolicy,
} from "./professional-license-split.js";
export { resolveSwiyuStatusListJwt } from "./status-list-resolver.js";
export type {
  SwiyuStatusListJwtResolutionRequest,
  SwiyuResolvedStatusList,
  SwiyuBoundedZlibInflater,
} from "./status-list-resolver.js";
export {
  FixedIndexStatusTree,
  SWIYU_FIXED_STATUS_DEPTH,
} from "../status-designs/fixed-index-merkle.js";
export type {
  FixedIndexStatusTreeOptions,
  FixedIndexStatusWitness,
  FixedIndexVerificationContext,
  StatusBit,
} from "../status-designs/fixed-index-merkle.js";
export {
  SWIYU_PUBLIC_VALUE_NAMES,
  buildSwiyuPublicContext,
  swiyuPublicContextScalars,
  encodeSwiyuExpectedPublicContext,
} from "./public-context.js";
export {
  WasmSwiyuProofBackend,
  WasmBridgeSwiyuProofBackend,
} from "./backend.js";
export {
  prepareSwiyuCredential,
  provisionSwiyuCredentialStatus,
  SwiyuZkpWallet,
  SwiyuZkpVerifier,
} from "./wallet.js";
export type {
  SwiyuCredentialStatusProvisioningRequest,
  SwiyuProvisionedCredentialStatus,
} from "./wallet.js";
export {
  SWIYU_SIDECAR_MAX_PROOF_ENVELOPE_BYTES,
  SWIYU_SIDECAR_MAX_REQUEST_BYTES,
  SwiyuSidecarRejection,
  SwiyuVerifierSidecarService,
  parseSwiyuSidecarRequest,
} from "./sidecar.js";
export type {
  SwiyuProfile,
  SwiyuCircuitId,
  SwiyuPrivateStatusSnapshot,
  SwiyuAuthoritativeStatusSnapshot,
  SwiyuStatusCommitment,
  SwiyuDenseStatusWitness,
  SwiyuChallenge,
  SwiyuHolderSigner,
  SwiyuWitnessGenerator,
  SwiyuLocalKeyFile,
  SwiyuKeyMaterial,
  SwiyuProofBackend,
  SwiyuProveResult,
  SwiyuBackendVerification,
  SwiyuLookupHints,
  SwiyuProofEnvelope,
  SwiyuPrepareRequest,
  SwiyuShowRequest,
  SwiyuVerifyRequest,
  SwiyuVerificationResult,
  SwiyuPublicContext,
  SwiyuCircuitInputs,
  SwiyuPreparedCredential,
} from "./types.js";
export type {
  SwiyuSidecarTrustAnchor,
  SwiyuSidecarIssuerRecord,
  SwiyuSidecarExpectedContext,
  SwiyuSidecarRequest,
  SwiyuSidecarSuccessResponse,
  SwiyuVerifierSidecarDependencies,
} from "./sidecar.js";
export type { SwiyuWasmBindings, SwiyuBridgeBindings } from "./backend.js";
export {
  SWISS_CANTONS,
  assertCantonEligible,
  buildCantonEligibilityPublicInputs,
  encodeSwissCanton,
} from "./canton-eligibility.js";
export {
  SWIYU_SPLIT_PROOF_ENVELOPE_VERSION,
  SwiyuSplitZkpWallet,
  SwiyuSplitZkpVerifier,
} from "./split-proof.js";
export type {
  SwiyuSplitProfileDescriptor,
  SwiyuSplitChallenge,
  SwiyuSplitProofBackend,
  SwiyuSplitBackendPrepared,
  SwiyuSplitProofPart,
  SwiyuSplitBackendVerification,
  SwiyuSplitPreparedCredential,
  SwiyuSplitProofEnvelope,
} from "./split-proof.js";
export {
  SWIYU_CANTON_ELIGIBILITY_PROFILE,
  SWIYU_CANTON_PREPARE_CIRCUIT,
  SWIYU_CANTON_SHOW_CIRCUIT,
  SWIYU_CANTON_SPLIT_DESCRIPTOR,
  buildSwiyuCantonChallenge,
  swiyuCantonPreparePublicValues,
  swiyuCantonShowPublicValues,
  SwiyuCantonEligibilityWallet,
  SwiyuCantonEligibilityVerifier,
} from "./canton-split.js";
export type {
  SwiyuCantonChallenge,
  SwiyuCantonPreparedCredential,
  SwiyuCantonProofEnvelope,
  SwiyuCantonVerifierPolicy,
} from "./canton-split.js";
export type {
  CantonEligibilityPolicy,
  CantonEligibilityPublicInputs,
  CantonEligibilityPublicRequest,
  SwissCanton,
} from "./canton-eligibility.js";
export {
  SWIYU_RESIDENCE_MAX_MUNICIPALITIES,
  SWIYU_RESIDENCE_MAX_BFS_CODE,
  SWIYU_RESIDENCE_MAX_DURATION_DAYS,
  SWIYU_RESIDENCE_DAY_BITS,
  SWIYU_RESIDENCE_MUNICIPALITY_BITS,
  SWIYU_DAYS_1900_TO_UNIX_EPOCH,
  residenceDateToDay1900,
  packSwiyuResidence,
  unpackSwiyuResidence,
  buildResidenceEligibilityPublicInputs,
  computeSwiyuResidencePolicyChallengeHash,
  assertResidenceEligible,
  validateResidenceEligibilityPolicy,
} from "./residence-eligibility.js";
export type {
  ResidenceMunicipalityCodes,
  ResidenceEligibilityPolicy,
  ResidenceEligibilityPublicRequest,
  ResidenceMunicipalityCodeSlots,
  ResidenceEligibilityPublicInputs,
} from "./residence-eligibility.js";
export {
  SWIYU_RESIDENCE_ELIGIBILITY_PROFILE,
  SWIYU_RESIDENCE_PREPARE_CIRCUIT,
  SWIYU_RESIDENCE_SHOW_CIRCUIT,
  SWIYU_RESIDENCE_SPLIT_DESCRIPTOR,
  buildSwiyuResidenceChallenge,
  swiyuResidencePreparePublicValues,
  swiyuResidenceShowPublicValues,
  SwiyuResidenceEligibilityWallet,
  SwiyuResidenceEligibilityVerifier,
} from "./residence-split.js";
export type {
  SwiyuResidenceChallenge,
  SwiyuResidencePreparedCredential,
  SwiyuResidenceProofEnvelope,
  SwiyuResidenceVerifierPolicy,
} from "./residence-split.js";
export {
  resolveSwiyuPackedStatusListJwt,
  resolveSwiyuTernaryStatusListJwt,
  SwiyuResidenceVerifierStatus,
} from "./residence-status.js";
export {
  SWIYU_BENCHMARK_AGE_PACKED_STATUS_V2,
  SWIYU_PACKED_STATUS_SHOW_PROFILES_V2,
} from "./status-benchmark-manifest.js";
export type {
  SwiyuTernaryStatusListJwtResolutionRequest,
  SwiyuResidenceBoundedZlibInflater,
  SwiyuResolvedPackedStatusList,
  SwiyuResolvedTernaryStatusList,
} from "./residence-status.js";
export {
  SWIYU_NULLIFIER_VERSION,
  SWIYU_NULLIFIER_SECRET_BYTES,
  SWIYU_NULLIFIER_CREDENTIAL_UID_BYTES,
  SWIYU_NULLIFIER_AGE18_PROFILE,
  assertSwiyuNullifierHolderSecret,
  generateSwiyuNullifierHolderSecret,
  computeSwiyuNullifierSecretCommitment,
  computeSwiyuNullifierCredentialSeed,
  buildSwiyuNullifierIssuerRecord,
  computeSwiyuNullifierScopeDigest,
  buildSwiyuNullifierScope,
  computeSwiyuScopedNullifier,
  computeSwiyuNullifierChallengeHash,
  swiyuNullifierDigestLimbs,
  buildSwiyuNullifierPrepareWitness,
  buildSwiyuNullifierShowWitness,
  hashSwiyuNullifierIdentifier,
} from "./nullifier.js";
export type {
  SwiyuNullifierCredentialMaterial,
  SwiyuNullifierScope,
  SwiyuNullifierPrepareWitness,
  SwiyuNullifierShowWitness,
  SwiyuNullifierScopeIdentifiers,
  SwiyuRandomValuesSource,
} from "./nullifier.js";
export { InMemorySwiyuNullifierRegistry } from "./nullifier-registry.js";
export type {
  SwiyuSpentNullifier,
  SwiyuNullifierRegistry,
} from "./nullifier-registry.js";
export {
  SWIYU_NULLIFIER_AGE18_PREPARE_CIRCUIT,
  SWIYU_NULLIFIER_AGE18_SHOW_CIRCUIT,
  SWIYU_NULLIFIER_AGE18_SPLIT_PROFILE,
  SWIYU_NULLIFIER_AGE18_SPLIT_DESCRIPTOR,
  buildSwiyuNullifierAge18Authorization,
  buildSwiyuNullifierAge18Challenge,
  swiyuNullifierAge18PreparePublicValues,
  swiyuNullifierAge18ShowPublicValues,
  SwiyuNullifierAge18Wallet,
  SwiyuNullifierAge18Verifier,
} from "./nullifier-age18-split.js";
export type {
  SwiyuNullifierAge18Challenge,
  SwiyuNullifierAge18PreparedCredential,
  SwiyuNullifierAge18ProofEnvelope,
  SwiyuNullifierAge18VerifierPolicy,
} from "./nullifier-age18-split.js";

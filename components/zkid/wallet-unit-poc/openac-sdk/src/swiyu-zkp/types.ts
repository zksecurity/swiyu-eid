import type { EcdsaPublicKey } from "../types.js";
import type { FixedIndexStatusWitness } from "../status-designs/fixed-index-merkle.js";
import type {
  SWIYU_AGE18_STATUS_CIRCUIT,
  SWIYU_AGE18_STATUS_PROFILE,
  SWIYU_PROOF_ENVELOPE_VERSION,
} from "./constants.js";

export type SwiyuProfile = typeof SWIYU_AGE18_STATUS_PROFILE;
export type SwiyuCircuitId = typeof SWIYU_AGE18_STATUS_CIRCUIT;

/** Wallet-only status material. URI, root, and Merkle path never reach the verifier. */
export interface SwiyuPrivateStatusSnapshot {
  /** Opaque verifier policy identifier. This, rather than the URI, may travel in the envelope. */
  id: string;
  /** Token Status List URI. It remains private credential/snapshot input. */
  uri: string;
  /** SHA-256 snapshot root from `FixedIndexStatusTree`. */
  root: string;
  epoch: number;
  listLength: number;
}

export interface SwiyuStatusCommitment {
  hashHi: bigint;
  hashLo: bigint;
}

/** Opaque snapshot metadata returned by a trusted status-list resolver. */
export interface SwiyuAuthoritativeStatusSnapshot {
  id: string;
  /** Issuer authenticated as the signer of the local status-list JWT. */
  issuer: string;
  /** Protected kid authenticated as the status-list JWT signing key. */
  kid: string;
  /** Exact status-list JWT subject, equal to the private credential status URI. */
  subject: string;
  /** Precomputed commitment to the private URI and authenticated snapshot root. */
  commitment: Readonly<SwiyuStatusCommitment>;
  epoch: number;
  listLength: number;
  /** Exclusive Unix-seconds freshness boundary authenticated by the resolver. */
  validBefore: bigint;
  /** Non-secret audit handle identifying the authenticated source token. */
  provenance: string;
}

export type SwiyuDenseStatusWitness = FixedIndexStatusWitness;

export interface SwiyuChallenge {
  nonce: string;
  clientId: string;
  responseUri: string;
  state: string;
  queryId: string;
  profile: SwiyuProfile;
  /** Strict Gregorian YYYY-MM-DD cutoff, normally today minus eighteen years. */
  cutoffDate: string;
  /** Verifier time as Unix seconds. */
  currentTime: bigint;
  /** Opaque policy snapshot id, not a status-list URI. */
  statusListSnapshot: string;
}

export interface SwiyuHolderSigner {
  /** Sign the already-computed 32-byte SHA-256 challenge digest using P-256 ECDSA. */
  signChallengeDigest(
    digest: Uint8Array,
    challenge: Readonly<SwiyuChallenge>,
  ): Promise<Uint8Array> | Uint8Array;
}

export interface SwiyuWitnessGenerator {
  calculateSwiyuWitnessWtns(
    inputs: Readonly<SwiyuCircuitInputs>,
  ): Promise<Uint8Array>;
}

export interface SwiyuProveResult {
  proof: Uint8Array;
  /** Ten little-endian field elements returned by the real proof backend. */
  publicValues: readonly Uint8Array[];
}

export interface SwiyuBackendVerification {
  valid: boolean;
  publicValues: readonly Uint8Array[];
  error?: string;
}

/**
 * A key intentionally kept on the local filesystem.
 *
 * The fixed-profile proving key is too large to copy through the JS/WASM
 * boundary. Only the Node native backend accepts this reference; browser and
 * WASM backends reject it at runtime.
 */
export interface SwiyuLocalKeyFile {
  readonly kind: "local-file";
  readonly path: string;
}

export type SwiyuKeyMaterial = Uint8Array | SwiyuLocalKeyFile;

/** Production proof boundary. Implementations must call a real prover/verifier. */
export interface SwiyuProofBackend {
  proveFromWitness(
    provingKey: SwiyuKeyMaterial,
    witness: Uint8Array,
  ): Promise<SwiyuProveResult>;
  verify(
    proof: Uint8Array,
    verifyingKey: SwiyuKeyMaterial,
    expectedPublicContext: Uint8Array,
  ): Promise<SwiyuBackendVerification>;
}

export interface SwiyuLookupHints {
  issuer: string;
  kid: string;
  vct: string;
}

export interface SwiyuProofEnvelope {
  version: typeof SWIYU_PROOF_ENVELOPE_VERSION;
  profile: SwiyuProfile;
  circuitId: SwiyuCircuitId;
  /** Canonical unpadded base64url encoding of the single Spartan proof. */
  proof: string;
  lookup: Readonly<SwiyuLookupHints>;
}

export interface SwiyuPrepareRequest {
  /**
   * Issuer-signed JWT + 1..64 disclosures, with an optional terminal `~`.
   * Every supplied disclosure is authenticated through the nested SD-JWT
   * disclosure graph; the fixed relation selects exactly one top-level
   * `birthdate` disclosure as its private predicate input.
   */
  compactSdJwt: string;
  /** P-256 issuer key resolved and trust-checked by the caller. */
  issuerPublicKey: EcdsaPublicKey;
}

export interface SwiyuShowRequest {
  prepared: SwiyuPreparedCredential;
  challenge: SwiyuChallenge;
  holderSigner: SwiyuHolderSigner;
  statusSnapshot: SwiyuPrivateStatusSnapshot;
  statusWitness: SwiyuDenseStatusWitness;
  provingKey: SwiyuKeyMaterial;
}

export interface SwiyuVerifyRequest {
  envelope: SwiyuProofEnvelope;
  challenge: SwiyuChallenge;
  /** Key resolved from envelope.lookup and independently trust-checked. */
  issuerPublicKey: EcdsaPublicKey;
  /** Snapshot resolved from the challenge's opaque policy id. */
  statusSnapshot: SwiyuAuthoritativeStatusSnapshot;
  verifyingKey: SwiyuKeyMaterial;
}

export interface SwiyuVerificationResult {
  valid: boolean;
  error?: string;
}

export interface SwiyuPublicContext {
  expressionResult: 1n;
  issuerPubKeyX: bigint;
  issuerPubKeyY: bigint;
  challengeHash: bigint;
  cutoffDate: bigint;
  currentTime: bigint;
  expectedMetadataHashHi: bigint;
  expectedMetadataHashLo: bigint;
  expectedStatusSnapshotHashHi: bigint;
  expectedStatusSnapshotHashLo: bigint;
}

/** Input names and dimensions exactly match `swiyu_age18_status_2k.circom`. */
export interface SwiyuCircuitInputs {
  issuerPubKeyX: bigint;
  issuerPubKeyY: bigint;
  challengeHash: bigint;
  cutoffDate: bigint;
  currentTime: bigint;
  expectedMetadataHashHi: bigint;
  expectedMetadataHashLo: bigint;
  expectedStatusSnapshotHashHi: bigint;
  expectedStatusSnapshotHashLo: bigint;
  message: bigint[];
  messageLength: number;
  periodIndex: number;
  headerJsonLength: number;
  payloadJsonLength: number;
  issuerSigR: bigint;
  issuerSigSInverse: bigint;
  disclosurePadded: bigint[];
  disclosureLength: number;
  disclosureJsonLength: number;
  disclosureSaltLength: number;
  holderSigR: bigint;
  holderSigSInverse: bigint;
  iss: bigint[];
  issLength: number;
  kid: bigint[];
  kidLength: number;
  vct: bigint[];
  vctLength: number;
  holderXB64: bigint[];
  holderYB64: bigint[];
  statusUri: bigint[];
  statusUriLength: number;
  nbfDigitLength: number;
  expDigitLength: number;
  statusIndexDigitLength: number;
  disclosureDigestB64: bigint[];
  statusValue: 0;
  statusSiblings: bigint[][];
  statusEpoch: number;
  statusListLength: number;
  headerAlgKeyStart: number;
  headerTypKeyStart: number;
  headerProfileVersionKeyStart: number;
  headerKidKeyStart: number;
  payloadIssKeyStart: number;
  payloadVctKeyStart: number;
  payloadNbfKeyStart: number;
  payloadExpKeyStart: number;
  payloadCnfKeyStart: number;
  payloadCnfClose: number;
  payloadJwkKeyStart: number;
  payloadJwkClose: number;
  payloadKtyKeyStart: number;
  payloadCrvKeyStart: number;
  payloadXKeyStart: number;
  payloadYKeyStart: number;
  payloadStatusKeyStart: number;
  payloadStatusClose: number;
  payloadStatusListKeyStart: number;
  payloadStatusListClose: number;
  payloadStatusUriKeyStart: number;
  payloadStatusIdxKeyStart: number;
  payloadSdAlgKeyStart: number;
  payloadSdKeyStart: number;
  payloadSdClose: number;
  payloadDigestStart: number;
}

/** Opaque class surface; construction is restricted to `prepareSwiyuCredential`. */
export interface SwiyuPreparedCredential {
  readonly profile: SwiyuProfile;
  readonly circuitId: SwiyuCircuitId;
  readonly lookup: SwiyuLookupHints;
}

import { base64urlEncode } from "../utils.js";
import {
  assertFieldElement,
  decodeBase64urlStrict,
  equalBytes,
} from "./encoding.js";
import type { SwiyuKeyMaterial, SwiyuLookupHints } from "./types.js";

export const SWIYU_SPLIT_PROOF_ENVELOPE_VERSION =
  "swiyu.split-proof-envelope.v1" as const;

export interface SwiyuSplitProfileDescriptor<
  Profile extends string = string,
  PrepareCircuit extends string = string,
  ShowCircuit extends string = string,
> {
  profile: Profile;
  prepareCircuitId: PrepareCircuit;
  showCircuitId: ShowCircuit;
}

export interface SwiyuSplitChallenge<
  Profile extends string = string,
  PrepareCircuit extends string = string,
  ShowCircuit extends string = string,
> extends SwiyuSplitProfileDescriptor<Profile, PrepareCircuit, ShowCircuit> {
  /** Field element obtained from the profile's canonical session encoding. */
  challengeHash: bigint;
  /** Verifier-selected Unix time used by the Show relation. */
  currentTime: bigint;
}

export interface SwiyuSplitBackendPrepared {
  /** Backend-private reusable assignment/instance handle. */
  handle: unknown;
  publicValues: readonly Uint8Array[];
}

export interface SwiyuSplitProofPart {
  proof: Uint8Array;
  publicValues: readonly Uint8Array[];
  /** Commitment extracted from the proof, never accepted from the envelope. */
  sharedCommitment: Uint8Array;
}

export interface SwiyuSplitBackendVerification {
  valid: boolean;
  publicValues: readonly Uint8Array[];
  sharedCommitment: Uint8Array;
  error?: string;
}

/**
 * Real backend boundary for the zkID Prepare/Show lifecycle.
 *
 * `prepare` may retain an in-memory assignment or return a durable handle.
 * `proveLinked` must reblind Prepare and Show with the same fresh randomness.
 * `verifyProof` must return the shared commitment embedded in the verified
 * proof so the SDK, independently of the backend, can compare both halves.
 */
export interface SwiyuSplitProofBackend {
  prepare(request: Readonly<{
    circuitId: string;
    provingKey: SwiyuKeyMaterial;
    witness: Uint8Array;
  }>): Promise<SwiyuSplitBackendPrepared>;

  proveLinked(request: Readonly<{
    prepareCircuitId: string;
    showCircuitId: string;
    preparedHandle: unknown;
    showProvingKey: SwiyuKeyMaterial;
    showWitness: Uint8Array;
  }>): Promise<Readonly<{
    prepare: SwiyuSplitProofPart;
    show: SwiyuSplitProofPart;
  }>>;

  /**
   * Verify with the key and circuit selected by the caller. Returned public
   * values and the shared commitment MUST be decoded from the verified proof;
   * an implementation must never echo `expectedPublicValues` or envelope data
   * as if they had been authenticated by the proof.
   */
  verifyProof(request: Readonly<{
    circuitId: string;
    proof: Uint8Array;
    verifyingKey: SwiyuKeyMaterial;
    expectedPublicValues: readonly Uint8Array[];
  }>): Promise<SwiyuSplitBackendVerification>;
}

export interface SwiyuSplitPreparedCredential<
  Profile extends string = string,
  PrepareCircuit extends string = string,
  ShowCircuit extends string = string,
> extends SwiyuSplitProfileDescriptor<Profile, PrepareCircuit, ShowCircuit> {
  readonly lookup: Readonly<SwiyuLookupHints>;
}

export interface SwiyuSplitProofEnvelope<
  Profile extends string = string,
  PrepareCircuit extends string = string,
  ShowCircuit extends string = string,
> extends SwiyuSplitProfileDescriptor<Profile, PrepareCircuit, ShowCircuit> {
  version: typeof SWIYU_SPLIT_PROOF_ENVELOPE_VERSION;
  prepareProof: string;
  showProof: string;
  lookup: Readonly<SwiyuLookupHints>;
}

type PreparedState = {
  backendHandle: unknown;
  preparePublicValues: readonly Uint8Array[];
};

class PreparedCredential<
  Profile extends string,
  PrepareCircuit extends string,
  ShowCircuit extends string,
> implements SwiyuSplitPreparedCredential<Profile, PrepareCircuit, ShowCircuit> {
  readonly lookup: Readonly<SwiyuLookupHints>;

  constructor(
    readonly profile: Profile,
    readonly prepareCircuitId: PrepareCircuit,
    readonly showCircuitId: ShowCircuit,
    lookup: Readonly<SwiyuLookupHints>,
  ) {
    this.lookup = Object.freeze({ ...lookup });
    Object.freeze(this);
  }
}

export class SwiyuSplitZkpWallet {
  private readonly preparedStates = new WeakMap<object, PreparedState>();

  constructor(private readonly backend: SwiyuSplitProofBackend) {}

  async prepare<Profile extends string, PrepareCircuit extends string, ShowCircuit extends string>(
    request: Readonly<{
      descriptor: SwiyuSplitProfileDescriptor<Profile, PrepareCircuit, ShowCircuit>;
      lookup: Readonly<SwiyuLookupHints>;
      prepareWitness: Uint8Array;
      prepareProvingKey: SwiyuKeyMaterial;
      expectedPreparePublicValues: readonly Uint8Array[];
    }>,
  ): Promise<SwiyuSplitPreparedCredential<Profile, PrepareCircuit, ShowCircuit>> {
    validateDescriptor(request.descriptor);
    validateWitness(request.prepareWitness, "Prepare witness");
    const expected = copyPublicValues(request.expectedPreparePublicValues);
    const result = await this.backend.prepare({
      circuitId: request.descriptor.prepareCircuitId,
      provingKey: request.prepareProvingKey,
      witness: request.prepareWitness,
    });
    if (result.handle === null || result.handle === undefined) {
      throw new Error("split proof backend returned no reusable Prepare handle");
    }
    assertPublicValues(result.publicValues, expected, "Prepare");
    const prepared = new PreparedCredential(
      request.descriptor.profile,
      request.descriptor.prepareCircuitId,
      request.descriptor.showCircuitId,
      request.lookup,
    );
    this.preparedStates.set(prepared, {
      backendHandle: result.handle,
      preparePublicValues: expected,
    });
    return prepared;
  }

  async show<Profile extends string, PrepareCircuit extends string, ShowCircuit extends string>(
    request: Readonly<{
      prepared: SwiyuSplitPreparedCredential<Profile, PrepareCircuit, ShowCircuit>;
      challenge: SwiyuSplitChallenge<Profile, PrepareCircuit, ShowCircuit>;
      showWitness: Uint8Array;
      showProvingKey: SwiyuKeyMaterial;
      expectedShowPublicValues: readonly Uint8Array[];
    }>,
  ): Promise<SwiyuSplitProofEnvelope<Profile, PrepareCircuit, ShowCircuit>> {
    const state = this.preparedStates.get(request.prepared as object);
    if (!state) throw new Error("prepared credential was not created by this split wallet");
    validateChallenge(request.challenge);
    assertSameDescriptor(request.prepared, request.challenge);
    validateWitness(request.showWitness, "Show witness");
    const expectedShow = copyPublicValues(request.expectedShowPublicValues);
    const result = await this.backend.proveLinked({
      prepareCircuitId: request.prepared.prepareCircuitId,
      showCircuitId: request.prepared.showCircuitId,
      preparedHandle: state.backendHandle,
      showProvingKey: request.showProvingKey,
      showWitness: request.showWitness,
    });
    validateProofPart(result.prepare, "Prepare");
    validateProofPart(result.show, "Show");
    assertPublicValues(result.prepare.publicValues, state.preparePublicValues, "Prepare");
    assertPublicValues(result.show.publicValues, expectedShow, "Show");
    if (!equalBytes(result.prepare.sharedCommitment, result.show.sharedCommitment)) {
      throw new Error("Prepare and Show proofs are not linked by the same shared commitment");
    }
    return Object.freeze({
      version: SWIYU_SPLIT_PROOF_ENVELOPE_VERSION,
      profile: request.prepared.profile,
      prepareCircuitId: request.prepared.prepareCircuitId,
      showCircuitId: request.prepared.showCircuitId,
      prepareProof: base64urlEncode(result.prepare.proof),
      showProof: base64urlEncode(result.show.proof),
      lookup: request.prepared.lookup,
    });
  }
}

export class SwiyuSplitZkpVerifier {
  constructor(private readonly backend: SwiyuSplitProofBackend) {}

  async verify<Profile extends string, PrepareCircuit extends string, ShowCircuit extends string>(
    request: Readonly<{
      envelope: SwiyuSplitProofEnvelope<Profile, PrepareCircuit, ShowCircuit>;
      challenge: SwiyuSplitChallenge<Profile, PrepareCircuit, ShowCircuit>;
      prepareVerifyingKey: SwiyuKeyMaterial;
      showVerifyingKey: SwiyuKeyMaterial;
      expectedPreparePublicValues: readonly Uint8Array[];
      expectedShowPublicValues: readonly Uint8Array[];
    }>,
  ): Promise<{ valid: boolean; error?: string }> {
    try {
      validateChallenge(request.challenge);
      if (request.envelope.version !== SWIYU_SPLIT_PROOF_ENVELOPE_VERSION) {
        throw new Error("split proof envelope version is unsupported");
      }
      assertSameDescriptor(request.envelope, request.challenge);
      const expectedPrepare = copyPublicValues(request.expectedPreparePublicValues);
      const expectedShow = copyPublicValues(request.expectedShowPublicValues);
      const [prepare, show] = await Promise.all([
        this.backend.verifyProof({
          circuitId: request.challenge.prepareCircuitId,
          proof: decodeBase64urlStrict(request.envelope.prepareProof, "Prepare proof"),
          verifyingKey: request.prepareVerifyingKey,
          expectedPublicValues: expectedPrepare,
        }),
        this.backend.verifyProof({
          circuitId: request.challenge.showCircuitId,
          proof: decodeBase64urlStrict(request.envelope.showProof, "Show proof"),
          verifyingKey: request.showVerifyingKey,
          expectedPublicValues: expectedShow,
        }),
      ]);
      if (!prepare.valid) throw new Error(prepare.error ?? "Prepare proof verification failed");
      if (!show.valid) throw new Error(show.error ?? "Show proof verification failed");
      assertPublicValues(prepare.publicValues, expectedPrepare, "Prepare");
      assertPublicValues(show.publicValues, expectedShow, "Show");
      validateCommitment(prepare.sharedCommitment, "Prepare");
      validateCommitment(show.sharedCommitment, "Show");
      if (!equalBytes(prepare.sharedCommitment, show.sharedCommitment)) {
        throw new Error("verified Prepare and Show proofs have different shared commitments");
      }
      return { valid: true };
    } catch (error) {
      return { valid: false, error: error instanceof Error ? error.message : String(error) };
    }
  }
}

function validateDescriptor(descriptor: SwiyuSplitProfileDescriptor) {
  for (const [label, value] of [
    ["profile", descriptor.profile],
    ["Prepare circuit id", descriptor.prepareCircuitId],
    ["Show circuit id", descriptor.showCircuitId],
  ] as const) {
    if (value.length === 0 || value.length > 128) throw new Error(`${label} is invalid`);
  }
  if (descriptor.prepareCircuitId === descriptor.showCircuitId) {
    throw new Error("Prepare and Show circuit ids must be distinct");
  }
}

function validateChallenge(challenge: SwiyuSplitChallenge) {
  validateDescriptor(challenge);
  assertFieldElement(challenge.challengeHash, "challengeHash");
  if (challenge.currentTime < 0n || challenge.currentTime >= 1n << 64n) {
    throw new Error("currentTime must fit in an unsigned 64-bit integer");
  }
}

function assertSameDescriptor(left: SwiyuSplitProfileDescriptor, right: SwiyuSplitProfileDescriptor) {
  if (
    left.profile !== right.profile ||
    left.prepareCircuitId !== right.prepareCircuitId ||
    left.showCircuitId !== right.showCircuitId
  ) throw new Error("split proof profile or circuit ids do not match the challenge");
}

function validateWitness(witness: Uint8Array, label: string) {
  if (!(witness instanceof Uint8Array) || witness.length === 0) {
    throw new Error(`${label} must be a non-empty Uint8Array`);
  }
}

function validateProofPart(part: SwiyuSplitProofPart, label: string) {
  if (!(part.proof instanceof Uint8Array) || part.proof.length === 0) {
    throw new Error(`${label} proof is empty or invalid`);
  }
  validateCommitment(part.sharedCommitment, label);
}

function validateCommitment(commitment: Uint8Array, label: string) {
  if (!(commitment instanceof Uint8Array) || commitment.length === 0) {
    throw new Error(`${label} shared commitment is empty or invalid`);
  }
}

function copyPublicValues(values: readonly Uint8Array[]): Uint8Array[] {
  if (!Array.isArray(values) || values.length === 0) {
    throw new Error("expected public values must be a non-empty array");
  }
  return values.map((value, index) => {
    if (!(value instanceof Uint8Array) || value.length !== 32) {
      throw new Error(`public value ${index} must contain exactly 32 bytes`);
    }
    return new Uint8Array(value);
  });
}

function assertPublicValues(
  actual: readonly Uint8Array[],
  expected: readonly Uint8Array[],
  label: string,
) {
  if (actual.length !== expected.length) {
    throw new Error(`${label} proof returned the wrong public-value count`);
  }
  for (let index = 0; index < expected.length; index++) {
    if (!equalBytes(actual[index]!, expected[index]!)) {
      throw new Error(`${label} proof public value ${index} does not match verifier context`);
    }
  }
}

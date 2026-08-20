import { describe, expect, it } from "vitest";
import {
  InMemorySwiyuNullifierRegistry,
  SWIYU_AGE18_STATUS_PROFILE,
  SwiyuNullifierAge18Verifier,
  SwiyuNullifierAge18Wallet,
  SwiyuSplitZkpVerifier,
  SwiyuSplitZkpWallet,
  buildSwiyuNullifierAge18Authorization,
  swiyuNullifierAge18ShowPublicValues,
  type SwiyuNullifierAge18VerifierPolicy,
  type SwiyuNullifierRegistry,
  type SwiyuSpentNullifier,
  type SwiyuSplitProofBackend,
} from "../../src/swiyu-zkp/index.js";
import { concatBytes, equalBytes } from "../../src/swiyu-zkp/encoding.js";
import {
  computeSwiyuPreparedStatusCommitment,
  computeSwiyuPreparedStatusUriCommitment,
} from "../../src/swiyu-zkp/commitments.js";

const lookup = {
  issuer: "did:example:issuer",
  kid: "did:example:issuer#key-1",
  vct: "https://example.ch/vct/person",
};
const policy: SwiyuNullifierAge18VerifierPolicy = {
  baseChallenge: {
    nonce: "nonce-1",
    clientId: "x509_san_dns:verifier.example.ch",
    responseUri: "https://verifier.example.ch/callback",
    state: "state-1",
    queryId: "query-1",
    profile: SWIYU_AGE18_STATUS_PROFILE,
    cutoffDate: "2007-08-17",
    currentTime: 1_755_388_800n,
    statusListSnapshot: "status-snapshot-1",
  },
  scope: {
    registryNamespace: "swiyu-benefit-claims",
    verifierOrigin: "x509_san_dns:verifier.example.ch",
    program: "age-gated-campaign-redemption",
    claimType: "one-redemption-per-credential",
    epoch: 202603n,
    eligibilityPolicy: "age-over-18-valid-status",
  },
  acceptedLookup: lookup,
  authoritativeStatusCommitment: computeSwiyuPreparedStatusCommitment(
    computeSwiyuPreparedStatusUriCommitment("https://status.example.ch/list/1"),
    "00".repeat(32),
  ),
};

describe("integrated age and credential-scoped nullifier adapter", () => {
  it("binds all scope dimensions into holder authorization", () => {
    const original = buildSwiyuNullifierAge18Authorization(policy);
    const changed = buildSwiyuNullifierAge18Authorization({
      ...policy,
      scope: { ...policy.scope, epoch: policy.scope.epoch + 1n },
    });
    expect(changed.digest).not.toEqual(original.digest);
    expect(changed.scopeDigest).not.toEqual(original.scopeDigest);
  });

  it("verifies before one atomic claim and rejects replay", async () => {
    const events: string[] = [];
    const backend = new BindingBackend(events);
    const registry = new TracingRegistry(events);
    const wallet = new SwiyuNullifierAge18Wallet(new SwiyuSplitZkpWallet(backend));
    const verifier = new SwiyuNullifierAge18Verifier(
      new SwiyuSplitZkpVerifier(backend),
      registry,
      () => new Date("2026-08-17T00:00:00Z"),
    );
    const nullifier = new Uint8Array(32).fill(0x45);
    const prepared = await wallet.prepare({
      lookup,
      issuerPubKeyX: 1n,
      issuerPubKeyY: 2n,
      prepareWitness: publicWitness([1n, 2n]),
      prepareProvingKey: new Uint8Array([1]),
    });
    const envelope = await wallet.show({
      prepared,
      policy,
      nullifier,
      showWitness: concatBytes(swiyuNullifierAge18ShowPublicValues(policy, nullifier)),
      showProvingKey: new Uint8Array([2]),
    });
    const request = {
      envelope,
      policy,
      issuerPubKeyX: 1n,
      issuerPubKeyY: 2n,
      prepareVerifyingKey: new Uint8Array([3]),
      showVerifyingKey: new Uint8Array([4]),
    };
    await expect(verifier.verifyAndClaim(request)).resolves.toEqual({
      valid: true,
      accepted: true,
    });
    const firstClaim = events.indexOf("registry:insertVerifiedClaim");
    expect(firstClaim).toBeGreaterThan(events.indexOf("proof:verify:prepare"));
    expect(firstClaim).toBeGreaterThan(events.indexOf("proof:verify:show"));
    await expect(verifier.verifyAndClaim(request)).resolves.toEqual({
      valid: true,
      accepted: false,
      error: "scoped nullifier was already consumed",
    });
    expect(registry.size).toBe(1);
  });

  it("does not mutate state when scope or proof context is wrong", async () => {
    const events: string[] = [];
    const backend = new BindingBackend(events);
    const registry = new TracingRegistry(events);
    const wallet = new SwiyuNullifierAge18Wallet(new SwiyuSplitZkpWallet(backend));
    const verifier = new SwiyuNullifierAge18Verifier(
      new SwiyuSplitZkpVerifier(backend),
      registry,
    );
    const nullifier = new Uint8Array(32).fill(0x45);
    const prepared = await wallet.prepare({
      lookup,
      issuerPubKeyX: 1n,
      issuerPubKeyY: 2n,
      prepareWitness: publicWitness([1n, 2n]),
      prepareProvingKey: new Uint8Array([1]),
    });
    const envelope = await wallet.show({
      prepared,
      policy,
      nullifier,
      showWitness: concatBytes(swiyuNullifierAge18ShowPublicValues(policy, nullifier)),
      showProvingKey: new Uint8Array([2]),
    });
    const changedPolicy = {
      ...policy,
      scope: { ...policy.scope, program: "different-program" },
    };
    const result = await verifier.verifyAndClaim({
      envelope,
      policy: changedPolicy,
      issuerPubKeyX: 1n,
      issuerPubKeyY: 2n,
      prepareVerifyingKey: new Uint8Array([3]),
      showVerifyingKey: new Uint8Array([4]),
    });
    expect(result.valid).toBe(false);
    expect(registry.size).toBe(0);
    expect(events).toContain("proof:verify:prepare");
    expect(events).toContain("proof:verify:show");
    expect(events).not.toContain("registry:insertVerifiedClaim");
  });
});

class BindingBackend implements SwiyuSplitProofBackend {
  constructor(private readonly events?: string[]) {}

  async prepare(request: { witness: Uint8Array }) {
    const publicValues = splitScalars(request.witness, 2);
    return { handle: { publicValues }, publicValues };
  }

  async proveLinked(request: { preparedHandle: unknown; showWitness: Uint8Array }) {
    const prepare = (request.preparedHandle as { publicValues: Uint8Array[] }).publicValues;
    const show = splitScalars(request.showWitness, 11);
    const commitment = new Uint8Array(32).fill(0xa5);
    return {
      prepare: proofPart(prepare, commitment),
      show: proofPart(show, commitment),
    };
  }

  async verifyProof(request: {
    circuitId: string;
    proof: Uint8Array;
    expectedPublicValues: readonly Uint8Array[];
  }) {
    this.events?.push(request.circuitId.includes("prepare")
      ? "proof:verify:prepare"
      : "proof:verify:show");
    const count = request.expectedPublicValues.length;
    const publicValues = splitScalars(request.proof, count);
    const sharedCommitment = request.proof.slice(count * 32);
    const valid = request.proof.length === (count + 1) * 32
      && publicValues.every((value, index) =>
        equalBytes(value, request.expectedPublicValues[index]!));
    return { valid, publicValues, sharedCommitment };
  }
}

class TracingRegistry implements SwiyuNullifierRegistry {
  readonly #inner = new InMemorySwiyuNullifierRegistry();

  constructor(private readonly events: string[]) {}

  insertVerifiedClaim(claim: Readonly<SwiyuSpentNullifier>): Promise<boolean> {
    this.events.push("registry:insertVerifiedClaim");
    return this.#inner.insertVerifiedClaim(claim);
  }

  get size(): number {
    return this.#inner.size;
  }
}

function proofPart(publicValues: Uint8Array[], commitment: Uint8Array) {
  return {
    proof: concatBytes([...publicValues, commitment]),
    publicValues,
    sharedCommitment: commitment,
  };
}

function publicWitness(values: readonly bigint[]): Uint8Array {
  return concatBytes(values.map(littleEndian32));
}

function splitScalars(bytes: Uint8Array, count: number): Uint8Array[] {
  return Array.from({ length: count }, (_, index) =>
    bytes.slice(index * 32, (index + 1) * 32));
}

function littleEndian32(value: bigint): Uint8Array {
  const output = new Uint8Array(32);
  let remaining = value;
  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

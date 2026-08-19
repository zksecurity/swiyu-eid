import { describe, expect, it } from "vitest";
import {
  SwiyuCantonEligibilityVerifier,
  SwiyuCantonEligibilityWallet,
  SwiyuSplitZkpVerifier,
  SwiyuSplitZkpWallet,
  swiyuCantonShowPublicValues,
  type SwiyuCantonVerifierPolicy,
  type SwiyuSplitProofBackend,
} from "../../src/swiyu-zkp/index.js";
import { concatBytes, equalBytes } from "../../src/swiyu-zkp/encoding.js";
import { base64urlEncode, base64Decode } from "../../src/utils.js";

const lookup = {
  issuer: "did:example:issuer",
  kid: "did:example:issuer#key-1",
  vct: "https://example.ch/vct/residence",
};
const policy: SwiyuCantonVerifierPolicy = {
  challengeHash: 7n,
  currentTime: 1_750_000_000n,
  acceptedLookup: lookup,
  authoritativeStatusUri: "https://status.example.ch/list/1",
  statusSnapshotRoot: "00".repeat(32),
  allowedCantons: ["ZH", "BE"],
};

describe("profile-agnostic linked Prepare/Show SDK with canton adapter", () => {
  it("creates and verifies a two-proof envelope through the backend boundary", async () => {
    const backend = new BindingSplitBackend();
    const wallet = new SwiyuCantonEligibilityWallet(new SwiyuSplitZkpWallet(backend));
    const verifier = new SwiyuCantonEligibilityVerifier(new SwiyuSplitZkpVerifier(backend));
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
      showWitness: publicWitness(cantonShowScalars(policy)),
      showProvingKey: new Uint8Array([2]),
    });
    expect(envelope.prepareProof).not.toBe(envelope.showProof);
    await expect(verifier.verify({
      envelope,
      policy,
      issuerPubKeyX: 1n,
      issuerPubKeyY: 2n,
      prepareVerifyingKey: new Uint8Array([3]),
      showVerifyingKey: new Uint8Array([4]),
    })).resolves.toEqual({ valid: true });
  });

  it("rejects a verifier policy or lookup that differs from the proven context", async () => {
    const backend = new BindingSplitBackend();
    const wallet = new SwiyuCantonEligibilityWallet(new SwiyuSplitZkpWallet(backend));
    const verifier = new SwiyuCantonEligibilityVerifier(new SwiyuSplitZkpVerifier(backend));
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
      showWitness: publicWitness(cantonShowScalars(policy)),
      showProvingKey: new Uint8Array([2]),
    });
    const result = await verifier.verify({
      envelope,
      policy: { ...policy, allowedCantons: ["GE"] },
      issuerPubKeyX: 1n,
      issuerPubKeyY: 2n,
      prepareVerifyingKey: new Uint8Array([3]),
      showVerifyingKey: new Uint8Array([4]),
    });
    expect(result.valid).toBe(false);
    const wrongIssuer = await verifier.verify({
      envelope,
      policy,
      issuerPubKeyX: 9n,
      issuerPubKeyY: 2n,
      prepareVerifyingKey: new Uint8Array([3]),
      showVerifyingKey: new Uint8Array([4]),
    });
    expect(wrongIssuer.valid).toBe(false);

    await expect(wallet.show({
      prepared,
      policy: {
        ...policy,
        acceptedLookup: { ...lookup, vct: "https://example.ch/vct/untrusted" },
      },
      showWitness: publicWitness(cantonShowScalars(policy)),
      showProvingKey: new Uint8Array([2]),
    })).rejects.toThrow("not accepted");
  });

  it("rejects independently valid proof halves with unequal shared commitments", async () => {
    const backend = new BindingSplitBackend(true);
    const wallet = new SwiyuCantonEligibilityWallet(new SwiyuSplitZkpWallet(backend));
    const prepared = await wallet.prepare({
      lookup,
      issuerPubKeyX: 1n,
      issuerPubKeyY: 2n,
      prepareWitness: publicWitness([1n, 2n]),
      prepareProvingKey: new Uint8Array([1]),
    });
    await expect(wallet.show({
      prepared,
      policy,
      showWitness: publicWitness(cantonShowScalars(policy)),
      showProvingKey: new Uint8Array([2]),
    })).rejects.toThrow("not linked");
  });

  it("does not pass a backend-private prepared handle to another wallet", async () => {
    const firstWallet = new SwiyuCantonEligibilityWallet(
      new SwiyuSplitZkpWallet(new BindingSplitBackend()),
    );
    const secondWallet = new SwiyuCantonEligibilityWallet(
      new SwiyuSplitZkpWallet(new BindingSplitBackend()),
    );
    const prepared = await firstWallet.prepare({
      lookup,
      issuerPubKeyX: 1n,
      issuerPubKeyY: 2n,
      prepareWitness: publicWitness([1n, 2n]),
      prepareProvingKey: new Uint8Array([1]),
    });
    await expect(secondWallet.show({
      prepared,
      policy,
      showWitness: publicWitness(cantonShowScalars(policy)),
      showProvingKey: new Uint8Array([2]),
    })).rejects.toThrow("not created by this split wallet");
  });

  it("rejects an envelope relabelled with a different circuit id", async () => {
    const backend = new BindingSplitBackend();
    const wallet = new SwiyuCantonEligibilityWallet(new SwiyuSplitZkpWallet(backend));
    const verifier = new SwiyuCantonEligibilityVerifier(new SwiyuSplitZkpVerifier(backend));
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
      showWitness: publicWitness(cantonShowScalars(policy)),
      showProvingKey: new Uint8Array([2]),
    });
    const result = await verifier.verify({
      envelope: { ...envelope, showCircuitId: "swiyu_other_show" } as typeof envelope,
      policy,
      issuerPubKeyX: 1n,
      issuerPubKeyY: 2n,
      prepareVerifyingKey: new Uint8Array([3]),
      showVerifyingKey: new Uint8Array([4]),
    });
    expect(result).toEqual({
      valid: false,
      error: "split proof profile or circuit ids do not match the challenge",
    });
  });

  it("verifier rejects two individually valid proofs with different embedded commitments", async () => {
    const backend = new BindingSplitBackend();
    const wallet = new SwiyuCantonEligibilityWallet(new SwiyuSplitZkpWallet(backend));
    const verifier = new SwiyuCantonEligibilityVerifier(new SwiyuSplitZkpVerifier(backend));
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
      showWitness: publicWitness(cantonShowScalars(policy)),
      showProvingKey: new Uint8Array([2]),
    });
    const unlinkedShow = base64Decode(envelope.showProof);
    unlinkedShow.fill(0x5a, unlinkedShow.length - 32);
    const result = await verifier.verify({
      envelope: { ...envelope, showProof: base64urlEncode(unlinkedShow) },
      policy,
      issuerPubKeyX: 1n,
      issuerPubKeyY: 2n,
      prepareVerifyingKey: new Uint8Array([3]),
      showVerifyingKey: new Uint8Array([4]),
    });
    expect(result).toEqual({
      valid: false,
      error: "verified Prepare and Show proofs have different shared commitments",
    });
  });
});

class BindingSplitBackend implements SwiyuSplitProofBackend {
  constructor(private readonly unlink = false) {}

  async prepare(request: { witness: Uint8Array }) {
    return {
      handle: { publicValues: splitScalars(request.witness, 2) },
      publicValues: splitScalars(request.witness, 2),
    };
  }

  async proveLinked(request: { preparedHandle: unknown; showWitness: Uint8Array }) {
    const preparePublic = (request.preparedHandle as { publicValues: Uint8Array[] }).publicValues;
    const showPublic = splitScalars(request.showWitness, 11);
    const prepareCommitment = new Uint8Array(32).fill(0xa5);
    const showCommitment = new Uint8Array(32).fill(this.unlink ? 0x5a : 0xa5);
    return {
      prepare: proofPart(preparePublic, prepareCommitment),
      show: proofPart(showPublic, showCommitment),
    };
  }

  async verifyProof(request: {
    proof: Uint8Array;
    expectedPublicValues: readonly Uint8Array[];
  }) {
    const publicBytes = request.expectedPublicValues.length * 32;
    const publicValues = splitScalars(request.proof.slice(0, publicBytes), request.expectedPublicValues.length);
    const sharedCommitment = request.proof.slice(publicBytes);
    const valid = request.proof.length === publicBytes + 32 &&
      publicValues.every((value, index) => equalBytes(value, request.expectedPublicValues[index]!));
    return { valid, publicValues, sharedCommitment, error: valid ? undefined : "public context mismatch" };
  }
}

function proofPart(publicValues: Uint8Array[], sharedCommitment: Uint8Array) {
  return {
    proof: concatBytes([...publicValues, sharedCommitment]),
    publicValues,
    sharedCommitment,
  };
}

function publicWitness(values: readonly bigint[]) {
  return concatBytes(values.map(littleEndian32));
}

function splitScalars(bytes: Uint8Array, count: number): Uint8Array[] {
  return Array.from({ length: count }, (_, index) =>
    bytes.slice(index * 32, (index + 1) * 32));
}

function littleEndian32(value: bigint) {
  const bytes = new Uint8Array(32);
  let remaining = value;
  for (let index = 0; index < 32; index++) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

function cantonShowScalars(value: SwiyuCantonVerifierPolicy): bigint[] {
  // The adapter is the source of truth. Convert its public bytes back into the
  // raw witness prefix expected by this deliberately tiny binding backend.
  return swiyuCantonShowPublicValues(value).map(littleEndianToBigint);
}

function littleEndianToBigint(bytes: Uint8Array) {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index--) {
    value = (value << 8n) | BigInt(bytes[index]!);
  }
  return value;
}

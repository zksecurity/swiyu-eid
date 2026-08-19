import { describe, expect, it } from "vitest";
import {
  SWIYU_PROFESSIONAL_LICENSE_VCT,
  SwiyuProfessionalLicenseVerifier,
  SwiyuProfessionalLicenseWallet,
  SwiyuSplitZkpVerifier,
  SwiyuSplitZkpWallet,
  swiyuProfessionalLicenseShowPublicValues,
  type SwiyuProfessionalLicenseVerifierPolicy,
  type SwiyuSplitProofBackend,
} from "../../src/swiyu-zkp/index.js";
import { concatBytes, equalBytes } from "../../src/swiyu-zkp/encoding.js";
import { base64Decode, base64urlEncode } from "../../src/utils.js";

const lookup = {
  issuer: "did:example:licen",
  kid: "did:example:issuer#key-1",
  vct: SWIYU_PROFESSIONAL_LICENSE_VCT,
};
const policy: SwiyuProfessionalLicenseVerifierPolicy = {
  challengeHash: 7n,
  currentTime: 1_750_000_000n,
  requiredValidUntil: 1_760_000_000n,
  acceptedLookup: lookup,
  authoritativeStatusUri: "https://status.example.ch/list/1",
  statusSnapshotRoot: "00".repeat(32),
};

describe("professional-licence linked Prepare/Show adapter", () => {
  it("creates and verifies an envelope bound to VCT, horizon, and status", async () => {
    const backend = new BindingBackend();
    const wallet = new SwiyuProfessionalLicenseWallet(new SwiyuSplitZkpWallet(backend));
    const verifier = new SwiyuProfessionalLicenseVerifier(new SwiyuSplitZkpVerifier(backend));
    const prepared = await wallet.prepare({
      lookup, issuerPubKeyX: 1n, issuerPubKeyY: 2n,
      prepareWitness: publicWitness([1n, 2n]), prepareProvingKey: new Uint8Array([1]),
    });
    const envelope = await wallet.show({
      prepared, policy,
      showWitness: publicWitness(showScalars(policy)), showProvingKey: new Uint8Array([2]),
    });
    await expect(verifier.verify({
      envelope, policy, issuerPubKeyX: 1n, issuerPubKeyY: 2n,
      prepareVerifyingKey: new Uint8Array([3]), showVerifyingKey: new Uint8Array([4]),
    })).resolves.toEqual({ valid: true });
  });

  it("rejects a changed horizon or unaccepted credential VCT", async () => {
    const backend = new BindingBackend();
    const wallet = new SwiyuProfessionalLicenseWallet(new SwiyuSplitZkpWallet(backend));
    const verifier = new SwiyuProfessionalLicenseVerifier(new SwiyuSplitZkpVerifier(backend));
    const prepared = await wallet.prepare({
      lookup, issuerPubKeyX: 1n, issuerPubKeyY: 2n,
      prepareWitness: publicWitness([1n, 2n]), prepareProvingKey: new Uint8Array([1]),
    });
    const envelope = await wallet.show({
      prepared, policy, showWitness: publicWitness(showScalars(policy)),
      showProvingKey: new Uint8Array([2]),
    });
    const changed = await verifier.verify({
      envelope, policy: { ...policy, requiredValidUntil: 1_770_000_000n },
      issuerPubKeyX: 1n, issuerPubKeyY: 2n,
      prepareVerifyingKey: new Uint8Array([3]), showVerifyingKey: new Uint8Array([4]),
    });
    expect(changed.valid).toBe(false);
    expect(() => wallet.prepare({
      lookup: { ...lookup, vct: "urn:ch:person:v1" },
      issuerPubKeyX: 1n, issuerPubKeyY: 2n,
      prepareWitness: new Uint8Array([1]), prepareProvingKey: new Uint8Array([1]),
    })).toThrow(/VCT is not accepted/);
  });

  it("rejects independently valid halves with unequal embedded commitments", async () => {
    const backend = new BindingBackend(true);
    const wallet = new SwiyuProfessionalLicenseWallet(new SwiyuSplitZkpWallet(backend));
    const prepared = await wallet.prepare({
      lookup, issuerPubKeyX: 1n, issuerPubKeyY: 2n,
      prepareWitness: publicWitness([1n, 2n]), prepareProvingKey: new Uint8Array([1]),
    });
    await expect(wallet.show({
      prepared, policy, showWitness: publicWitness(showScalars(policy)),
      showProvingKey: new Uint8Array([2]),
    })).rejects.toThrow(/not linked/);
  });

  it("verifier rejects two individually valid proofs with different embedded commitments", async () => {
    const backend = new BindingBackend();
    const wallet = new SwiyuProfessionalLicenseWallet(new SwiyuSplitZkpWallet(backend));
    const verifier = new SwiyuProfessionalLicenseVerifier(new SwiyuSplitZkpVerifier(backend));
    const prepared = await wallet.prepare({
      lookup, issuerPubKeyX: 1n, issuerPubKeyY: 2n,
      prepareWitness: publicWitness([1n, 2n]), prepareProvingKey: new Uint8Array([1]),
    });
    const envelope = await wallet.show({
      prepared, policy, showWitness: publicWitness(showScalars(policy)),
      showProvingKey: new Uint8Array([2]),
    });
    const unlinkedShow = base64Decode(envelope.showProof);
    unlinkedShow.fill(0x5a, unlinkedShow.length - 32);
    const result = await verifier.verify({
      envelope: { ...envelope, showProof: base64urlEncode(unlinkedShow) },
      policy, issuerPubKeyX: 1n, issuerPubKeyY: 2n,
      prepareVerifyingKey: new Uint8Array([3]), showVerifyingKey: new Uint8Array([4]),
    });
    expect(result).toEqual({
      valid: false,
      error: "verified Prepare and Show proofs have different shared commitments",
    });
  });
});

class BindingBackend implements SwiyuSplitProofBackend {
  constructor(private readonly unlink = false) {}
  async prepare(request: { witness: Uint8Array }) {
    const publicValues = split(request.witness, 2);
    return { handle: { publicValues }, publicValues };
  }
  async proveLinked(request: { preparedHandle: unknown; showWitness: Uint8Array }) {
    const preparePublic = (request.preparedHandle as { publicValues: Uint8Array[] }).publicValues;
    const showPublic = split(request.showWitness, 7);
    const prepareCommitment = new Uint8Array(32).fill(0xa5);
    const showCommitment = new Uint8Array(32).fill(this.unlink ? 0x5a : 0xa5);
    return {
      prepare: part(preparePublic, prepareCommitment),
      show: part(showPublic, showCommitment),
    };
  }
  async verifyProof(request: { proof: Uint8Array; expectedPublicValues: readonly Uint8Array[] }) {
    const count = request.expectedPublicValues.length;
    const publicValues = split(request.proof, count);
    const sharedCommitment = request.proof.slice(count * 32);
    const valid = request.proof.length === (count + 1) * 32 &&
      publicValues.every((value, index) => equalBytes(value, request.expectedPublicValues[index]!));
    return { valid, publicValues, sharedCommitment };
  }
}

function part(publicValues: Uint8Array[], sharedCommitment: Uint8Array) {
  return { proof: concatBytes([...publicValues, sharedCommitment]), publicValues, sharedCommitment };
}
function publicWitness(values: readonly bigint[]) { return concatBytes(values.map(le32)); }
function split(bytes: Uint8Array, count: number) {
  return Array.from({ length: count }, (_, index) => bytes.slice(index * 32, (index + 1) * 32));
}
function le32(value: bigint) {
  const bytes = new Uint8Array(32);
  for (let index = 0; index < 32; index++) { bytes[index] = Number(value & 255n); value >>= 8n; }
  return bytes;
}
function showScalars(value: SwiyuProfessionalLicenseVerifierPolicy) {
  return swiyuProfessionalLicenseShowPublicValues(value).map((bytes) => {
    let result = 0n;
    for (let index = 31; index >= 0; index--) result = (result << 8n) | BigInt(bytes[index]!);
    return result;
  });
}

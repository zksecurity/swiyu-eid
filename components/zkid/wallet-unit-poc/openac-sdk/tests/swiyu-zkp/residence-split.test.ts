import { deflateSync, inflateSync } from "node:zlib";
import { describe, expect, it } from "vitest";

import {
  SWIYU_BENCHMARK_RESIDENCE,
} from "../../src/swiyu-zkp/residence-benchmark-manifest.js";
import { computeSwiyuBenchmarkResidenceChallengeHash } from "../../src/swiyu-zkp/residence-benchmark-challenge.js";
import {
  SwiyuResidenceEligibilityVerifier,
  SwiyuResidenceEligibilityWallet,
  buildSwiyuResidenceChallenge,
  swiyuResidenceShowPublicValues,
  type SwiyuResidenceVerifierPolicy,
} from "../../src/swiyu-zkp/residence-split.js";
import { resolveSwiyuPackedStatusListJwt } from "../../src/swiyu-zkp/residence-status.js";
import {
  SwiyuSplitZkpVerifier,
  SwiyuSplitZkpWallet,
  type SwiyuSplitProofBackend,
} from "../../src/swiyu-zkp/split-proof.js";
import { hashSwiyuChallenge } from "../../src/swiyu-zkp/challenge.js";
import { concatBytes, equalBytes } from "../../src/swiyu-zkp/encoding.js";
import { base64urlEncode } from "../../src/utils.js";
import {
  CHECKED_IN_DID_TDW_KID,
  ISSUER_PRIVATE_KEY,
  makeChallenge,
  publicJwk,
  signJwt,
} from "./fixture.js";

const lookup = {
  issuer: "did:example:issuer",
  kid: CHECKED_IN_DID_TDW_KID,
  vct: SWIYU_BENCHMARK_RESIDENCE.vct,
};

describe("combined-disclosure residence Prepare/Show adapter", () => {
  it("uses the benchmark's directory-domain-separated holder challenge end to end", async () => {
    const challenge = makeChallenge();
    const baseChallengeHash = hashSwiyuChallenge(challenge).scalar;
    const policy = residencePolicy(baseChallengeHash, challenge.currentTime);
    const expectedChallengeHash = computeSwiyuBenchmarkResidenceChallengeHash(
      baseChallengeHash,
    );
    expect(buildSwiyuResidenceChallenge(policy).challengeHash)
      .toBe(expectedChallengeHash);
    expect(expectedChallengeHash).not.toBe(baseChallengeHash);

    const backend = new BindingBackend();
    const wallet = new SwiyuResidenceEligibilityWallet(
      new SwiyuSplitZkpWallet(backend),
    );
    const verifier = new SwiyuResidenceEligibilityVerifier(
      new SwiyuSplitZkpVerifier(backend),
    );
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
      showWitness: concatBytes(swiyuResidenceShowPublicValues(policy)),
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
    await expect(verifier.verify(request)).resolves.toEqual({ valid: true });

    await expect(verifier.verify({
      ...request,
      policy: {
        ...policy,
        municipalityDirectorySha256: "22".repeat(32),
      },
    })).resolves.toMatchObject({ valid: false });
  });
});

function residencePolicy(
  baseChallengeHash: bigint,
  currentTime: bigint,
): SwiyuResidenceVerifierPolicy {
  const iat = Number(currentTime - 30n);
  const subject = "https://status.example.ch/lists/2026-07";
  const compactJwt = signJwt(
    JSON.stringify({
      alg: "ES256",
      kid: CHECKED_IN_DID_TDW_KID,
      typ: "statuslist+jwt",
      profile_version: "swiss-profile-vc:1.0.0",
    }),
    JSON.stringify({
      iss: lookup.issuer,
      sub: subject,
      iat,
      exp: iat + 600,
      ttl: 300,
      status_list: {
        bits: 2,
        lst: base64urlEncode(new Uint8Array(deflateSync(new Uint8Array(16)))),
      },
    }),
  );
  const resolved = resolveSwiyuPackedStatusListJwt({
    compactJwt,
    issuerPublicKey: publicJwk(ISSUER_PRIVATE_KEY, CHECKED_IN_DID_TDW_KID),
    expectedIssuer: lookup.issuer,
    expectedSubject: subject,
    credentialStatusIndex: 42,
    currentTime,
    inflateZlib(compressed, maxOutputBytes) {
      return new Uint8Array(
        inflateSync(compressed, { maxOutputLength: maxOutputBytes }),
      );
    },
  });
  return {
    baseChallengeHash,
    currentTime,
    acceptedLookup: lookup,
    trustedStatus: resolved.verifierStatus,
    ...SWIYU_BENCHMARK_RESIDENCE.policy,
  };
}

class BindingBackend implements SwiyuSplitProofBackend {
  async prepare(request: { witness: Uint8Array }) {
    const publicValues = split(request.witness, 2);
    return { handle: { publicValues }, publicValues };
  }

  async proveLinked(request: {
    preparedHandle: unknown;
    showWitness: Uint8Array;
  }) {
    const prepare = (request.preparedHandle as {
      publicValues: Uint8Array[];
    }).publicValues;
    const show = split(request.showWitness, 24);
    const commitment = new Uint8Array(32).fill(0xa5);
    return {
      prepare: proofPart(prepare, commitment),
      show: proofPart(show, commitment),
    };
  }

  async verifyProof(request: {
    proof: Uint8Array;
    expectedPublicValues: readonly Uint8Array[];
  }) {
    const count = request.expectedPublicValues.length;
    const publicValues = split(request.proof, count);
    const sharedCommitment = request.proof.slice(count * 32);
    const valid = request.proof.length === (count + 1) * 32
      && publicValues.every((value, index) =>
        equalBytes(value, request.expectedPublicValues[index]!));
    return { valid, publicValues, sharedCommitment };
  }
}

function proofPart(publicValues: Uint8Array[], sharedCommitment: Uint8Array) {
  return {
    proof: concatBytes([...publicValues, sharedCommitment]),
    publicValues,
    sharedCommitment,
  };
}

function publicWitness(values: readonly bigint[]): Uint8Array {
  return concatBytes(values.map(littleEndian32));
}

function split(bytes: Uint8Array, count: number): Uint8Array[] {
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

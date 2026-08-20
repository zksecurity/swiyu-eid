import { describe, expect, it } from "vitest";
import { mkdir, readFile, writeFile } from "fs/promises";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2";

import { SwiyuZkpWallet } from "../../src/swiyu-zkp/wallet.js";
import { parseSwiyuCompactSdJwt } from "../../src/swiyu-zkp/parser.js";
import { hashSwiyuChallenge } from "../../src/swiyu-zkp/challenge.js";
import { PackedStatusChunkTree } from "../../src/status-designs/packed-status-chunk-merkle.js";
import {
  SWIYU_BENCHMARK_AGE_PACKED_STATUS_V2,
  SWIYU_PACKED_STATUS_SHOW_PROFILES_V2,
} from "../../src/swiyu-zkp/status-benchmark-manifest.js";
import {
  computeSwiyuPreparedLookupCommitment,
  computeSwiyuPreparedSessionCommitment,
  computeSwiyuPreparedStatusCommitment,
  computeSwiyuPreparedStatusUriCommitment,
} from "../../src/swiyu-zkp/commitments.js";
import {
  buildSwiyuNullifierIssuerRecord,
  buildSwiyuNullifierShowWitness,
  computeSwiyuNullifierCredentialSeed,
  computeSwiyuNullifierChallengeHash,
  computeSwiyuNullifierScopeDigest,
  computeSwiyuNullifierSecretCommitment,
  hashSwiyuNullifierIdentifier,
  swiyuNullifierDigestLimbs,
} from "../../src/swiyu-zkp/nullifier.js";
import {
  SWIYU_BENCHMARK_NULLIFIER_CREDENTIAL_UID_HEX,
  SWIYU_BENCHMARK_NULLIFIER_HOLDER_SECRET_HEX,
  SWIYU_BENCHMARK_NULLIFIER_SCOPE_IDS,
} from "../../src/swiyu-zkp/nullifier-benchmark-manifest.js";
import {
  base64urlToBigInt,
  modInverse,
  P256_SCALAR_ORDER,
} from "../../src/utils.js";
import {
  BindingTestBackend,
  HOLDER_PRIVATE_KEY,
  ISSUER_PRIVATE_KEY,
  RecordingWitnessGenerator,
  buildCredentialFixture,
  holderSigner,
  makeChallenge,
  makeStatus,
} from "./fixture.js";

const enabled = process.env.SWIYU_NULLIFIER_BENCHMARK === "1";
const primaryPacked = process.env.SWIYU_PACKED_STATUS_PRIMARY === "1";
const fixedRuns = process.env.SWIYU_NULLIFIER_RUNS === undefined
  ? undefined
  : Number.parseInt(process.env.SWIYU_NULLIFIER_RUNS, 10);
const here = dirname(fileURLToPath(import.meta.url));
const circom = join(here, "..", "..", "..", "circom");
const output = join(circom, "build", "swiyu_nullifier_age18_benchmark");
const holderSecret = Uint8Array.from(Buffer.from(
  SWIYU_BENCHMARK_NULLIFIER_HOLDER_SECRET_HEX,
  "hex",
));
const credentialUid = Uint8Array.from(Buffer.from(
  SWIYU_BENCHMARK_NULLIFIER_CREDENTIAL_UID_HEX,
  "hex",
));

describe.skipIf(!enabled)("swiyu age + scoped-nullifier benchmark fixtures", () => {
  it("generates repeated linked witnesses and rejects altered public nullifiers", async () => {
    if (fixedRuns !== undefined && (!Number.isInteger(fixedRuns) || fixedRuns < 1)) {
      throw new Error("SWIYU_NULLIFIER_RUNS must be a positive integer");
    }
    const fixture = buildCredentialFixture({ swiyuIssuerShape: true });
    const parsed = parseSwiyuCompactSdJwt(
      fixture.compactSdJwt,
      fixture.issuerPublicKey,
    );
    const challenge = makeChallenge();
    const { snapshot, witness: statusWitness } = makeStatus();
    const recorder = new RecordingWitnessGenerator();
    const wallet = new SwiyuZkpWallet({
      witnessGenerator: recorder,
      proofBackend: new BindingTestBackend(recorder),
    });
    const prepared = wallet.prepare({
      compactSdJwt: fixture.compactSdJwt,
      issuerPublicKey: fixture.issuerPublicKey,
    });
    await wallet.show({
      prepared,
      challenge,
      holderSigner: holderSigner(HOLDER_PRIVATE_KEY),
      statusSnapshot: snapshot,
      statusWitness,
      provingKey: new Uint8Array([1]),
    });
    if (!recorder.inputs) throw new Error("fixture did not produce circuit inputs");

    const lookup = computeSwiyuPreparedLookupCommitment(parsed.lookup);
    const uri = computeSwiyuPreparedStatusUriCommitment(parsed.statusUri);
    const status = computeSwiyuPreparedStatusCommitment(uri, snapshot.root);
    let statusStarted = performance.now();
    const packedTree = PackedStatusChunkTree.buildSwiyuProfile(
      new Uint8Array(SWIYU_BENCHMARK_AGE_PACKED_STATUS_V2.listLength / 4),
      SWIYU_BENCHMARK_AGE_PACKED_STATUS_V2.epoch,
    );
    const packedV2TreeBuildMs = performance.now() - statusStarted;
    expect(packedTree.root).toBe(SWIYU_BENCHMARK_AGE_PACKED_STATUS_V2.snapshotRoot);
    statusStarted = performance.now();
    const packedStatusWitness = packedTree.witness(parsed.statusIndex);
    const packedV2PathGenerationMs = performance.now() - statusStarted;
    const packedStatus = computeSwiyuPreparedStatusCommitment(uri, packedTree.root);
    const sharedAgeRows = [
      base64urlToBigInt(parsed.holderPublicKey.x),
      base64urlToBigInt(parsed.holderPublicKey.y),
      parsed.birthdateNumeric,
      parsed.nbf,
      parsed.exp,
      parsed.statusIndex,
      lookup.hashHi,
      lookup.hashLo,
      uri.hashHi,
      uri.hashLo,
    ];
    const signingInput = fixture.jwt.slice(0, fixture.jwt.lastIndexOf("."));
    const credentialBindingHash = swiyuNullifierDigestLimbs(
      sha256(new TextEncoder().encode(signingInput)),
    );
    const secretCommitment = computeSwiyuNullifierSecretCommitment(holderSecret);
    const issuerRecord = buildSwiyuNullifierIssuerRecord({
      credentialUid,
      secretCommitment,
      credentialBindingHash,
    });
    const auxiliarySignature = p256.sign(sha256(issuerRecord), ISSUER_PRIVATE_KEY);
    const credentialSeed = computeSwiyuNullifierCredentialSeed({
      holderSecret,
      credentialUid,
      credentialBindingHash,
    });
    const scopeDigest = computeSwiyuNullifierScopeDigest({
      registryNamespaceId: hashSwiyuNullifierIdentifier(
        SWIYU_BENCHMARK_NULLIFIER_SCOPE_IDS.registryNamespace,
        "registry namespace",
      ),
      verifierOriginHash: hashSwiyuNullifierIdentifier(
        SWIYU_BENCHMARK_NULLIFIER_SCOPE_IDS.verifierOrigin,
        "verifier origin",
      ),
      programId: hashSwiyuNullifierIdentifier(
        SWIYU_BENCHMARK_NULLIFIER_SCOPE_IDS.program,
        "program",
      ),
      claimTypeId: hashSwiyuNullifierIdentifier(
        SWIYU_BENCHMARK_NULLIFIER_SCOPE_IDS.claimType,
        "claim type",
      ),
      epoch: SWIYU_BENCHMARK_NULLIFIER_SCOPE_IDS.epoch,
      eligibilityPolicyDigest: hashSwiyuNullifierIdentifier(
        SWIYU_BENCHMARK_NULLIFIER_SCOPE_IDS.eligibilityPolicy,
        "eligibility policy",
      ),
    });
    const nullifierChallenge = computeSwiyuNullifierChallengeHash(
      hashSwiyuChallenge(challenge).scalar,
      scopeDigest,
    );
    const challengeHash = nullifierChallenge.scalar;
    const session = computeSwiyuPreparedSessionCommitment(challengeHash, lookup);
    const holderSignature = p256.sign(nullifierChallenge.digest, HOLDER_PRIVATE_KEY);
    const nullifier = buildSwiyuNullifierShowWitness({ credentialSeed, scopeDigest });

    const prepareInputs = {
      ...recorder.inputs,
      message: recorder.inputs.message.slice(0, 896),
      nullifierIssuerSigR: auxiliarySignature.r,
      nullifierIssuerSigSInverse: modInverse(auxiliarySignature.s, P256_SCALAR_ORDER),
      nullifierHolderSecret: Array.from(holderSecret, BigInt),
      credentialUid: Array.from(credentialUid, BigInt),
      secretCommitment: Array.from(secretCommitment, BigInt),
    };
    const showInputs = {
      holderKeyX: sharedAgeRows[0],
      holderKeyY: sharedAgeRows[1],
      birthdateNumeric: sharedAgeRows[2],
      credentialNbf: sharedAgeRows[3],
      credentialExp: sharedAgeRows[4],
      statusIndex: sharedAgeRows[5],
      lookupHashHi: sharedAgeRows[6],
      lookupHashLo: sharedAgeRows[7],
      statusUriHashHi: sharedAgeRows[8],
      statusUriHashLo: sharedAgeRows[9],
      holderSigR: holderSignature.r,
      holderSigSInverse: modInverse(holderSignature.s, P256_SCALAR_ORDER),
      statusValue: recorder.inputs.statusValue,
      statusSiblings: recorder.inputs.statusSiblings,
      statusEpoch: recorder.inputs.statusEpoch,
      statusListLength: recorder.inputs.statusListLength,
      challengeHash,
      cutoffDate: recorder.inputs.cutoffDate,
      currentTime: recorder.inputs.currentTime,
      expectedMetadataHashHi: session.hashHi,
      expectedMetadataHashLo: session.hashLo,
      expectedStatusSnapshotHashHi: status.hashHi,
      expectedStatusSnapshotHashLo: status.hashLo,
      ...nullifier,
    };
    const packedShowInputs = {
      ...showInputs,
      statusChunk: packedStatusWitness.chunk.map(BigInt),
      statusSiblings: packedStatusWitness.siblings.map((pair) =>
        pair.map((hex) => Array.from(Buffer.from(hex, "hex"), BigInt))),
      statusEpoch: packedTree.epoch,
      statusListLength: packedTree.entryCount,
      expectedStatusSnapshotHashHi: packedStatus.hashHi,
      expectedStatusSnapshotHashLo: packedStatus.hashLo,
    };

    const prepareSamples: number[] = [];
    const showSamples: number[] = [];
    const packedShowSamples: number[] = [];
    let prepareWtns = new Uint8Array();
    let showWtns = new Uint8Array();
    let packedShowWtns = new Uint8Array();
    const initialRuns = fixedRuns ?? 2;
    for (let run = 0; run < initialRuns; run++) {
      let started = performance.now();
      prepareWtns = await calculate("swiyu_nullifier_age18_prepare", prepareInputs);
      prepareSamples.push(performance.now() - started);
      if (primaryPacked) {
        started = performance.now();
        packedShowWtns = await calculate(
          "swiyu_nullifier_age18_show_packed_chunk_v2",
          packedShowInputs,
        );
        packedShowSamples.push(performance.now() - started);
        started = performance.now();
        showWtns = await calculate("swiyu_nullifier_age18_show", showInputs);
        showSamples.push(performance.now() - started);
      } else {
        started = performance.now();
        showWtns = await calculate("swiyu_nullifier_age18_show", showInputs);
        showSamples.push(performance.now() - started);
        started = performance.now();
        packedShowWtns = await calculate(
          "swiyu_nullifier_age18_show_packed_chunk_v2",
          packedShowInputs,
        );
        packedShowSamples.push(performance.now() - started);
      }
    }
    const expanded = fixedRuns === undefined
      && (unstable(prepareSamples)
        || unstable(showSamples)
        || unstable(packedShowSamples));
    const repetitions = fixedRuns ?? (expanded ? 7 : 3);
    while (prepareSamples.length < repetitions) {
      let started = performance.now();
      prepareWtns = await calculate("swiyu_nullifier_age18_prepare", prepareInputs);
      prepareSamples.push(performance.now() - started);
      if (primaryPacked) {
        started = performance.now();
        packedShowWtns = await calculate(
          "swiyu_nullifier_age18_show_packed_chunk_v2",
          packedShowInputs,
        );
        packedShowSamples.push(performance.now() - started);
        started = performance.now();
        showWtns = await calculate("swiyu_nullifier_age18_show", showInputs);
        showSamples.push(performance.now() - started);
      } else {
        started = performance.now();
        showWtns = await calculate("swiyu_nullifier_age18_show", showInputs);
        showSamples.push(performance.now() - started);
        started = performance.now();
        packedShowWtns = await calculate(
          "swiyu_nullifier_age18_show_packed_chunk_v2",
          packedShowInputs,
        );
        packedShowSamples.push(performance.now() - started);
      }
    }

    const secondSeed = computeSwiyuNullifierCredentialSeed({
      holderSecret,
      credentialUid: new Uint8Array(32).fill(0x23),
      credentialBindingHash,
    });
    const unlinkedNullifier = buildSwiyuNullifierShowWitness({
      credentialSeed: secondSeed,
      scopeDigest,
    });
    const unlinkedShowWtns = await calculate("swiyu_nullifier_age18_show", {
      ...showInputs,
      ...unlinkedNullifier,
    });
    const unlinkedPackedShowWtns = await calculate(
      "swiyu_nullifier_age18_show_packed_chunk_v2",
      { ...packedShowInputs, ...unlinkedNullifier },
    );
    if (fixedRuns === undefined) {
      await expect(calculate("swiyu_nullifier_age18_show", {
        ...showInputs,
        expectedNullifierLo: nullifier.expectedNullifierLo + 1n,
      })).rejects.toThrow();
      await expect(calculate("swiyu_nullifier_age18_show", {
        ...showInputs,
        birthdateNumeric: 20100101n,
      })).rejects.toThrow();
    }

    await mkdir(output, { recursive: true });
    await Promise.all([
      writeFile(join(output, "prepare.wtns"), prepareWtns),
      writeFile(join(output, "show.wtns"), showWtns),
      writeFile(join(output, "show-packed-v2.wtns"), packedShowWtns),
      writeFile(join(output, "show-unlinked.wtns"), unlinkedShowWtns),
      writeFile(join(output, "show-unlinked-packed-v2.wtns"), unlinkedPackedShowWtns),
      writeFile(join(output, "witness-runs.json"), JSON.stringify({
        profile: "swiyu.age-over-18.scoped-nullifier.v1",
        predicate: "age over 18 and at most one accepted claim per credential/nullifier attestation and verifier scope",
        repetitions,
        expandedAfterFirstTwo: expanded,
        processPeakRssBytes: process.resourceUsage().maxRSS * 1024,
        policy: {
          sourceClaim: ["birthdate", "2000-02-29"],
          cutoffDate: challenge.cutoffDate,
          currentTime: Number(recorder.inputs.currentTime),
          acceptedLookup: parsed.lookup,
          profileVersion: "swiyu.age-over-18.scoped-nullifier.v1",
          epoch: SWIYU_BENCHMARK_NULLIFIER_SCOPE_IDS.epoch.toString(),
          statusRequired: "VALID (00)",
          packedStatusV2: SWIYU_BENCHMARK_AGE_PACKED_STATUS_V2,
          packedStatusShow: SWIYU_PACKED_STATUS_SHOW_PROFILES_V2.ageNullifier,
          statusSnapshot: {
            uri: parsed.statusUri,
            index: parsed.statusIndex,
            ...SWIYU_BENCHMARK_AGE_PACKED_STATUS_V2,
          },
          guarantee: "one claim per credential/nullifier attestation, not one person",
          scopeDigestHex: Buffer.from(scopeDigest).toString("hex"),
          scopeDigestBase64url: Buffer.from(scopeDigest).toString("base64url"),
          holderAuthorizedChallengeScalar: challengeHash.toString(),
        },
        witnessGenerationMs: {
          prepare: prepareSamples,
          show: showSamples,
          showPackedV2: packedShowSamples,
        },
        witnessGenerationStats: {
          prepare: stats(prepareSamples),
          show: stats(showSamples),
          showPackedV2: stats(packedShowSamples),
        },
        statusSnapshotStagesMs: {
          packedV2TreeBuild: [packedV2TreeBuildMs],
          packedV2PathGeneration: [packedV2PathGenerationMs],
        },
        witnessBytes: {
          prepare: prepareWtns.byteLength,
          show: showWtns.byteLength,
          showPackedV2: packedShowWtns.byteLength,
        },
      }, null, 2) + "\n"),
    ]);
    expect(prepareWtns.byteLength).toBeGreaterThan(1_000_000);
    expect(showWtns.byteLength).toBeGreaterThan(1_000_000);
    expect(packedShowWtns.byteLength).toBeGreaterThan(1_000_000);
  }, 30 * 60_000);
});

async function calculate(circuitName: string, inputs: Record<string, unknown>): Promise<Uint8Array> {
  // @ts-expect-error generated Circom module
  const imported = await import("../../assets/witness_calculator.js");
  const builder = imported.default ?? imported;
  const wasm = await readFile(
    join(circom, "build", circuitName, `${circuitName}_js`, `${circuitName}.wasm`),
  );
  const calculator = await builder(wasm, { sanityCheck: true });
  return calculator.calculateWTNSBin(inputs, true);
}

function unstable(values: number[]): boolean {
  if (values.length < 2) return false;
  const [first, second] = values;
  return Math.abs(first! - second!) / Math.max((first! + second!) / 2, 0.001) > 0.15;
}

function stats(values: number[]) {
  const ordered = [...values].sort((a, b) => a - b);
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  const variance = values.length > 1
    ? values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / (values.length - 1)
    : 0;
  const standardDeviation = Math.sqrt(variance);
  return {
    min: ordered[0], median: ordered[Math.floor(ordered.length / 2)], max: ordered.at(-1), mean,
    standardDeviation,
    coefficientOfVariation: mean === 0 ? 0 : standardDeviation / mean,
  };
}

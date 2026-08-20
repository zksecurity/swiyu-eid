import { describe, expect, it } from "vitest";
import { mkdir, readFile, writeFile } from "fs/promises";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { arch, cpus, platform, release, totalmem } from "os";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2";

import { SwiyuZkpWallet } from "../../src/swiyu-zkp/wallet.js";
import { parseSwiyuCompactSdJwt } from "../../src/swiyu-zkp/parser.js";
import { hashSwiyuChallenge } from "../../src/swiyu-zkp/challenge.js";
import { TernaryFixedIndexStatusTree } from "../../src/status-designs/ternary-fixed-index-merkle.js";
import { PackedStatusChunkTree } from "../../src/status-designs/packed-status-chunk-merkle.js";
import { packSwiyuResidence } from "../../src/swiyu-zkp/residence-eligibility.js";
import {
  SWIYU_BENCHMARK_RESIDENCE,
  SWIYU_BENCHMARK_RESIDENCE_STATUS,
} from "../../src/swiyu-zkp/residence-benchmark-manifest.js";
import { computeSwiyuBenchmarkResidenceChallengeHash } from "../../src/swiyu-zkp/residence-benchmark-challenge.js";
import { SWIYU_PACKED_STATUS_SHOW_PROFILES_V2 } from "../../src/swiyu-zkp/status-benchmark-manifest.js";
import {
  base64urlEncode,
  base64urlToBigInt,
  bigintToBytes,
  modInverse,
  P256_SCALAR_ORDER,
  sha256Pad,
} from "../../src/utils.js";
import {
  computeSwiyuPreparedLookupCommitment,
  computeSwiyuPreparedSessionCommitment,
  computeSwiyuPreparedStatusCommitment,
  computeSwiyuPreparedStatusUriCommitment,
} from "../../src/swiyu-zkp/commitments.js";
import {
  BindingTestBackend,
  HOLDER_PRIVATE_KEY,
  RecordingWitnessGenerator,
  buildCredentialFixture,
  holderSigner,
  makeChallenge,
  makeStatus,
  signJwt,
} from "./fixture.js";

const enabled = process.env.SWIYU_RESIDENCE_BENCHMARK === "1";
const primaryPacked = process.env.SWIYU_PACKED_STATUS_PRIMARY === "1";
const fixedRuns = process.env.SWIYU_RESIDENCE_RUNS === undefined
  ? undefined
  : Number.parseInt(process.env.SWIYU_RESIDENCE_RUNS, 10);
const here = dirname(fileURLToPath(import.meta.url));
const circom = join(here, "..", "..", "..", "circom");
const output = join(circom, "build", "swiyu_residence_benchmark");
const encoder = new TextEncoder();
const MUNICIPALITY_SALT = "AQIDBAUGBwgJCgsMDQ4PEA";
const SINCE_SALT = "__79_Pv6-fj39vX08_Lx8A";
const RESIDENCE_VCT = SWIYU_BENCHMARK_RESIDENCE.vct;

describe.skipIf(!enabled)("swiyu residence Prepare/Show benchmark fixtures", () => {
  it("generates repeated linked witnesses and exercises sound negative cases", async () => {
    if (fixedRuns !== undefined && (!Number.isInteger(fixedRuns) || fixedRuns < 1)) {
      throw new Error("SWIYU_RESIDENCE_RUNS must be a positive integer");
    }

    // The production age wallet supplies the stable parser/status fields shared
    // by all profiles. The residence policy challenge is re-signed below.
    const scaffold = buildCredentialFixture({ swiyuIssuerShape: true });
    const parsed = parseSwiyuCompactSdJwt(
      scaffold.compactSdJwt,
      scaffold.issuerPublicKey,
    );
    const challenge = makeChallenge();
    const { snapshot, witness: binaryStatusWitness } = makeStatus();
    const recorder = new RecordingWitnessGenerator();
    const wallet = new SwiyuZkpWallet({
      witnessGenerator: recorder,
      proofBackend: new BindingTestBackend(recorder),
    });
    const prepared = wallet.prepare({
      compactSdJwt: scaffold.compactSdJwt,
      issuerPublicKey: scaffold.issuerPublicKey,
    });
    await wallet.show({
      prepared,
      challenge,
      holderSigner: holderSigner(),
      statusSnapshot: snapshot,
      statusWitness: binaryStatusWitness,
      provingKey: new Uint8Array([1]),
    });
    if (!recorder.inputs) throw new Error("fixture did not produce circuit inputs");

    const residenceFixture = buildResidenceFixture();
    const [residenceJwt, municipalityDisclosure, sinceDisclosure] =
      residenceFixture.compactSdJwt.split("~") as [string, string, string];
    const prepareInputs = residencePrepareInputs(
      recorder.inputs,
      residenceJwt,
      municipalityDisclosure,
      sinceDisclosure,
      SWIYU_BENCHMARK_RESIDENCE.selectedMunicipalityBfs,
    );

    const lookupHints = {
      ...parsed.lookup,
      vct: RESIDENCE_VCT,
    };
    const lookup = computeSwiyuPreparedLookupCommitment(lookupHints);
    const uri = computeSwiyuPreparedStatusUriCommitment(parsed.statusUri);
    const baseChallengeHash = hashSwiyuChallenge(challenge).scalar;
    const challengeHash = computeSwiyuBenchmarkResidenceChallengeHash(
      baseChallengeHash,
    );
    const residenceHolderSignature = p256.sign(
      bigintToBytes(challengeHash, 32),
      HOLDER_PRIVATE_KEY,
    );
    const session = computeSwiyuPreparedSessionCommitment(challengeHash, lookup);
    const statusTreeBuildSamples: number[] = [];
    const statusPathSamples: number[] = [];
    const packedStatusTreeBuildSamples: number[] = [];
    const packedStatusPathSamples: number[] = [];
    let ternaryTree!: TernaryFixedIndexStatusTree;
    let ternaryWitness!: ReturnType<TernaryFixedIndexStatusTree["witness"]>;
    let packedTree!: PackedStatusChunkTree;
    let packedWitness!: ReturnType<PackedStatusChunkTree["witness"]>;
    const statusInitialRuns = fixedRuns ?? 2;
    if (primaryPacked) {
      for (let run = 0; run < statusInitialRuns; run++) {
        let started = performance.now();
        packedTree = PackedStatusChunkTree.buildSwiyuProfile(
          new Uint8Array(SWIYU_BENCHMARK_RESIDENCE_STATUS.listLength / 4),
          SWIYU_BENCHMARK_RESIDENCE_STATUS.epoch,
        );
        packedStatusTreeBuildSamples.push(performance.now() - started);
        started = performance.now();
        packedWitness = packedTree.witness(parsed.statusIndex);
        packedStatusPathSamples.push(performance.now() - started);
      }
    }
    for (let run = 0; run < statusInitialRuns; run++) {
      let statusStarted = performance.now();
      ternaryTree = TernaryFixedIndexStatusTree.buildSwiyuProfile(
        Array<typeof SWIYU_BENCHMARK_RESIDENCE_STATUS.statusValue>(
          SWIYU_BENCHMARK_RESIDENCE_STATUS.listLength,
        ).fill(SWIYU_BENCHMARK_RESIDENCE_STATUS.statusValue),
        SWIYU_BENCHMARK_RESIDENCE_STATUS.epoch,
      );
      statusTreeBuildSamples.push(performance.now() - statusStarted);
      statusStarted = performance.now();
      ternaryWitness = ternaryTree.witness(parsed.statusIndex);
      statusPathSamples.push(performance.now() - statusStarted);
    }
    const statusExpanded = fixedRuns === undefined
      && (unstable(statusTreeBuildSamples) || unstable(statusPathSamples));
    const statusRepetitions = fixedRuns ?? (statusExpanded ? 7 : 3);
    while (statusTreeBuildSamples.length < statusRepetitions) {
      let statusStarted = performance.now();
      ternaryTree = TernaryFixedIndexStatusTree.buildSwiyuProfile(
        Array<typeof SWIYU_BENCHMARK_RESIDENCE_STATUS.statusValue>(
          SWIYU_BENCHMARK_RESIDENCE_STATUS.listLength,
        ).fill(SWIYU_BENCHMARK_RESIDENCE_STATUS.statusValue),
        SWIYU_BENCHMARK_RESIDENCE_STATUS.epoch,
      );
      statusTreeBuildSamples.push(performance.now() - statusStarted);
      statusStarted = performance.now();
      ternaryWitness = ternaryTree.witness(parsed.statusIndex);
      statusPathSamples.push(performance.now() - statusStarted);
    }
    const status = computeSwiyuPreparedStatusCommitment(uri, ternaryTree.root);
    expect(ternaryTree.root).toBe(SWIYU_BENCHMARK_RESIDENCE_STATUS.snapshotRoot);
    const packedRunsAlreadyMeasured = packedStatusTreeBuildSamples.length;
    for (let run = packedRunsAlreadyMeasured; run < statusRepetitions; run++) {
      let started = performance.now();
      packedTree = PackedStatusChunkTree.buildSwiyuProfile(
        new Uint8Array(SWIYU_BENCHMARK_RESIDENCE_STATUS.listLength / 4),
        SWIYU_BENCHMARK_RESIDENCE_STATUS.epoch,
      );
      packedStatusTreeBuildSamples.push(performance.now() - started);
      started = performance.now();
      packedWitness = packedTree.witness(parsed.statusIndex);
      packedStatusPathSamples.push(performance.now() - started);
    }
    expect(packedTree.root).toBe(
      SWIYU_BENCHMARK_RESIDENCE_STATUS.packedV2.snapshotRoot,
    );
    const packedStatus = computeSwiyuPreparedStatusCommitment(uri, packedTree.root);
    const allowedMunicipalityCodes = [
      ...SWIYU_BENCHMARK_RESIDENCE.policy.allowedMunicipalityBfs.map(BigInt),
      ...Array<bigint>(14).fill(0n),
    ];
    const showInputs = {
      holderKeyX: base64urlToBigInt(parsed.holderPublicKey.x),
      holderKeyY: base64urlToBigInt(parsed.holderPublicKey.y),
      packedResidence: packSwiyuResidence(
        SWIYU_BENCHMARK_RESIDENCE.selectedMunicipalityBfs,
        SWIYU_BENCHMARK_RESIDENCE.residenceSince,
      ),
      credentialNbf: parsed.nbf,
      credentialExp: parsed.exp,
      statusIndex: parsed.statusIndex,
      lookupHashHi: lookup.hashHi,
      lookupHashLo: lookup.hashLo,
      statusUriHashHi: uri.hashHi,
      statusUriHashLo: uri.hashLo,
      holderSigR: residenceHolderSignature.r,
      holderSigSInverse: modInverse(
        residenceHolderSignature.s,
        P256_SCALAR_ORDER,
      ),
      statusValue: 0,
      statusSiblings: ternaryWitness.siblings.map((pair) =>
        pair.map((hex) => Array.from(Buffer.from(hex, "hex"), BigInt))),
      statusEpoch: ternaryTree.epoch,
      statusListLength: ternaryTree.entryCount,
      challengeHash,
      allowedCount: SWIYU_BENCHMARK_RESIDENCE.policy.allowedMunicipalityBfs.length,
      allowedMunicipalityCodes,
      minimumResidenceDays: SWIYU_BENCHMARK_RESIDENCE.policy.minimumResidenceDays,
      currentTime: recorder.inputs.currentTime,
      expectedMetadataHashHi: session.hashHi,
      expectedMetadataHashLo: session.hashLo,
      expectedStatusSnapshotHashHi: status.hashHi,
      expectedStatusSnapshotHashLo: status.hashLo,
    };
    const packedShowInputs = {
      ...showInputs,
      statusChunk: packedWitness.chunk.map(BigInt),
      statusSiblings: packedWitness.siblings.map((pair) =>
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
      prepareWtns = await calculate("swiyu_residence_prepare_compact", prepareInputs);
      prepareSamples.push(performance.now() - started);
      if (primaryPacked) {
        started = performance.now();
        packedShowWtns = await calculate(
          "swiyu_residence_show_packed_chunk_v2",
          packedShowInputs,
        );
        packedShowSamples.push(performance.now() - started);
        started = performance.now();
        showWtns = await calculate("swiyu_residence_show_split", showInputs);
        showSamples.push(performance.now() - started);
      } else {
        started = performance.now();
        showWtns = await calculate("swiyu_residence_show_split", showInputs);
        showSamples.push(performance.now() - started);
        started = performance.now();
        packedShowWtns = await calculate(
          "swiyu_residence_show_packed_chunk_v2",
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
      prepareWtns = await calculate("swiyu_residence_prepare_compact", prepareInputs);
      prepareSamples.push(performance.now() - started);
      if (primaryPacked) {
        started = performance.now();
        packedShowWtns = await calculate(
          "swiyu_residence_show_packed_chunk_v2",
          packedShowInputs,
        );
        packedShowSamples.push(performance.now() - started);
        started = performance.now();
        showWtns = await calculate("swiyu_residence_show_split", showInputs);
        showSamples.push(performance.now() - started);
      } else {
        started = performance.now();
        showWtns = await calculate("swiyu_residence_show_split", showInputs);
        showSamples.push(performance.now() - started);
        started = performance.now();
        packedShowWtns = await calculate(
          "swiyu_residence_show_packed_chunk_v2",
          packedShowInputs,
        );
        packedShowSamples.push(performance.now() - started);
      }
    }

    // A second, independently valid Show relation has a different private
    // shared row; split-proof linkage must reject pairing it with Prepare.
    const unlinkedShowWtns = await calculate("swiyu_residence_show_split", {
      ...showInputs,
      packedResidence: packSwiyuResidence(351, "2023-01-01"),
    });
    const unlinkedPackedShowWtns = await calculate(
      "swiyu_residence_show_packed_chunk_v2",
      {
        ...packedShowInputs,
        packedResidence: packSwiyuResidence(351, "2023-01-01"),
      },
    );
    if (fixedRuns === undefined) {
      await expect(calculate("swiyu_residence_show_split", {
        ...showInputs,
        allowedMunicipalityCodes: [351n, 6621n, ...Array<bigint>(14).fill(0n)],
      })).rejects.toThrow();
      await expect(calculate("swiyu_residence_show_split", {
        ...showInputs,
        minimumResidenceDays: 3650,
      })).rejects.toThrow();
      await expect(calculate("swiyu_residence_show_split", {
        ...showInputs,
        allowedMunicipalityCodes: [261n, 351n, 9n, ...Array<bigint>(13).fill(0n)],
      })).rejects.toThrow();
      await expect(calculate("swiyu_residence_show_split", {
        ...showInputs,
        statusListLength: 131_073,
      })).rejects.toThrow();

      const invalidDateFixture = buildResidenceFixture({ since: "2100-02-29" });
      const [badJwt, badMunicipality, badSince] =
        invalidDateFixture.compactSdJwt.split("~") as [string, string, string];
      await expect(calculate(
        "swiyu_residence_prepare_compact",
        residencePrepareInputs(recorder.inputs, badJwt, badMunicipality, badSince, 261),
      )).rejects.toThrow();

      const reusedSaltFixture = buildResidenceFixture({ sinceSalt: MUNICIPALITY_SALT });
      const [reusedJwt, reusedMunicipality, reusedSince] =
        reusedSaltFixture.compactSdJwt.split("~") as [string, string, string];
      await expect(calculate(
        "swiyu_residence_prepare_compact",
        residencePrepareInputs(
          recorder.inputs,
          reusedJwt,
          reusedMunicipality,
          reusedSince,
          261,
        ),
      )).rejects.toThrow();

      const nonCanonicalSaltFixture = buildResidenceFixture({
        municipalitySalt: "AQIDBAUGBwgJCgsMDQ4PEB",
      });
      const [nonCanonicalJwt, nonCanonicalMunicipality, nonCanonicalSince] =
        nonCanonicalSaltFixture.compactSdJwt.split("~") as [string, string, string];
      await expect(calculate(
        "swiyu_residence_prepare_compact",
        residencePrepareInputs(
          recorder.inputs,
          nonCanonicalJwt,
          nonCanonicalMunicipality,
          nonCanonicalSince,
          261,
        ),
      )).rejects.toThrow();
    }

    await mkdir(output, { recursive: true });
    await Promise.all([
      writeFile(join(output, "prepare.wtns"), prepareWtns),
      writeFile(join(output, "show.wtns"), showWtns),
      writeFile(join(output, "show-packed-v2.wtns"), packedShowWtns),
      writeFile(join(output, "show-unlinked.wtns"), unlinkedShowWtns),
      writeFile(join(output, "show-unlinked-packed-v2.wtns"), unlinkedPackedShowWtns),
      writeFile(join(output, "witness-runs.json"), JSON.stringify({
        profile: "swiyu.residence-eligibility.prepare-show.v1",
        predicate: "issuer-authenticated municipality is in a public 1..16 BFS allow-list and residence_since is at least the public duration",
        repetitions,
        expandedAfterFirstTwo: expanded,
        processPeakRssBytes: process.resourceUsage().maxRSS * 1024,
        runtime: {
          node: process.version,
          platform: platform(),
          release: release(),
          arch: arch(),
          logicalCpuCount: cpus().length,
          cpuModel: cpus()[0]?.model,
          totalMemoryBytes: totalmem(),
        },
        statusSnapshotStagesMs: {
          repetitions: statusRepetitions,
          expandedAfterFirstTwo: statusExpanded,
          ternaryTreeBuild: statusTreeBuildSamples,
          statusPathGeneration: statusPathSamples,
          ternaryTreeBuildStats: stats(statusTreeBuildSamples),
          statusPathGenerationStats: stats(statusPathSamples),
          packedV2TreeBuild: packedStatusTreeBuildSamples,
          packedV2PathGeneration: packedStatusPathSamples,
          packedV2TreeBuildStats: stats(packedStatusTreeBuildSamples),
          packedV2PathGenerationStats: stats(packedStatusPathSamples),
        },
        policy: {
          municipalityBfs: SWIYU_BENCHMARK_RESIDENCE.selectedMunicipalityBfs,
          residenceSince: SWIYU_BENCHMARK_RESIDENCE.residenceSince,
          allowedMunicipalityBfs: SWIYU_BENCHMARK_RESIDENCE.policy.allowedMunicipalityBfs,
          minimumResidenceDays: SWIYU_BENCHMARK_RESIDENCE.policy.minimumResidenceDays,
          currentTime: Number(recorder.inputs.currentTime),
          municipalityDirectoryAsOf: SWIYU_BENCHMARK_RESIDENCE.policy.municipalityDirectoryAsOf,
          municipalityDirectorySha256: SWIYU_BENCHMARK_RESIDENCE.policy.municipalityDirectorySha256,
          holderChallengeBinding: "swiyu-residence-policy-v1",
          UTCWholeDaySemantics: true,
          statusRequired: "VALID (00)",
          statusSnapshot: {
            encoding: "packed two-bit statuses",
            listLength: ternaryTree.entryCount,
            epoch: ternaryTree.epoch,
            root: ternaryTree.root,
            sdkHostRootContract:
              "same all-VALID entries, list length, epoch, and ternary construction; exact root must match",
            packedV2: {
              ...SWIYU_BENCHMARK_RESIDENCE_STATUS.packedV2,
              ...SWIYU_PACKED_STATUS_SHOW_PROFILES_V2.residence,
              root: packedTree.root,
            },
          },
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

function buildResidenceFixture(options: {
  municipalitySalt?: string;
  sinceSalt?: string;
  since?: string;
} = {}): { compactSdJwt: string } {
  const scaffold = buildCredentialFixture({
    swiyuIssuerShape: true,
    vct: RESIDENCE_VCT,
  });
  const [scaffoldJwt] = scaffold.compactSdJwt.split("~");
  const [header, payload] = scaffoldJwt!.split(".") as [string, string];
  const municipalityDisclosure = base64urlEncode(encoder.encode(JSON.stringify([
    options.municipalitySalt ?? MUNICIPALITY_SALT,
    "residence_municipality_bfs",
    SWIYU_BENCHMARK_RESIDENCE.selectedMunicipalityBfs,
  ])));
  const sinceDisclosure = base64urlEncode(encoder.encode(JSON.stringify([
    options.sinceSalt ?? SINCE_SALT,
    "residence_since",
    options.since ?? SWIYU_BENCHMARK_RESIDENCE.residenceSince,
  ])));
  const payloadObject = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as {
    _sd: string[];
  };
  payloadObject._sd = [municipalityDisclosure, sinceDisclosure].map((disclosure) =>
    base64urlEncode(sha256(encoder.encode(disclosure))));
  const jwt = signJwt(
    Buffer.from(header, "base64url").toString("utf8"),
    JSON.stringify(payloadObject),
  );
  return {
    compactSdJwt: `${jwt}~${municipalityDisclosure}~${sinceDisclosure}~`,
  };
}

function residencePrepareInputs(
  base: Record<string, unknown>,
  jwt: string,
  municipalityDisclosure: string,
  sinceDisclosure: string,
  municipalityBfs: number,
): Record<string, unknown> {
  const [header, payload, compactSignature] = jwt.split(".") as [string, string, string];
  const signingInput = `${header}.${payload}`;
  const [message, messageLength] = sha256Pad(encoder.encode(signingInput), 896);
  const [municipalityPadded] = sha256Pad(encoder.encode(municipalityDisclosure), 128);
  const [sincePadded] = sha256Pad(encoder.encode(sinceDisclosure), 128);
  const signature = p256.Signature.fromCompact(Buffer.from(compactSignature, "base64url"));
  const municipalityDigest = base64urlEncode(sha256(encoder.encode(municipalityDisclosure)));
  const sinceDigest = base64urlEncode(sha256(encoder.encode(sinceDisclosure)));
  const payloadJson = Buffer.from(payload, "base64url").toString("utf8");
  const cnfKey = keyStart(payloadJson, "cnf");
  const cnfOpen = payloadJson.indexOf("{", cnfKey);
  const cnfClose = matchingClose(payloadJson, cnfOpen, "{", "}");
  const jwkKey = keyStart(payloadJson, "jwk", cnfOpen);
  const jwkOpen = payloadJson.indexOf("{", jwkKey);
  const jwkClose = matchingClose(payloadJson, jwkOpen, "{", "}");
  const statusKey = keyStart(payloadJson, "status");
  const statusOpen = payloadJson.indexOf("{", statusKey);
  const statusClose = matchingClose(payloadJson, statusOpen, "{", "}");
  const statusListKey = keyStart(payloadJson, "status_list", statusOpen);
  const statusListOpen = payloadJson.indexOf("{", statusListKey);
  const statusListClose = matchingClose(payloadJson, statusListOpen, "{", "}");
  const sdKey = keyStart(payloadJson, "_sd");
  const sdOpen = payloadJson.indexOf("[", sdKey);
  const sdClose = matchingClose(payloadJson, sdOpen, "[", "]");
  const inputs: Record<string, unknown> = {
    ...base,
    message: Array.from(message, BigInt),
    messageLength,
    periodIndex: header.length,
    headerJsonLength: Buffer.from(header, "base64url").length,
    payloadJsonLength: Buffer.byteLength(payloadJson),
    payloadIssKeyStart: keyStart(payloadJson, "iss"),
    payloadVctKeyStart: keyStart(payloadJson, "vct"),
    payloadNbfKeyStart: keyStart(payloadJson, "nbf"),
    payloadExpKeyStart: keyStart(payloadJson, "exp"),
    payloadCnfKeyStart: cnfKey,
    payloadCnfClose: cnfClose,
    payloadJwkKeyStart: jwkKey,
    payloadJwkClose: jwkClose,
    payloadKtyKeyStart: keyStart(payloadJson, "kty", jwkOpen),
    payloadCrvKeyStart: keyStart(payloadJson, "crv", jwkOpen),
    payloadXKeyStart: keyStart(payloadJson, "x", jwkOpen),
    payloadYKeyStart: keyStart(payloadJson, "y", jwkOpen),
    payloadStatusKeyStart: statusKey,
    payloadStatusClose: statusClose,
    payloadStatusListKeyStart: statusListKey,
    payloadStatusListClose: statusListClose,
    payloadStatusUriKeyStart: keyStart(payloadJson, "uri", statusListOpen),
    payloadStatusIdxKeyStart: keyStart(payloadJson, "idx", statusListOpen),
    payloadSdAlgKeyStart: keyStart(payloadJson, "_sd_alg"),
    payloadSdKeyStart: sdKey,
    payloadSdClose: sdClose,
    // JsonDigestArrayMember indices point at each member's opening quote.
    payloadMunicipalityDigestStart: payloadJson.indexOf(municipalityDigest) - 1,
    payloadSinceDigestStart: payloadJson.indexOf(sinceDigest) - 1,
    issuerSigR: signature.r,
    issuerSigSInverse: modInverse(signature.s, P256_SCALAR_ORDER),
    municipalityDisclosurePadded: Array.from(municipalityPadded, BigInt),
    municipalityDisclosureLength: municipalityDisclosure.length,
    municipalityDisclosureJsonLength: Buffer.from(municipalityDisclosure, "base64url").length,
    municipalityDisclosureSaltLength: MUNICIPALITY_SALT.length,
    municipalityDigitLength: String(municipalityBfs).length,
    sinceDisclosurePadded: Array.from(sincePadded, BigInt),
    sinceDisclosureLength: sinceDisclosure.length,
    sinceDisclosureJsonLength: Buffer.from(sinceDisclosure, "base64url").length,
    sinceDisclosureSaltLength: SINCE_SALT.length,
    municipalityDisclosureDigestB64: Array.from(encoder.encode(municipalityDigest), BigInt),
    sinceDisclosureDigestB64: Array.from(encoder.encode(sinceDigest), BigInt),
    vct: asciiPadded(RESIDENCE_VCT, 112),
    vctLength: RESIDENCE_VCT.length,
  };
  for (const key of [
    "challengeHash", "cutoffDate", "currentTime",
    "expectedMetadataHashHi", "expectedMetadataHashLo",
    "expectedStatusSnapshotHashHi", "expectedStatusSnapshotHashLo",
    "holderSigR", "holderSigSInverse", "statusValue", "statusSiblings",
    "statusEpoch", "statusListLength", "disclosurePadded", "disclosureLength",
    "disclosureJsonLength", "disclosureSaltLength", "disclosureDigestB64",
    "payloadDigestStart",
  ]) delete inputs[key];
  return inputs;
}

function asciiPadded(value: string, length: number): bigint[] {
  const output = Array<bigint>(length).fill(0n);
  for (let index = 0; index < value.length; index++) output[index] = BigInt(value.charCodeAt(index));
  return output;
}

function keyStart(json: string, key: string, from = 0): number {
  const index = json.indexOf(`"${key}":`, from);
  if (index < 0) throw new Error(`missing JSON key ${key}`);
  return index;
}

function matchingClose(
  json: string,
  openIndex: number,
  open: "{" | "[",
  close: "}" | "]",
): number {
  let depth = 0;
  let inString = false;
  for (let index = openIndex; index < json.length; index++) {
    const char = json[index]!;
    if (char === '"' && json[index - 1] !== "\\") inString = !inString;
    if (inString) continue;
    if (char === open) depth += 1;
    if (char === close) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  throw new Error(`unclosed JSON container at ${openIndex}`);
}

async function calculate(
  circuitName: string,
  inputs: Record<string, unknown>,
): Promise<Uint8Array> {
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
    min: ordered[0],
    median: ordered[Math.floor(ordered.length / 2)],
    max: ordered.at(-1),
    mean,
    standardDeviation,
    coefficientOfVariation: mean === 0 ? 0 : standardDeviation / mean,
  };
}

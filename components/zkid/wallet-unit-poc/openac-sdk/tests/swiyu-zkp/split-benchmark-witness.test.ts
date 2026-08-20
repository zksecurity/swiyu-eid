import { describe, expect, it } from "vitest";
import { mkdir, readFile, writeFile } from "fs/promises";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

import { SwiyuZkpWallet } from "../../src/swiyu-zkp/wallet.js";
import { parseSwiyuCompactSdJwt } from "../../src/swiyu-zkp/parser.js";
import { hashSwiyuChallenge } from "../../src/swiyu-zkp/challenge.js";
import { PackedStatusChunkTree } from "../../src/status-designs/packed-status-chunk-merkle.js";
import {
  SWIYU_BENCHMARK_AGE_PACKED_STATUS_V2,
  SWIYU_PACKED_STATUS_SHOW_PROFILES_V2,
} from "../../src/swiyu-zkp/status-benchmark-manifest.js";
import { base64urlToBigInt } from "../../src/utils.js";
import {
  computeSwiyuPreparedLookupCommitment,
  computeSwiyuPreparedSessionCommitment,
  computeSwiyuPreparedStatusCommitment,
  computeSwiyuPreparedStatusUriCommitment,
} from "../../src/swiyu-zkp/commitments.js";
import {
  BindingTestBackend,
  RecordingWitnessGenerator,
  buildCredentialFixture,
  holderSigner,
  makeChallenge,
  makeStatus,
} from "./fixture.js";

const enabled = process.env.SWIYU_SPLIT_BENCHMARK === "1";
const primaryPacked = process.env.SWIYU_PACKED_STATUS_PRIMARY === "1";
const here = dirname(fileURLToPath(import.meta.url));
const circom = join(here, "..", "..", "..", "circom");
const output = join(circom, "build", "swiyu_split_benchmark");

describe.skipIf(!enabled)("swiyu Prepare/Show split benchmark fixtures", () => {
  it("generates valid linked and deliberately-unlinked WTNS files", async () => {
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
      holderSigner: holderSigner(),
      statusSnapshot: snapshot,
      statusWitness,
      provingKey: new Uint8Array([1]),
    });
    if (!recorder.inputs) throw new Error("fixture did not produce circuit inputs");

    const lookup = computeSwiyuPreparedLookupCommitment(parsed.lookup);
    const uri = computeSwiyuPreparedStatusUriCommitment(parsed.statusUri);
    const challengeHash = hashSwiyuChallenge(challenge).scalar;
    const session = computeSwiyuPreparedSessionCommitment(challengeHash, lookup);
    const status = computeSwiyuPreparedStatusCommitment(uri, snapshot.root);
    let statusStarted = performance.now();
    const packedTree = PackedStatusChunkTree.buildSwiyuProfile(
      new Uint8Array(SWIYU_BENCHMARK_AGE_PACKED_STATUS_V2.listLength / 4),
      SWIYU_BENCHMARK_AGE_PACKED_STATUS_V2.epoch,
    );
    const packedV2TreeBuildMs = performance.now() - statusStarted;
    expect(packedTree.root).toBe(SWIYU_BENCHMARK_AGE_PACKED_STATUS_V2.snapshotRoot);
    statusStarted = performance.now();
    const packedWitness = packedTree.witness(parsed.statusIndex);
    const packedV2PathGenerationMs = performance.now() - statusStarted;
    const packedStatus = computeSwiyuPreparedStatusCommitment(uri, packedTree.root);

    const prepareInputs = {
      // The flag-disabled online signals remain in this benchmark template's
      // input ABI even though they create no constraints in Prepare.
      ...recorder.inputs,
      message: recorder.inputs.message.slice(0, 896),
    };
    const showInputs = {
      holderKeyX: base64urlToBigInt(parsed.holderPublicKey.x),
      holderKeyY: base64urlToBigInt(parsed.holderPublicKey.y),
      birthdateNumeric: parsed.birthdateNumeric,
      credentialNbf: parsed.nbf,
      credentialExp: parsed.exp,
      statusIndex: parsed.statusIndex,
      lookupHashHi: lookup.hashHi,
      lookupHashLo: lookup.hashLo,
      statusUriHashHi: uri.hashHi,
      statusUriHashLo: uri.hashLo,
      holderSigR: recorder.inputs.holderSigR,
      holderSigSInverse: recorder.inputs.holderSigSInverse,
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

    const prepareStarted = performance.now();
    const prepareWtns = await calculate(
      "swiyu_age18_prepare_compact",
      prepareInputs,
    );
    const prepareWitnessMs = performance.now() - prepareStarted;
    let showWtns: Uint8Array;
    let showWitnessMs: number;
    let packedShowWtns: Uint8Array;
    let packedShowWitnessMs: number;
    if (primaryPacked) {
      let started = performance.now();
      packedShowWtns = await calculate(
        "swiyu_age18_show_packed_chunk_v2",
        packedShowInputs,
      );
      packedShowWitnessMs = performance.now() - started;
      started = performance.now();
      showWtns = await calculate("swiyu_age18_show_split", showInputs);
      showWitnessMs = performance.now() - started;
    } else {
      let started = performance.now();
      showWtns = await calculate("swiyu_age18_show_split", showInputs);
      showWitnessMs = performance.now() - started;
      started = performance.now();
      packedShowWtns = await calculate(
        "swiyu_age18_show_packed_chunk_v2",
        packedShowInputs,
      );
      packedShowWitnessMs = performance.now() - started;
    }
    const unlinkedStarted = performance.now();
    const unlinkedShowWtns = await calculate("swiyu_age18_show_split", {
      ...showInputs,
      birthdateNumeric: 19990101n,
    });
    const unlinkedShowWitnessMs = performance.now() - unlinkedStarted;
    const unlinkedPackedShowWtns = await calculate(
      "swiyu_age18_show_packed_chunk_v2",
      { ...packedShowInputs, birthdateNumeric: 19990101n },
    );

    await mkdir(output, { recursive: true });
    await Promise.all([
      writeFile(join(output, "prepare.wtns"), prepareWtns),
      writeFile(join(output, "show.wtns"), showWtns),
      writeFile(join(output, "show-packed-v2.wtns"), packedShowWtns),
      writeFile(join(output, "show-unlinked.wtns"), unlinkedShowWtns),
      writeFile(join(output, "show-unlinked-packed-v2.wtns"), unlinkedPackedShowWtns),
      writeFile(
        join(output, "fixture.json"),
        JSON.stringify(
          {
            witnessGenerationMs: {
              prepare: prepareWitnessMs,
              show: showWitnessMs,
              showPackedV2: packedShowWitnessMs,
              unlinkedShow: unlinkedShowWitnessMs,
            },
            statusSnapshotStagesMs: {
              packedV2TreeBuild: [packedV2TreeBuildMs],
              packedV2PathGeneration: [packedV2PathGenerationMs],
            },
            processPeakRssBytes: process.resourceUsage().maxRSS * 1024,
            policy: {
              sourceClaim: ["birthdate", "2000-02-29"],
              cutoffDate: challenge.cutoffDate,
              derivedClaim: ["age_over_18", true],
              statusRequired: "VALID (00)",
              packedStatusV2: SWIYU_BENCHMARK_AGE_PACKED_STATUS_V2,
              packedStatusShow: SWIYU_PACKED_STATUS_SHOW_PROFILES_V2.age,
              statusSnapshot: {
                uri: parsed.statusUri,
                index: parsed.statusIndex,
                ...SWIYU_BENCHMARK_AGE_PACKED_STATUS_V2,
              },
            },
            shared: {
              holderKeyX: showInputs.holderKeyX,
              holderKeyY: showInputs.holderKeyY,
              birthdateNumeric: showInputs.birthdateNumeric,
              credentialNbf: showInputs.credentialNbf,
              credentialExp: showInputs.credentialExp,
              statusIndex: showInputs.statusIndex,
              lookupHashHi: lookup.hashHi,
              lookupHashLo: lookup.hashLo,
              statusUriHashHi: uri.hashHi,
              statusUriHashLo: uri.hashLo,
              expressionResult: 1n,
            },
            public: {
              prepare: [parsed.baseInputs.issuerPubKeyX, parsed.baseInputs.issuerPubKeyY],
              show: [
                challengeHash,
                showInputs.cutoffDate,
                showInputs.currentTime,
                session.hashHi,
                session.hashLo,
                status.hashHi,
                status.hashLo,
              ],
              showPackedV2: [
                challengeHash,
                showInputs.cutoffDate,
                showInputs.currentTime,
                session.hashHi,
                session.hashLo,
                packedStatus.hashHi,
                packedStatus.hashLo,
              ],
            },
          },
          (_key, value) => typeof value === "bigint" ? value.toString() : value,
          2,
        ),
      ),
    ]);

    expect(prepareWtns.byteLength).toBeGreaterThan(1_000_000);
    expect(showWtns.byteLength).toBeGreaterThan(1_000_000);
    expect(packedShowWtns.byteLength).toBeGreaterThan(1_000_000);
  }, 20 * 60_000);
});

async function calculate(
  circuitName: string,
  inputs: Record<string, unknown>,
): Promise<Uint8Array> {
  // The generated calculator is CommonJS-compatible and intentionally has no
  // TypeScript declarations.
  // @ts-expect-error generated Circom module
  const imported = await import("../../assets/witness_calculator.js");
  const builder = imported.default ?? imported;
  const wasm = await readFile(
    join(circom, "build", circuitName, `${circuitName}_js`, `${circuitName}.wasm`),
  );
  const calculator = await builder(wasm, { sanityCheck: true });
  return calculator.calculateWTNSBin(inputs, true);
}

import { describe, expect, it } from "vitest";
import { mkdir, readFile, writeFile } from "fs/promises";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2";

import { SwiyuZkpWallet } from "../../src/swiyu-zkp/wallet.js";
import { parseSwiyuCompactSdJwt } from "../../src/swiyu-zkp/parser.js";
import { hashSwiyuChallenge } from "../../src/swiyu-zkp/challenge.js";
import {
  base64urlEncode,
  base64urlToBigInt,
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
  RecordingWitnessGenerator,
  buildCredentialFixture,
  holderSigner,
  makeChallenge,
  makeStatus,
} from "./fixture.js";

const enabled = process.env.SWIYU_CANTON_BENCHMARK === "1";
const fixedSingleRun = process.env.SWIYU_FIXED_BENCHMARK_RUNS === "1";
const here = dirname(fileURLToPath(import.meta.url));
const circom = join(here, "..", "..", "..", "circom");
const output = join(circom, "build", "swiyu_canton_benchmark");
const encoder = new TextEncoder();
const cantonCode = (code: string) => BigInt(code.charCodeAt(0) * 256 + code.charCodeAt(1));

describe.skipIf(!enabled)("swiyu canton Prepare/Show benchmark fixtures", () => {
  it("generates adaptive timed linked witness repetitions and sound negative cases", async () => {
    // Reuse the production parser/wallet to construct all stable inputs, then
    // replace only the signed JWT and selected disclosure with the canton
    // credential. Their fixed-width signed payload layouts are identical.
    const ageFixture = buildCredentialFixture({ swiyuIssuerShape: true });
    const parsed = parseSwiyuCompactSdJwt(
      ageFixture.compactSdJwt,
      ageFixture.issuerPublicKey,
    );
    const challenge = makeChallenge();
    const { snapshot, witness: statusWitness } = makeStatus();
    const recorder = new RecordingWitnessGenerator();
    const wallet = new SwiyuZkpWallet({
      witnessGenerator: recorder,
      proofBackend: new BindingTestBackend(recorder),
    });
    const prepared = wallet.prepare({
      compactSdJwt: ageFixture.compactSdJwt,
      issuerPublicKey: ageFixture.issuerPublicKey,
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

    const cantonFixture = buildCredentialFixture({
      swiyuIssuerShape: true,
      disclosureName: "resident_canton",
      birthdate: "ZH",
    });
    const prepareInputs = cantonPrepareInputs(recorder.inputs, cantonFixture.jwt, cantonFixture.disclosure);
    const lookup = computeSwiyuPreparedLookupCommitment(parsed.lookup);
    const uri = computeSwiyuPreparedStatusUriCommitment(parsed.statusUri);
    const challengeHash = hashSwiyuChallenge(challenge).scalar;
    const session = computeSwiyuPreparedSessionCommitment(challengeHash, lookup);
    const status = computeSwiyuPreparedStatusCommitment(uri, snapshot.root);
    const showInputs = {
      holderKeyX: base64urlToBigInt(parsed.holderPublicKey.x),
      holderKeyY: base64urlToBigInt(parsed.holderPublicKey.y),
      cantonCode: cantonCode("ZH"),
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
      allowedCount: 2,
      allowedCantonCodes: [cantonCode("ZH"), cantonCode("BE"), 0n, 0n],
      currentTime: recorder.inputs.currentTime,
      expectedMetadataHashHi: session.hashHi,
      expectedMetadataHashLo: session.hashLo,
      expectedStatusSnapshotHashHi: status.hashHi,
      expectedStatusSnapshotHashLo: status.hashLo,
    };

    const prepareRuns: number[] = [];
    const showRuns: number[] = [];
    let prepareWtns = new Uint8Array();
    let showWtns = new Uint8Array();
    const initialRuns = fixedSingleRun ? 1 : 2;
    for (let run = 0; run < initialRuns; run++) {
      let started = performance.now();
      prepareWtns = await calculate("swiyu_canton_prepare_compact", prepareInputs);
      prepareRuns.push(performance.now() - started);
      started = performance.now();
      showWtns = await calculate("swiyu_canton_show_split", showInputs);
      showRuns.push(performance.now() - started);
    }
    const firstTwoVaryOver15Percent = !fixedSingleRun && [prepareRuns, showRuns].some(
      ([first, second]) => Math.abs(first! - second!) / Math.max((first! + second!) / 2, 0.001) > 0.15,
    );
    const requiredRuns = fixedSingleRun ? 1 : firstTwoVaryOver15Percent ? 7 : 3;
    while (prepareRuns.length < requiredRuns) {
      let started = performance.now();
      prepareWtns = await calculate("swiyu_canton_prepare_compact", prepareInputs);
      prepareRuns.push(performance.now() - started);
      started = performance.now();
      showWtns = await calculate("swiyu_canton_show_split", showInputs);
      showRuns.push(performance.now() - started);
    }
    const unlinkedShowWtns = await calculate("swiyu_canton_show_split", {
      ...showInputs,
      cantonCode: cantonCode("BE"),
    });
    await expect(calculate("swiyu_canton_show_split", {
      ...showInputs,
      allowedCount: 2,
      allowedCantonCodes: [cantonCode("BE"), cantonCode("GE"), 0n, 0n],
    })).rejects.toThrow();
    const invalidCantonFixture = buildCredentialFixture({
      swiyuIssuerShape: true,
      disclosureName: "resident_canton",
      birthdate: "XX",
    });
    await expect(calculate(
      "swiyu_canton_prepare_compact",
      cantonPrepareInputs(
        recorder.inputs,
        invalidCantonFixture.jwt,
        invalidCantonFixture.disclosure,
      ),
    )).rejects.toThrow();

    await mkdir(output, { recursive: true });
    await Promise.all([
      writeFile(join(output, "prepare.wtns"), prepareWtns),
      writeFile(join(output, "show.wtns"), showWtns),
      writeFile(join(output, "show-unlinked.wtns"), unlinkedShowWtns),
      writeFile(join(output, "witness-runs.json"), JSON.stringify({
        predicate: "issuer-authenticated resident_canton belongs to a public 1..4 canton allow-list",
        policy: {
          disclosedClaim: ["resident_canton", "ZH"],
          allowedValues: ["ZH", "BE"],
          allowedCount: 2,
          statusRequired: "VALID (00)",
        },
        repetitionRule: {
          firstTwoPrincipalStageVariationOver15Percent: firstTwoVaryOver15Percent,
          requiredRuns,
          satisfied: prepareRuns.length >= requiredRuns && showRuns.length >= requiredRuns,
        },
        prepareWitnessMs: prepareRuns,
        showWitnessMs: showRuns,
        prepareWitnessStats: stats(prepareRuns),
        showWitnessStats: stats(showRuns),
        prepareWitnessBytes: prepareWtns.byteLength,
        showWitnessBytes: showWtns.byteLength,
        // Linux and macOS expose maxRSS in KiB to Node. The pinned Docker
        // benchmark is Linux, so normalize the fresh witness process to bytes.
        processPeakRssBytes: process.resourceUsage().maxRSS * 1024,
      }, null, 2) + "\n"),
    ]);
    expect(prepareWtns.byteLength).toBeGreaterThan(1_000_000);
    expect(showWtns.byteLength).toBeGreaterThan(1_000_000);
  }, 20 * 60_000);
});

function cantonPrepareInputs(
  base: Record<string, unknown>,
  jwt: string,
  disclosure: string,
): Record<string, unknown> {
  const [header, payload, compactSignature] = jwt.split(".") as [string, string, string];
  const signingInput = `${header}.${payload}`;
  const [message, messageLength] = sha256Pad(encoder.encode(signingInput), 896);
  const [disclosurePadded] = sha256Pad(encoder.encode(disclosure), 128);
  const decodedDisclosure = Buffer.from(disclosure, "base64url");
  const signature = p256.Signature.fromCompact(Buffer.from(compactSignature, "base64url"));
  const digest = base64urlEncode(sha256(encoder.encode(disclosure)));
  const inputs: Record<string, unknown> = {
    ...base,
    message: Array.from(message, BigInt),
    messageLength,
    issuerSigR: signature.r,
    issuerSigSInverse: modInverse(signature.s, P256_SCALAR_ORDER),
    disclosurePadded: Array.from(disclosurePadded, BigInt),
    disclosureLength: disclosure.length,
    disclosureJsonLength: decodedDisclosure.length,
    disclosureSaltLength: "abcdefghijklmnop".length,
    disclosureDigestB64: Array.from(encoder.encode(digest), BigInt),
  };
  // The dedicated Prepare ABI deliberately contains no online presentation
  // inputs; remove the age-profile values used only to seed this fixture.
  for (const key of [
    "challengeHash", "cutoffDate", "currentTime",
    "expectedMetadataHashHi", "expectedMetadataHashLo",
    "expectedStatusSnapshotHashHi", "expectedStatusSnapshotHashLo",
    "holderSigR", "holderSigSInverse", "statusValue", "statusSiblings",
    "statusEpoch", "statusListLength",
  ]) delete inputs[key];
  return inputs;
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

function stats(values: number[]) {
  const ordered = [...values].sort((a, b) => a - b);
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  const variance = values.length > 1
    ? values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / (values.length - 1)
    : 0;
  const standardDeviation = Math.sqrt(variance);
  return {
    values,
    min: ordered[0],
    median: ordered[Math.floor(ordered.length / 2)],
    max: ordered.at(-1),
    mean,
    variance,
    standardDeviation,
    coefficientOfVariation: mean === 0 ? 0 : standardDeviation / mean,
  };
}

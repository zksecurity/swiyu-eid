import { describe, expect, it } from "vitest";
import { mkdir, readFile, writeFile } from "fs/promises";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2";

import { SwiyuZkpWallet } from "../../src/swiyu-zkp/wallet.js";
import {
  base64urlEncode,
  modInverse,
  P256_SCALAR_ORDER,
  sha256Pad,
} from "../../src/utils.js";
import { SWIYU_BENCHMARK_RESIDENCE } from "../../src/swiyu-zkp/residence-benchmark-manifest.js";
import {
  BindingTestBackend,
  RecordingWitnessGenerator,
  buildCredentialFixture,
  holderSigner,
  makeChallenge,
  makeStatus,
  signJwt,
} from "./fixture.js";

const enabled = process.env.SWIYU_RESIDENCE_COMBINED_BENCHMARK === "1";
const fixedRuns = process.env.SWIYU_RESIDENCE_COMBINED_RUNS === undefined
  ? undefined
  : Number.parseInt(process.env.SWIYU_RESIDENCE_COMBINED_RUNS, 10);
const here = dirname(fileURLToPath(import.meta.url));
const circom = join(here, "..", "..", "..", "circom");
const output = join(circom, "build", "swiyu_residence_combined_benchmark");
const encoder = new TextEncoder();
const RESIDENCE_SALT = SWIYU_BENCHMARK_RESIDENCE.disclosureSalt;
const RESIDENCE_VCT = SWIYU_BENCHMARK_RESIDENCE.vct;

describe.skipIf(!enabled)("combined residence-disclosure Prepare A/B fixture", () => {
  it("generates the optimized witness and rejects non-canonical claim shapes", async () => {
    if (fixedRuns !== undefined && (!Number.isInteger(fixedRuns) || fixedRuns < 1)) {
      throw new Error("SWIYU_RESIDENCE_COMBINED_RUNS must be a positive integer");
    }

    const base = await buildBaseInputs();
    const fixture = buildCombinedFixture();
    const inputs = combinedPrepareInputs(
      base,
      fixture.jwt,
      fixture.disclosure,
      SWIYU_BENCHMARK_RESIDENCE.selectedMunicipalityBfs,
    );

    expect(inputs.periodIndex).toBe(246);
    expect(inputs.payloadJsonLength).toBe(428);
    expect(fixture.disclosure.length).toBe(112);
    expect(Buffer.from(fixture.disclosure, "base64url").length).toBe(84);
    const signedPayload = Buffer.from(fixture.jwt.split(".")[1]!, "base64url").toString("utf8");
    const statusUri = String.fromCharCode(...(inputs.statusUri as bigint[])
      .slice(0, Number(inputs.statusUriLength)).map(Number));
    expect(statusUri).toBe("https://status.example.ch/lists/2026-07");
    expect(signedPayload.slice(
      Number(inputs.payloadStatusUriKeyStart),
      Number(inputs.payloadStatusUriKeyStart) + 48,
    )).toContain(statusUri);

    const samples: number[] = [];
    let witness = new Uint8Array();
    const initialRuns = fixedRuns ?? 2;
    for (let run = 0; run < initialRuns; run++) {
      const started = performance.now();
      witness = await calculate(inputs);
      samples.push(performance.now() - started);
    }
    const expanded = fixedRuns === undefined && unstable(samples);
    const repetitions = fixedRuns ?? (expanded ? 7 : 3);
    while (samples.length < repetitions) {
      const started = performance.now();
      witness = await calculate(inputs);
      samples.push(performance.now() - started);
    }

    if (fixedRuns === undefined) {
      // These fully issuer-signed failures test the optimized disclosure
      // grammar/ranges. The pinned timing worker omits them because correctness
      // is established before the serialized campaign and their extra witness
      // calculations would create profile-specific thermal preconditioning.
      await expect(calculate(combinedInputsFor(base, { since: "2100-02-29" })))
        .rejects.toThrow();
      await expect(calculate(combinedInputsFor(base, { municipalityBfs: 7000 })))
        .rejects.toThrow();
      await expect(calculate(combinedInputsFor(base, {
        salt: "AQIDBAUGBwgJCgsMDQ4PEB",
      }))).rejects.toThrow();
      await expect(calculate(combinedInputsFor(base, { reverseObjectKeys: true })))
        .rejects.toThrow();
      await expect(calculate(combinedInputsFor(base, { extraWhitespace: true })))
        .rejects.toThrow();
    }

    await mkdir(output, { recursive: true });
    await Promise.all([
      writeFile(join(output, "prepare.wtns"), witness),
      writeFile(join(output, "witness-runs.json"), JSON.stringify({
        profile: "swiyu.residence-eligibility.combined-disclosure-ab.v1",
        controlProfile: "swiyu.residence-eligibility.prepare-show.v1",
        representation: "one object-valued SD-JWT disclosure",
        selectiveDisclosureTradeoff:
          "municipality_bfs and since cannot be released independently",
        disclosure: {
          decodedBytes: 84,
          encodedBytes: 112,
          payloadDecodedBytes: 428,
          payloadEncodedBytes: 571,
          signingInputBytes: 818,
        },
        fixtureIdentity: {
          compactCredentialSha256: base64urlEncode(
            sha256(encoder.encode(`${fixture.jwt}~${fixture.disclosure}~`)),
          ),
          issuerJwtSha256: base64urlEncode(sha256(encoder.encode(fixture.jwt))),
          disclosureSha256: [base64urlEncode(
            sha256(encoder.encode(fixture.disclosure)),
          )],
        },
        bounds: {
          paddedSigningInputBytes: 832,
          encodedHeaderBytes: 248,
          encodedPayloadBytes: 572,
          statusUriCommitmentBytes: 160,
          statusUriParserBufferBytes: 120,
          fixtureStatusUriBytes: 39,
          portability:
            "bounded fixture/profile optimization; not a universal SD-JWT URI bound",
        },
        repetitions,
        expandedAfterFirstTwo: expanded,
        processPeakRssBytes: process.resourceUsage().maxRSS * 1024,
        prepareWitnessMs: samples,
        prepareWitnessStats: stats(samples),
        prepareWitnessBytes: witness.byteLength,
      }, null, 2) + "\n"),
    ]);
    expect(witness.byteLength).toBeGreaterThan(1_000_000);
  }, 30 * 60_000);
});

async function buildBaseInputs(): Promise<Record<string, unknown>> {
  const scaffold = buildCredentialFixture({
    swiyuIssuerShape: true,
    vct: RESIDENCE_VCT,
  });
  const recorder = new RecordingWitnessGenerator();
  const wallet = new SwiyuZkpWallet({
    witnessGenerator: recorder,
    proofBackend: new BindingTestBackend(recorder),
  });
  const prepared = wallet.prepare({
    compactSdJwt: scaffold.compactSdJwt,
    issuerPublicKey: scaffold.issuerPublicKey,
  });
  const { snapshot, witness } = makeStatus();
  await wallet.show({
    prepared,
    challenge: makeChallenge(),
    holderSigner: holderSigner(),
    statusSnapshot: snapshot,
    statusWitness: witness,
    provingKey: new Uint8Array([1]),
  });
  if (!recorder.inputs) throw new Error("fixture did not produce base circuit inputs");
  return recorder.inputs;
}

interface CombinedOptions {
  salt?: string;
  municipalityBfs?: number;
  since?: string;
  reverseObjectKeys?: boolean;
  extraWhitespace?: boolean;
}

function buildCombinedFixture(options: CombinedOptions = {}): {
  jwt: string;
  disclosure: string;
  municipalityBfs: number;
} {
  const municipalityBfs = options.municipalityBfs
    ?? SWIYU_BENCHMARK_RESIDENCE.selectedMunicipalityBfs;
  const scaffold = buildCredentialFixture({
    swiyuIssuerShape: true,
    vct: RESIDENCE_VCT,
  });
  const [scaffoldJwt] = scaffold.compactSdJwt.split("~");
  const [header, payload] = scaffoldJwt!.split(".") as [string, string];
  const residence = options.reverseObjectKeys
    ? {
        since: options.since ?? SWIYU_BENCHMARK_RESIDENCE.residenceSince,
        municipality_bfs: municipalityBfs,
      }
    : {
        municipality_bfs: municipalityBfs,
        since: options.since ?? SWIYU_BENCHMARK_RESIDENCE.residenceSince,
      };
  let disclosureJson = JSON.stringify([
    options.salt ?? RESIDENCE_SALT,
    "residence",
    residence,
  ]);
  if (options.extraWhitespace) disclosureJson = disclosureJson.replace(/}\]$/, " }]");
  const disclosure = base64urlEncode(encoder.encode(disclosureJson));
  const payloadObject = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as {
    _sd: string[];
  };
  payloadObject._sd = [base64urlEncode(sha256(encoder.encode(disclosure)))];
  return {
    jwt: signJwt(
      Buffer.from(header, "base64url").toString("utf8"),
      JSON.stringify(payloadObject),
    ),
    disclosure,
    municipalityBfs,
  };
}

function combinedInputsFor(
  base: Record<string, unknown>,
  options: CombinedOptions,
): Record<string, unknown> {
  const fixture = buildCombinedFixture(options);
  return combinedPrepareInputs(
    base,
    fixture.jwt,
    fixture.disclosure,
    fixture.municipalityBfs,
  );
}

function combinedPrepareInputs(
  base: Record<string, unknown>,
  jwt: string,
  disclosure: string,
  municipalityBfs: number,
): Record<string, unknown> {
  const [header, payload, compactSignature] = jwt.split(".") as [string, string, string];
  const signingInput = `${header}.${payload}`;
  const [message, messageLength] = sha256Pad(encoder.encode(signingInput), 832);
  const [disclosurePadded] = sha256Pad(encoder.encode(disclosure), 128);
  const signature = p256.Signature.fromCompact(Buffer.from(compactSignature, "base64url"));
  const digest = base64urlEncode(sha256(encoder.encode(disclosure)));
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
    // JsonDigestArrayMember points at the member's opening quote.
    payloadResidenceDigestStart: payloadJson.indexOf(digest) - 1,
    issuerSigR: signature.r,
    issuerSigSInverse: modInverse(signature.s, P256_SCALAR_ORDER),
    residenceDisclosurePadded: Array.from(disclosurePadded, BigInt),
    residenceDisclosureLength: disclosure.length,
    residenceDisclosureJsonLength: Buffer.from(disclosure, "base64url").length,
    residenceDisclosureSaltLength: RESIDENCE_SALT.length,
    municipalityDigitLength: String(municipalityBfs).length,
    residenceDisclosureDigestB64: Array.from(encoder.encode(digest), BigInt),
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
  for (let index = 0; index < value.length; index++) {
    output[index] = BigInt(value.charCodeAt(index));
  }
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

async function calculate(inputs: Record<string, unknown>): Promise<Uint8Array> {
  // @ts-expect-error generated Circom module
  const imported = await import("../../assets/witness_calculator.js");
  const builder = imported.default ?? imported;
  const wasm = await readFile(join(
    circom,
    "build",
    "swiyu_residence_combined_prepare_compact",
    "swiyu_residence_combined_prepare_compact_js",
    "swiyu_residence_combined_prepare_compact.wasm",
  ));
  const calculator = await builder(wasm, { sanityCheck: true });
  return calculator.calculateWTNSBin(inputs, true);
}

function unstable(values: readonly number[]): boolean {
  if (values.length < 2) return false;
  const [first, second] = values;
  return Math.abs(first! - second!) / Math.max((first! + second!) / 2, 0.001) > 0.15;
}

function stats(values: readonly number[]) {
  const ordered = [...values].sort((a, b) => a - b);
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  const variance = values.reduce((sum, value) => sum + (value - mean) ** 2, 0)
    / Math.max(values.length - 1, 1);
  return {
    median: ordered[Math.floor(ordered.length / 2)],
    mean,
    standardDeviation: Math.sqrt(variance),
    coefficientOfVariation: mean === 0 ? 0 : Math.sqrt(variance) / mean,
    minimum: ordered[0],
    maximum: ordered.at(-1),
  };
}

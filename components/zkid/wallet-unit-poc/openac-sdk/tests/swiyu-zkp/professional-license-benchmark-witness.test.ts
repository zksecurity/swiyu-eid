import { describe, expect, it } from "vitest";
import { mkdir, readFile, writeFile } from "fs/promises";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

import { SwiyuZkpWallet } from "../../src/swiyu-zkp/wallet.js";
import { parseSwiyuCompactSdJwt } from "../../src/swiyu-zkp/parser.js";
import { hashSwiyuChallenge } from "../../src/swiyu-zkp/challenge.js";
import {
  P256_SCALAR_ORDER,
  base64urlToBigInt,
  modInverse,
  sha256Pad,
} from "../../src/utils.js";
import {
  buildProfessionalLicensePublicContext,
  buildProfessionalLicenseShowInputs,
} from "../../src/swiyu-zkp/professional-license.js";
import {
  computeSwiyuPreparedLookupCommitment,
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

const enabled = process.env.SWIYU_PROFESSIONAL_LICENSE_BENCHMARK === "1";
const here = dirname(fileURLToPath(import.meta.url));
const circom = join(here, "..", "..", "..", "circom");
const output = join(circom, "build", "swiyu_professional_license_benchmark");
const VCT = "urn:ch:professional-license:v1";
const ISSUER = "did:example:licen";
const REQUIRED_VALID_UNTIL = 1_760_000_000n;

describe.skipIf(!enabled)("professional-licence valid-through benchmark", () => {
  it("generates linked Prepare/Show witnesses and records three timing samples", async () => {
    // The scaffold drives the existing online status/signature helper only.
    // The actual Prepare witness below uses a professional credential whose
    // sole disclosure is `license_id`; no birthdate disclosure is present.
    const scaffold = buildCredentialFixture({
      swiyuIssuerShape: true,
      vct: VCT,
      issuer: ISSUER,
      exp: 1_800_000_000,
    });
    const fixture = buildCredentialFixture({
      swiyuIssuerShape: true,
      vct: VCT,
      issuer: ISSUER,
      exp: 1_800_000_000,
      disclosureName: "license_id",
      birthdate: "CH-MED-001",
    });
    const parsed = parseSwiyuCompactSdJwt(
      scaffold.compactSdJwt,
      scaffold.issuerPublicKey,
    );
    expect(parsed.lookup.vct).toBe(VCT);

    const challenge = makeChallenge();
    const { snapshot, witness: statusWitness } = makeStatus();
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
      statusWitness,
      provingKey: new Uint8Array([1]),
    });
    if (!recorder.inputs) throw new Error("fixture did not produce circuit inputs");

    // The verifier constructs these commitments from its accepted
    // issuer/kid/VCT lookup and selected session/status context. Consequently,
    // the professional-licence VCT is part of the proven public statement.
    const challengeHash = hashSwiyuChallenge(challenge).scalar;
    const policy = buildProfessionalLicensePublicContext({
      lookup: parsed.lookup,
      statusUri: parsed.statusUri,
      statusRoot: snapshot.root,
      challengeHash,
      currentTime: recorder.inputs.currentTime,
      requiredValidUntil: REQUIRED_VALID_UNTIL,
    });
    const lookup = computeSwiyuPreparedLookupCommitment(parsed.lookup);
    const uri = computeSwiyuPreparedStatusUriCommitment(parsed.statusUri);
    const signingInput = fixture.jwt.slice(0, fixture.jwt.lastIndexOf("."));
    const signature = Buffer.from(fixture.jwt.slice(fixture.jwt.lastIndexOf(".") + 1), "base64url");
    const [paddedSigningInput, paddedLength] = sha256Pad(
      new TextEncoder().encode(signingInput),
      896,
    );
    const prepareInputs = {
      ...recorder.inputs,
      message: Array.from(paddedSigningInput, BigInt),
      messageLength: paddedLength,
      issuerSigR: bytesToBigint(signature.subarray(0, 32)),
      issuerSigSInverse: modInverse(
        bytesToBigint(signature.subarray(32, 64)),
        P256_SCALAR_ORDER,
      ),
      disclosurePadded: Array<bigint>(128).fill(0n),
      disclosureLength: 0,
      disclosureJsonLength: 0,
      disclosureSaltLength: 0,
      disclosureDigestB64: Array<bigint>(43).fill(0n),
    };
    const showInputs = buildProfessionalLicenseShowInputs({
      holderKeyX: base64urlToBigInt(parsed.holderPublicKey.x),
      holderKeyY: base64urlToBigInt(parsed.holderPublicKey.y),
      preparedPredicateValue: 0n,
      credentialNbf: parsed.nbf,
      credentialExp: parsed.exp,
      statusIndex: parsed.statusIndex,
      lookupHashHi: lookup.hashHi,
      lookupHashLo: lookup.hashLo,
      statusUriHashHi: uri.hashHi,
      statusUriHashLo: uri.hashLo,
    }, {
      holderSigR: recorder.inputs.holderSigR,
      holderSigSInverse: recorder.inputs.holderSigSInverse,
      statusValue: recorder.inputs.statusValue,
      statusSiblings: recorder.inputs.statusSiblings,
      statusEpoch: recorder.inputs.statusEpoch,
      statusListLength: recorder.inputs.statusListLength,
    }, policy);

    const prepareSamples: number[] = [];
    const showSamples: number[] = [];
    let prepareWtns!: Uint8Array;
    let showWtns!: Uint8Array;
    const fixedRepetitions = process.env.SWIYU_PROFESSIONAL_LICENSE_RUNS === undefined
      ? undefined
      : Number.parseInt(process.env.SWIYU_PROFESSIONAL_LICENSE_RUNS, 10);
    if (fixedRepetitions !== undefined && fixedRepetitions < 1) {
      throw new Error("SWIYU_PROFESSIONAL_LICENSE_RUNS must be at least 1");
    }
    const initialRepetitions = fixedRepetitions ?? 2;
    for (let run = 0; run < initialRepetitions; run++) {
      let started = performance.now();
      prepareWtns = await calculate("swiyu_professional_license_prepare_compact", prepareInputs);
      prepareSamples.push(performance.now() - started);
      started = performance.now();
      showWtns = await calculate(
        "swiyu_professional_license_show_split",
        showInputs,
      );
      showSamples.push(performance.now() - started);
    }
    const expanded = fixedRepetitions === undefined &&
      (unstable(prepareSamples) || unstable(showSamples));
    const repetitions = fixedRepetitions ?? (expanded ? 7 : 3);
    for (let run = initialRepetitions; run < repetitions; run++) {
      let started = performance.now();
      prepareWtns = await calculate("swiyu_professional_license_prepare_compact", prepareInputs);
      prepareSamples.push(performance.now() - started);
      started = performance.now();
      showWtns = await calculate(
        "swiyu_professional_license_show_split",
        showInputs,
      );
      showSamples.push(performance.now() - started);
    }

    // A credential expiring before the verifier-selected project end cannot
    // produce a witness, even though it remains valid at currentTime.
    await expect(
      calculate("swiyu_professional_license_show_split", {
        ...showInputs,
        requiredValidUntil: 1_810_000_000n,
      }),
    ).rejects.toThrow();
    // This witness satisfies the complete Show relation independently, but its
    // issuer-authenticated expiry shared row differs from Prepare. Native proof
    // verification must succeed while the pair linkage check rejects it.
    const unlinkedShowWtns = await calculate(
      "swiyu_professional_license_show_split",
      { ...showInputs, credentialExp: 1_790_000_000n },
    );

    await mkdir(output, { recursive: true });
    await Promise.all([
      writeFile(join(output, "prepare-professional-license.wtns"), prepareWtns),
      writeFile(join(output, "show-professional-license.wtns"), showWtns),
      writeFile(join(output, "show-professional-license-unlinked.wtns"), unlinkedShowWtns),
      writeFile(
        join(output, "witness-runs.json"),
        JSON.stringify(
          {
            profile: "swiyu.professional-license-valid-through.v1",
            repetitions,
            expandedAfterFirstTwo: expanded,
            processPeakRssBytes: process.resourceUsage().maxRSS * 1024,
            vct: VCT,
            policy: {
              currentTime: recorder.inputs.currentTime,
              requiredValidUntil: REQUIRED_VALID_UNTIL,
              credentialExp: parsed.exp,
              statusRequired: "VALID (00)",
            },
            witnessGenerationMs: {
              prepare: prepareSamples,
              show: showSamples,
            },
          },
          (_key, value) => typeof value === "bigint" ? value.toString() : value,
          2,
        ),
      ),
    ]);
    expect(prepareWtns.byteLength).toBeGreaterThan(1_000_000);
    expect(showWtns.byteLength).toBeGreaterThan(1_000_000);
  }, 30 * 60_000);
});

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

function bytesToBigint(bytes: Uint8Array): bigint {
  return BigInt(`0x${Buffer.from(bytes).toString("hex")}`);
}

function unstable(samples: readonly number[]): boolean {
  const mean = (samples[0]! + samples[1]!) / 2;
  return Math.abs(samples[0]! - samples[1]!) / mean > 0.15;
}

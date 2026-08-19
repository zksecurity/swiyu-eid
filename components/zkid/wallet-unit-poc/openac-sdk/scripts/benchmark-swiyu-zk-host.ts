/**
 * Measures SDK-side work omitted from the Circom/Spartan core timings.
 * Real parsing, validation, status-path checking, public-context construction,
 * holder signing, and envelope creation run around deliberately fake
 * witness/proof boundaries. Results must be added separately and labelled;
 * they are not Circom or Spartan timings.
 */
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { deflateSync, inflateSync } from "node:zlib";
import { SwiyuZkpVerifier, SwiyuZkpWallet } from "../src/swiyu-zkp/wallet.js";
import { parseSwiyuCompactSdJwt } from "../src/swiyu-zkp/parser.js";
import { hashSwiyuChallenge } from "../src/swiyu-zkp/challenge.js";
import {
  SwiyuCantonEligibilityVerifier,
  SwiyuCantonEligibilityWallet,
  swiyuCantonShowPublicValues,
} from "../src/swiyu-zkp/canton-split.js";
import {
  SwiyuProfessionalLicenseVerifier,
  SwiyuProfessionalLicenseWallet,
  swiyuProfessionalLicenseShowPublicValues,
} from "../src/swiyu-zkp/professional-license-split.js";
import {
  SwiyuResidenceEligibilityVerifier,
  SwiyuResidenceEligibilityWallet,
  swiyuResidenceShowPublicValues,
} from "../src/swiyu-zkp/residence-split.js";
import { resolveSwiyuPackedStatusListJwt } from "../src/swiyu-zkp/residence-status.js";
import {
  SwiyuNullifierAge18Verifier,
  SwiyuNullifierAge18Wallet,
  swiyuNullifierAge18ShowPublicValues,
} from "../src/swiyu-zkp/nullifier-age18-split.js";
import { InMemorySwiyuNullifierRegistry } from "../src/swiyu-zkp/nullifier-registry.js";
import { SWIYU_BENCHMARK_NULLIFIER_SCOPE_IDS } from "../src/swiyu-zkp/nullifier-benchmark-manifest.js";
import {
  SWIYU_BENCHMARK_RESIDENCE,
  SWIYU_BENCHMARK_RESIDENCE_STATUS,
} from "../src/swiyu-zkp/residence-benchmark-manifest.js";
import { SWIYU_BENCHMARK_AGE_PACKED_STATUS_V2 } from "../src/swiyu-zkp/status-benchmark-manifest.js";
import {
  computeSwiyuPreparedStatusCommitment,
  computeSwiyuPreparedStatusUriCommitment,
} from "../src/swiyu-zkp/commitments.js";
import {
  SwiyuSplitZkpVerifier,
  SwiyuSplitZkpWallet,
  type SwiyuSplitProofBackend,
} from "../src/swiyu-zkp/split-proof.js";
import { concatBytes } from "../src/swiyu-zkp/encoding.js";
import {
  BindingTestBackend,
  CHECKED_IN_DID_TDW_KID,
  RecordingWitnessGenerator,
  buildCredentialFixture,
  holderSigner,
  makeChallenge,
  makeStatus,
  signJwt,
} from "../tests/swiyu-zkp/fixture.js";
import { base64urlEncode } from "../src/utils.js";

const RUNS = Number(arg("--runs") ?? "3");
const ADAPTIVE = process.argv.includes("--adaptive");
const ITERATIONS = Number(arg("--iterations") ?? "1000");
const OUTPUT = arg("--out");
const SYNTHETIC_PROOF_PAIR_BYTES = Number(arg("--proof-pair-bytes") ?? "292190");
const PREPARE_PROOF_BYTES = Number(arg("--prepare-proof-bytes") ?? String(Math.floor(SYNTHETIC_PROOF_PAIR_BYTES * 180055 / 292190)));
const SHOW_PROOF_BYTES = Number(arg("--show-proof-bytes") ?? String(SYNTHETIC_PROOF_PAIR_BYTES - PREPARE_PROOF_BYTES));
const PROFILE = parseProfile(arg("--profile") ?? "age");
type HostProfile = "age" | "canton" | "professional-license" | "residence" | "scoped-nullifier";

if (PREPARE_PROOF_BYTES + SHOW_PROOF_BYTES !== SYNTHETIC_PROOF_PAIR_BYTES) {
  throw new Error("prepare and show proof byte counts must sum to --proof-pair-bytes");
}

async function main() {
if (!process.argv.includes("--worker")) {
  const self = fileURLToPath(import.meta.url);
  const tsxLoader = fileURLToPath(
    new URL("../../circom/node_modules/tsx/dist/loader.mjs", import.meta.url),
  );
  const runWorker = (index: number) => {
    const workerArgv = [
      "--import", tsxLoader, self, "--worker",
      "--run", String(index + 1),
      "--iterations", String(ITERATIONS),
      "--profile", PROFILE,
      "--proof-pair-bytes", String(SYNTHETIC_PROOF_PAIR_BYTES),
      "--prepare-proof-bytes", String(PREPARE_PROOF_BYTES),
      "--show-proof-bytes", String(SHOW_PROOF_BYTES),
    ];
    const startedAt = new Date().toISOString();
    return {
      ...JSON.parse(execFileSync(process.execPath, workerArgv, {
        encoding: "utf8", maxBuffer: 16 * 1024 * 1024,
      })),
      processArgv: [process.execPath, ...workerArgv],
      startedAt,
      endedAt: new Date().toISOString(),
    };
  };
  const rawRuns = [runWorker(0), runWorker(1)];
  const firstTwoVaryOver15Percent = sdkVariationOver15Percent(rawRuns);
  const requiredRuns = ADAPTIVE ? (firstTwoVaryOver15Percent ? 7 : 3) : RUNS;
  while (rawRuns.length < requiredRuns) rawRuns.push(runWorker(rawRuns.length));
  if (rawRuns.some((run) => run.profile !== PROFILE)) {
    throw new Error(`SDK host worker profile does not match requested profile ${PROFILE}`);
  }
  const report = {
    schema: "swiyu.zk-sdk-host-orchestration.v1",
    profile: PROFILE,
    generatedAt: new Date().toISOString(),
    runtime: { node: process.version, platform: process.platform, arch: process.arch },
    runs: rawRuns.length,
    repetitionRule: {
      adaptive: ADAPTIVE,
      thresholdRelativeToFirstTwoMean: 0.15,
      firstTwoPrincipalStageVariationOver15Percent: firstTwoVaryOver15Percent,
      requiredRuns,
      satisfied: rawRuns.length === requiredRuns,
    },
    iterationsPerRun: ITERATIONS,
    warmupsPerWorker: 100,
    implementation: PROFILE === "age" ? {
      kind: "age full wallet path plus exact-sized split-envelope framing",
      exactProfileAdapter: false,
    } : {
      kind: "partial exact profile-specific split wallet and verifier adapter component",
      exactProfileAdapter: true,
    },
    boundary: {
      included: PROFILE === "age" ? [
          "SD-JWT parse and issuer verification",
          "challenge/status validation and status Merkle-witness verification",
          "public-context and circuit-input construction",
          "holder P-256 signing and self-verification",
          "SDK proof-envelope object construction",
          "exact-sized two-proof base64url/JSON envelope framing",
          "verifier public-context reconstruction with a fake proof verifier",
        ] : [
          "SD-JWT parse and issuer verification through the current common parser",
          "exact profile-specific verifier policy/public-context construction",
          "exact profile-specific split adapter validation and dispatch",
          "exact-sized Prepare/Show proof base64url envelope framing",
          "exact profile-specific verifier context reconstruction with a fake proof verifier",
        ],
      excluded: PROFILE === "age" ? [
          "Circom witness generation",
          "Spartan assignment, proof, setup, proof serialization/deserialization, and verification",
          "network and persistent storage I/O",
        ] : [
          "predicate-specific private witness-input construction",
          "holder signing and status Merkle-witness verification before the split adapter",
          "Circom witness generation",
          "Spartan assignment, proof, setup, proof serialization/deserialization, and verification",
          "network and persistent storage I/O",
        ],
      caveat: PROFILE === "age"
        ? "age wallet.show uses a recording witness generator and binding fake proof backend; exact two-proof framing is measured separately"
        : "partial adapter component only: exact profile policy/context/dispatch/framing, but missing private input, holder-signing, and status-witness orchestration must not be presented as full SDK overhead",
    },
    syntheticProofPairBytes: SYNTHETIC_PROOF_PAIR_BYTES,
    prepareProofBytes: PREPARE_PROOF_BYTES,
    showProofBytes: SHOW_PROOF_BYTES,
    exactProofFramingIncludedInShow: PROFILE !== "age",
    rawRuns,
    summary: summarize(rawRuns),
  };
  const rendered = `${JSON.stringify(report, null, 2)}\n`;
  if (OUTPUT) writeFileSync(OUTPUT, rendered);
  process.stdout.write(rendered);
} else {
  process.stdout.write(`${JSON.stringify(await worker(Number(arg("--run") ?? "1")))}\n`);
}
}

async function worker(run: number) {
  return PROFILE === "age" ? workerAge(run) : workerSplit(run, PROFILE);
}

async function workerAge(run: number) {
  const fixture = buildCredentialFixture({ swiyuIssuerShape: true });
  const challenge = makeChallenge();
  const { snapshot, authoritativeSnapshot, witness: statusWitness } = makeStatus();
  const recorder = new RecordingWitnessGenerator();
  const backend = new BindingTestBackend(recorder);
  const wallet = new SwiyuZkpWallet({ witnessGenerator: recorder, proofBackend: backend });
  const verifier = new SwiyuZkpVerifier(backend);
  const prepareRequest = {
    compactSdJwt: fixture.compactSdJwt,
    issuerPublicKey: fixture.issuerPublicKey,
  };
  let prepared = wallet.prepare(prepareRequest);
  const showRequest = () => ({
    prepared,
    challenge,
    holderSigner: holderSigner(),
    statusSnapshot: snapshot,
    statusWitness,
    provingKey: new Uint8Array([1]),
  });
  let envelope = await wallet.show(showRequest());
  const verifyRequest = () => ({
    envelope,
    challenge,
    issuerPublicKey: fixture.issuerPublicKey,
    statusSnapshot: authoritativeSnapshot,
    verifyingKey: new Uint8Array([1]),
  });

  for (let index = 0; index < 100; index++) {
    prepared = wallet.prepare(prepareRequest);
    envelope = await wallet.show(showRequest());
    JSON.stringify(envelope);
    const result = await verifier.verify(verifyRequest());
    if (!result.valid) throw new Error(result.error ?? "warm-up verification failed");
    frameSyntheticProofPair(PREPARE_PROOF_BYTES, SHOW_PROOF_BYTES);
  }

  const prepare = measureSync(ITERATIONS, () => {
    prepared = wallet.prepare(prepareRequest);
  });
  const show = await measureAsync(ITERATIONS, async () => {
    envelope = await wallet.show(showRequest());
  });
  const envelopeObjectJson = measureSync(ITERATIONS, () => {
    JSON.stringify(envelope);
  });
  const exactSizedProofPairFraming = measureSync(ITERATIONS, () => {
    frameSyntheticProofPair(PREPARE_PROOF_BYTES, SHOW_PROOF_BYTES);
  });
  const verify = await measureAsync(ITERATIONS, async () => {
    const result = await verifier.verify(verifyRequest());
    if (!result.valid) throw new Error(result.error ?? "fake-boundary verification failed");
  });

  return {
    profile: "age" as const,
    implementationProfile: "swiyu.age-over-18.status.v1",
    run,
    iterations: ITERATIONS,
    timings: {
      perCredentialPrepareSdk: prepare,
      perPresentationShowSdkWithFakeBoundaries: show,
      perPresentationEnvelopeObjectJson: envelopeObjectJson,
      exactSizedProofPairFraming: exactSizedProofPairFraming,
      perPresentationVerifierSdkWithFakeBoundary: verify,
    },
    sizes: {
      sdkEnvelopeObjectJsonBytes: Buffer.byteLength(JSON.stringify(envelope)),
      syntheticProofPairRawBytes: SYNTHETIC_PROOF_PAIR_BYTES,
      syntheticProofPairBase64urlBytes: Buffer.from(new Uint8Array(SYNTHETIC_PROOF_PAIR_BYTES)).toString("base64url").length,
      syntheticProofPairFramedJsonBytes: Buffer.byteLength(frameSyntheticProofPair(PREPARE_PROOF_BYTES, SHOW_PROOF_BYTES)),
      transmittedEnvelopeJsonBytes: Buffer.byteLength(frameSyntheticProofPair(PREPARE_PROOF_BYTES, SHOW_PROOF_BYTES)),
    },
    processPeakRssBytes: process.resourceUsage().maxRSS * 1024,
  };
}

async function workerSplit(run: number, profile: Exclude<HostProfile, "age">) {
  const vct = profile === "canton"
    ? "https://example.ch/vct/person"
    : profile === "professional-license"
      ? "urn:ch:professional-license:v1"
      : profile === "residence"
        ? SWIYU_BENCHMARK_RESIDENCE.vct
        : "https://example.ch/vct/person";
  const fixture = buildCredentialFixture({
    swiyuIssuerShape: true,
    vct,
    ...(profile === "professional-license" ? { issuer: "did:example:licen" } : {}),
  });
  const { snapshot } = makeStatus();
  const baseChallenge = makeChallenge();
  const challengeHash = hashSwiyuChallenge(baseChallenge).scalar;
  const backend = new SizedBindingSplitBackend(PREPARE_PROOF_BYTES, SHOW_PROOF_BYTES);
  const splitWallet = new SwiyuSplitZkpWallet(backend);
  const splitVerifier = new SwiyuSplitZkpVerifier(backend);
  const key = new Uint8Array([1]);
  let parsed = parseSwiyuCompactSdJwt(fixture.compactSdJwt, fixture.issuerPublicKey);
  const residenceStatusResolution = profile === "residence"
    ? resolveResidenceStatus(
        fixture.statusUri,
        parsed.statusIndex,
        fixture.issuerPublicKey,
        baseChallenge.currentTime,
      )
    : undefined;
  const residenceStatus = residenceStatusResolution?.verifierStatus;
  const policy = profile === "canton" ? {
    challengeHash,
    currentTime: 1_750_000_000n,
    acceptedLookup: parsed.lookup,
    authoritativeStatusUri: snapshot.uri,
    statusSnapshotRoot: snapshot.root,
    allowedCantons: ["ZH", "BE"] as const,
  } : profile === "professional-license" ? {
    challengeHash,
    currentTime: 1_750_000_000n,
    requiredValidUntil: 1_760_000_000n,
    acceptedLookup: parsed.lookup,
    authoritativeStatusUri: snapshot.uri,
    statusSnapshotRoot: snapshot.root,
  } : profile === "residence" ? {
    baseChallengeHash: challengeHash,
    currentTime: baseChallenge.currentTime,
    acceptedLookup: parsed.lookup,
    trustedStatus: residenceStatus!,
    ...SWIYU_BENCHMARK_RESIDENCE.policy,
  } : {
    baseChallenge,
    scope: SWIYU_BENCHMARK_NULLIFIER_SCOPE_IDS,
    acceptedLookup: parsed.lookup,
    authoritativeStatusCommitment: computeSwiyuPreparedStatusCommitment(
      computeSwiyuPreparedStatusUriCommitment(snapshot.uri),
      SWIYU_BENCHMARK_AGE_PACKED_STATUS_V2.snapshotRoot,
    ),
  };
  const wallet = profile === "canton"
    ? new SwiyuCantonEligibilityWallet(splitWallet)
    : profile === "professional-license"
      ? new SwiyuProfessionalLicenseWallet(splitWallet)
      : profile === "residence"
        ? new SwiyuResidenceEligibilityWallet(splitWallet)
        : new SwiyuNullifierAge18Wallet(splitWallet);
  const nullifierRegistry = profile === "scoped-nullifier"
    ? new InMemorySwiyuNullifierRegistry()
    : undefined;
  const verifier = profile === "canton"
    ? new SwiyuCantonEligibilityVerifier(splitVerifier)
    : profile === "professional-license"
      ? new SwiyuProfessionalLicenseVerifier(splitVerifier)
      : profile === "residence"
        ? new SwiyuResidenceEligibilityVerifier(splitVerifier)
        : new SwiyuNullifierAge18Verifier(
          splitVerifier,
          nullifierRegistry!,
        );
  const publicNullifier = new Uint8Array(32).fill(0x45);
  let prepared: any;
  let envelope: any;

  const prepareOperation = async () => {
    parsed = parseSwiyuCompactSdJwt(fixture.compactSdJwt, fixture.issuerPublicKey);
    prepared = await wallet.prepare({
      lookup: parsed.lookup,
      issuerPubKeyX: parsed.baseInputs.issuerPubKeyX,
      issuerPubKeyY: parsed.baseInputs.issuerPubKeyY,
      prepareWitness: publicWitness([
        parsed.baseInputs.issuerPubKeyX,
        parsed.baseInputs.issuerPubKeyY,
      ]),
      prepareProvingKey: key,
    } as any);
  };
  const showOperation = async () => {
    const showValues = profile === "canton"
      ? swiyuCantonShowPublicValues(policy as any)
      : profile === "professional-license"
        ? swiyuProfessionalLicenseShowPublicValues(policy as any)
        : profile === "residence"
          ? swiyuResidenceShowPublicValues(policy as any)
          : swiyuNullifierAge18ShowPublicValues(policy as any, publicNullifier);
    envelope = await wallet.show({
      prepared,
      policy,
      ...(profile === "scoped-nullifier" ? { nullifier: publicNullifier } : {}),
      showWitness: concatBytes(showValues),
      showProvingKey: key,
    } as any);
    assertSplitEnvelopeIdentity(envelope, profile);
  };
  const verifyOperation = async () => {
    const result = await verifier.verify({
      envelope,
      policy,
      issuerPubKeyX: parsed.baseInputs.issuerPubKeyX,
      issuerPubKeyY: parsed.baseInputs.issuerPubKeyY,
      prepareVerifyingKey: key,
      showVerifyingKey: key,
    } as any);
    if (!result.valid) throw new Error(result.error ?? `${profile} split verification failed`);
  };
  let claimSequence = 0;
  const verifyThenClaimOperation = profile === "scoped-nullifier"
    ? async () => {
        const nullifier = indexedNullifier(++claimSequence);
        const claimEnvelope = {
          ...envelope,
          nullifier: base64urlEncode(nullifier),
        };
        const result = await (verifier as SwiyuNullifierAge18Verifier).verifyAndClaim({
          envelope: claimEnvelope,
          policy: policy as any,
          issuerPubKeyX: parsed.baseInputs.issuerPubKeyX,
          issuerPubKeyY: parsed.baseInputs.issuerPubKeyY,
          prepareVerifyingKey: key,
          showVerifyingKey: key,
        });
        if (!result.valid || !result.accepted) {
          throw new Error(result.error ?? "scoped-nullifier verify-then-claim orchestration failed");
        }
      }
    : undefined;

  await prepareOperation();
  await showOperation();
  await verifyOperation();
  let invalidProofLeavesRegistryUnchanged: boolean | undefined;
  if (profile === "scoped-nullifier") {
    const sizeBeforeInvalidProof = nullifierRegistry!.size;
    const invalid = await (verifier as SwiyuNullifierAge18Verifier).verifyAndClaim({
      envelope: {
        ...envelope,
        showProof: envelope.showProof.slice(0, -2),
      },
      policy: policy as any,
      issuerPubKeyX: parsed.baseInputs.issuerPubKeyX,
      issuerPubKeyY: parsed.baseInputs.issuerPubKeyY,
      prepareVerifyingKey: key,
      showVerifyingKey: key,
    });
    invalidProofLeavesRegistryUnchanged = !invalid.valid
      && !invalid.accepted
      && nullifierRegistry!.size === sizeBeforeInvalidProof;
    if (!invalidProofLeavesRegistryUnchanged) {
      throw new Error("invalid scoped-nullifier proof mutated the in-memory registry");
    }
  }
  for (let index = 0; index < 100; index++) {
    await prepareOperation();
    await showOperation();
    JSON.stringify(envelope);
    await verifyOperation();
    if (verifyThenClaimOperation) await verifyThenClaimOperation();
  }

  const prepare = await measureAsync(ITERATIONS, prepareOperation);
  const show = await measureAsync(ITERATIONS, showOperation);
  const envelopeObjectJson = measureSync(ITERATIONS, () => JSON.stringify(envelope));
  const exactSizedProofPairFraming = measureSync(ITERATIONS, () => JSON.stringify(envelope));
  const verify = await measureAsync(ITERATIONS, verifyOperation);
  const verifyThenClaim = verifyThenClaimOperation
    ? await measureAsync(ITERATIONS, verifyThenClaimOperation)
    : undefined;
  if (profile === "scoped-nullifier" && nullifierRegistry!.size !== 100 + ITERATIONS) {
    throw new Error("scoped-nullifier verify-then-claim benchmark lost or duplicated a unique claim");
  }
  const envelopeJsonBytes = Buffer.byteLength(JSON.stringify(envelope));
  return {
    profile,
    implementationProfile: envelope.profile,
    circuitIds: {
      prepare: envelope.prepareCircuitId,
      show: envelope.showCircuitId,
    },
    run,
    iterations: ITERATIONS,
    timings: {
      perCredentialPrepareSdk: prepare,
      perPresentationShowSdkWithFakeBoundaries: show,
      perPresentationEnvelopeObjectJson: envelopeObjectJson,
      exactSizedProofPairFraming,
      perPresentationVerifierSdkWithFakeBoundary: verify,
      ...(verifyThenClaim ? {
        perPresentationVerifyThenClaimSdkWithFakeProofBoundaryAndInMemoryRegistry:
          verifyThenClaim,
      } : {}),
    },
    sizes: {
      sdkEnvelopeObjectJsonBytes: envelopeJsonBytes,
      syntheticProofPairRawBytes: PREPARE_PROOF_BYTES + SHOW_PROOF_BYTES,
      syntheticProofPairBase64urlBytes: envelope.prepareProof.length + envelope.showProof.length,
      syntheticProofPairFramedJsonBytes: envelopeJsonBytes,
      transmittedEnvelopeJsonBytes: envelopeJsonBytes,
    },
    ...(profile === "scoped-nullifier" ? {
      verifyThenClaimBoundary: {
        classification: "SDK orchestration supplement",
        proofVerification: "deliberately fake proof backend, identical to the other SDK host timings",
        registry: "process-local InMemorySwiyuNullifierRegistry with a unique scoped nullifier per operation",
        excludes: "SQLite, durable I/O, transaction commit, and concurrency; those remain in the separately measured nullifier-state harness",
        ordering: "SwiyuNullifierAge18Verifier.verifyAndClaim verifies both proof halves before insertVerifiedClaim",
      },
      correctness: {
        invalidProofLeavesRegistryUnchanged,
        acceptedUniqueClaims: nullifierRegistry!.size,
        expectedAcceptedUniqueClaims: 100 + ITERATIONS,
      },
    } : {}),
    ...(residenceStatusResolution ? {
      authenticatedStatusBoundary: {
        classification: "untimed authenticated fixture setup",
        encoding: "statuslist+jwt with packed two-bit statuses",
        listLength: residenceStatusResolution.verifierStatus.listLength,
        epoch: residenceStatusResolution.verifierStatus.epoch,
        snapshotRoot: residenceStatusResolution.privateSnapshot.root,
        treeProfile: residenceStatusResolution.verifierStatus.treeProfile,
        nativeWitnessRootContract:
          "same all-VALID packed bytes, list length, epoch, and packed-chunk v2 ternary construction; exact root must match",
      },
    } : {}),
    processPeakRssBytes: process.resourceUsage().maxRSS * 1024,
  };
}

class SizedBindingSplitBackend implements SwiyuSplitProofBackend {
  constructor(
    private readonly prepareProofBytes: number,
    private readonly showProofBytes: number,
  ) {}

  async prepare(request: { witness: Uint8Array }) {
    const publicValues = splitScalars(request.witness, 2);
    return { handle: { publicValues }, publicValues };
  }

  async proveLinked(request: { preparedHandle: unknown; showWitness: Uint8Array }) {
    const preparePublic = (request.preparedHandle as { publicValues: Uint8Array[] }).publicValues;
    const showPublic = splitScalars(request.showWitness, request.showWitness.length / 32);
    const sharedCommitment = new Uint8Array(32).fill(0xa5);
    return {
      prepare: {
        proof: new Uint8Array(this.prepareProofBytes).fill(0x31),
        publicValues: preparePublic,
        sharedCommitment,
      },
      show: {
        proof: new Uint8Array(this.showProofBytes).fill(0x32),
        publicValues: showPublic,
        sharedCommitment,
      },
    };
  }

  async verifyProof(request: {
    circuitId: string;
    proof: Uint8Array;
    expectedPublicValues: readonly Uint8Array[];
  }) {
    const expectedBytes = request.circuitId.includes("prepare")
      ? this.prepareProofBytes
      : this.showProofBytes;
    const valid = request.proof.length === expectedBytes;
    return {
      valid,
      publicValues: request.expectedPublicValues.map((value) => new Uint8Array(value)),
      sharedCommitment: new Uint8Array(32).fill(0xa5),
      error: valid ? undefined : "exact-sized fake proof length mismatch",
    };
  }
}

function assertSplitEnvelopeIdentity(envelope: any, profile: Exclude<HostProfile, "age">) {
  const expected = profile === "canton" ? {
    profile: "swiyu.canton-eligibility.prepare-show.v1",
    prepare: "swiyu_canton_prepare_compact",
    show: "swiyu_canton_show_split",
  } : profile === "professional-license" ? {
    profile: "swiyu.professional-license-valid-through.v1",
    prepare: "swiyu_professional_license_prepare_compact",
    show: "swiyu_professional_license_show_split",
  } : profile === "residence" ? {
    profile: "swiyu.residence-eligibility.combined-disclosure.v1",
    prepare: "swiyu_residence_combined_prepare_compact",
    show: "swiyu_residence_show_packed_chunk_v2",
  } : {
    profile: "swiyu.age-over-18.scoped-nullifier.v1",
    prepare: "swiyu_nullifier_age18_prepare",
    show: "swiyu_nullifier_age18_show_packed_chunk_v2",
  };
  if (envelope.profile !== expected.profile || envelope.prepareCircuitId !== expected.prepare ||
      envelope.showCircuitId !== expected.show) {
    throw new Error(`${profile} split envelope identity mismatch`);
  }
}

function splitScalars(bytes: Uint8Array, count: number) {
  if (!Number.isInteger(count) || count < 1 || bytes.length !== count * 32) {
    throw new Error("fake split witness does not contain complete public scalars");
  }
  return Array.from({ length: count }, (_, index) =>
    bytes.slice(index * 32, (index + 1) * 32));
}

function publicWitness(values: readonly bigint[]) {
  return concatBytes(values.map((value) => {
    const bytes = new Uint8Array(32);
    let remaining = value;
    for (let index = 0; index < 32; index++) {
      bytes[index] = Number(remaining & 0xffn);
      remaining >>= 8n;
    }
    return bytes;
  }));
}

function frameSyntheticProofPair(prepareBytes: number, showBytes: number) {
  return JSON.stringify({
    version: "swiyu.split-proof-envelope.v1",
    profile: "swiyu.age-over-18.packed-status-chunk.v2",
    prepareCircuitId: "swiyu_age18_prepare_compact",
    showCircuitId: "swiyu_age18_show_packed_chunk_v2",
    prepareProof: Buffer.from(new Uint8Array(prepareBytes)).toString("base64url"),
    showProof: Buffer.from(new Uint8Array(showBytes)).toString("base64url"),
    lookup: {
      issuer: "did:example:issuer",
      kid: "did:example:issuer#key-1",
      vct: "https://example.ch/vct/person",
    },
  });
}

function indexedNullifier(index: number): Uint8Array {
  if (!Number.isSafeInteger(index) || index < 1) {
    throw new Error("scoped-nullifier benchmark index must be a positive safe integer");
  }
  const value = new Uint8Array(32);
  new DataView(value.buffer).setBigUint64(24, BigInt(index), false);
  return value;
}

function resolveResidenceStatus(
  subject: string,
  credentialStatusIndex: number,
  issuerPublicKey: ReturnType<typeof buildCredentialFixture>["issuerPublicKey"],
  currentTime: bigint,
) {
  const iat = SWIYU_BENCHMARK_RESIDENCE_STATUS.epoch;
  if (currentTime < BigInt(iat) || currentTime >= BigInt(iat + 300)) {
    throw new Error("residence host currentTime is outside the frozen status snapshot");
  }
  const packed = new Uint8Array(
    SWIYU_BENCHMARK_RESIDENCE_STATUS.listLength / 4,
  );
  const compactJwt = signJwt(
    JSON.stringify({
      alg: "ES256",
      kid: CHECKED_IN_DID_TDW_KID,
      typ: "statuslist+jwt",
      profile_version: "swiss-profile-vc:1.0.0",
    }),
    JSON.stringify({
      iss: "did:example:issuer",
      sub: subject,
      iat,
      exp: iat + 600,
      ttl: 300,
      status_list: {
        bits: 2,
        lst: base64urlEncode(new Uint8Array(deflateSync(packed, { level: 9 }))),
      },
    }),
  );
  const resolved = resolveSwiyuPackedStatusListJwt({
    compactJwt,
    issuerPublicKey,
    expectedIssuer: "did:example:issuer",
    expectedSubject: subject,
    credentialStatusIndex,
    currentTime,
    inflateZlib(compressed, maxOutputBytes) {
      return new Uint8Array(
        inflateSync(compressed, { maxOutputLength: maxOutputBytes }),
      );
    },
  });
  if (
    resolved.verifierStatus.listLength !== SWIYU_BENCHMARK_RESIDENCE_STATUS.listLength
    || resolved.verifierStatus.epoch !== SWIYU_BENCHMARK_RESIDENCE_STATUS.epoch
    || resolved.privateSnapshot.root
      !== SWIYU_BENCHMARK_RESIDENCE_STATUS.packedV2.snapshotRoot
    || resolved.verifierStatus.treeProfile
      !== SWIYU_BENCHMARK_RESIDENCE_STATUS.packedV2.treeProfile
  ) {
    throw new Error("authenticated residence status does not match the benchmark manifest");
  }
  return resolved;
}

function measureSync(iterations: number, operation: () => unknown) {
  const cpuBefore = process.cpuUsage();
  const wallBefore = process.hrtime.bigint();
  for (let index = 0; index < iterations; index++) operation();
  return elapsed(iterations, wallBefore, cpuBefore);
}

async function measureAsync(iterations: number, operation: () => Promise<unknown>) {
  const cpuBefore = process.cpuUsage();
  const wallBefore = process.hrtime.bigint();
  for (let index = 0; index < iterations; index++) await operation();
  return elapsed(iterations, wallBefore, cpuBefore);
}

function elapsed(iterations: number, wallBefore: bigint, cpuBefore: NodeJS.CpuUsage) {
  const wallNs = Number(process.hrtime.bigint() - wallBefore);
  const cpu = process.cpuUsage(cpuBefore);
  return {
    wallMsPerOperation: wallNs / 1e6 / iterations,
    cpuMsPerOperation: (cpu.user + cpu.system) / 1000 / iterations,
    totalWallMs: wallNs / 1e6,
    totalCpuMs: (cpu.user + cpu.system) / 1000,
  };
}

function summarize(runs: Array<Record<string, any>>) {
  return Object.fromEntries(Object.keys(runs[0].timings).map((stage) => [stage, {
    wallMs: stats(runs.map((run) => run.timings[stage].wallMsPerOperation)),
    cpuMs: stats(runs.map((run) => run.timings[stage].cpuMsPerOperation)),
  }]));
}

function sdkVariationOver15Percent(runs: Array<Record<string, any>>) {
  return Object.keys(runs[0].timings).some((stage) => {
    const first = runs[0].timings[stage].wallMsPerOperation;
    const second = runs[1].timings[stage].wallMsPerOperation;
    const mean = (first + second) / 2;
    return mean !== 0 && Math.abs(first - second) / mean > 0.15;
  });
}

function stats(values: number[]) {
  const sorted = [...values].sort((a, b) => a - b);
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  const variance = values.length > 1
    ? values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / (values.length - 1)
    : 0;
  const standardDeviation = Math.sqrt(variance);
  return {
    samples: values,
    min: sorted[0],
    median: sorted[Math.floor(sorted.length / 2)],
    max: sorted.at(-1),
    mean,
    variance,
    standardDeviation,
    coefficientOfVariation: mean === 0 ? 0 : standardDeviation / mean,
  };
}

function arg(name: string) {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}

function parseProfile(value: string): HostProfile {
  if (
    value === "age"
    || value === "canton"
    || value === "professional-license"
    || value === "residence"
    || value === "scoped-nullifier"
  ) return value;
  throw new Error(`unsupported SDK host profile: ${value}`);
}

await main();

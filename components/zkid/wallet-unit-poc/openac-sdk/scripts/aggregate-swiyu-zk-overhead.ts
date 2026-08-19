/** Consolidate raw same-host SD-JWT controls and repeated age-ZK runs. */
import { readFileSync, writeFileSync } from "node:fs";

const output = required("--out");
const rawDir = required("--raw-dir");
const zkRunCount = Number(arg("--zk-runs") ?? "7");
const zkHost = arg("--zk-host") ? readJson(required("--zk-host")) : undefined;
const professionalZkWitness = arg("--professional-zk-witness")
  ? readJson(required("--professional-zk-witness"))
  : undefined;
const controls = Object.fromEntries(
  ["age-over-18", "resident-canton", "professional-license"].flatMap((profile) => {
    const path = arg(`--${profile}-control`);
    return path ? [[profile, readJson(path)]] : [];
  }),
);

const ageZkRawRuns = Array.from({ length: zkRunCount }, (_, offset) => {
  const run = offset + 1;
  const native = readJson(`${rawDir}/zk-run-${run}.json`);
  const fixture = readJson(`${rawDir}/zk-witness-${run}.json`);
  return {
    run,
    witnessGenerationWallMs: fixture.witnessGenerationMs,
    native,
    lifecycleWallMs: {
      oneTimeCircuitSetup: native.prepare.setup_ms + native.show.setup_ms,
      perCredentialReusableWork:
        fixture.witnessGenerationMs.prepare + native.prepare.assignment_ms,
      perPresentationWalletWork:
        native.prepare.final_proof_ms +
        fixture.witnessGenerationMs.show +
        native.show.assignment_ms +
        native.show.final_proof_ms,
      perPresentationVerifierWork:
        native.prepare.verify_ms + native.show.verify_ms,
      firstPresentationWalletWork:
        fixture.witnessGenerationMs.prepare +
        native.prepare.assignment_ms +
        native.prepare.final_proof_ms +
        fixture.witnessGenerationMs.show +
        native.show.assignment_ms +
        native.show.final_proof_ms,
    },
  };
});

const first = ageZkRawRuns[0].native;
const professionalSemanticParity = assertProfessionalSemanticParity(
  controls["professional-license"], professionalZkWitness,
);
const report = {
  schema: "swiyu.zk-overhead-benchmark.v1",
  generatedAt: new Date().toISOString(),
  methodology: {
    host: "same local arm64 macOS host",
    noZk: "3 fresh Node workers per profile, 1000 operations per worker; wall and process CPU measured",
    zk: `${zkRunCount} fresh native process runs; Circom witness wall time measured separately; native stage figures are wall-clock, not CPU time`,
    varianceRule: "After two ZK runs, expand from 3 to 7 if any principal stage differs by more than 15% relative to their mean.",
    varianceRuleTriggeredBy: "Prepare witness generation differed by more than 15%; later Show/native variation independently confirmed expansion was appropriate.",
    excluded: [
      "DID document and status-list network retrieval (trust material is preloaded for both paths)",
      "Circom compilation, a developer/build-time artifact-generation step",
      "application HTTP, JSON request routing, database, and UI overhead",
    ],
  },
  semanticComparison: {
    issuerAuthentication: {
      noZk: "Verifier checks issuer ES256 on each received SD-JWT presentation.",
      zk: "Prepare proves issuer ES256 and authenticated parsing; each presentation transmits a freshly linked Prepare proof.",
    },
    holderBinding: {
      noZk: "Standard ES256 kb+jwt binds nonce, audience, iat, and sd_hash.",
      zk: "Holder ES256 signature binds the canonical challenge digest; the Show relation binds challenge metadata.",
      caveat: "Both provide holder possession and replay/context binding, but the signed wire objects differ.",
    },
    status: {
      noZk: "Verifier performs an O(1) lookup in a preloaded status-list byte array.",
      zk: "Show verifies a Merkle authentication path and VALID value against a fresh public status commitment.",
      caveat: "Fetching and authenticating the upstream status object/root is excluded in both measurements.",
    },
    agePredicate: {
      noZk: "The standard control selectively discloses age_over_18=true.",
      zk: "The birthdate and cutoff comparison stay private; only successful proof verification is exposed.",
    },
  },
  noZkControls: controls,
  professionalSemanticParity,
  ageZk: {
    rawRuns: ageZkRawRuns,
    summary: summarizeZk(ageZkRawRuns),
    stableArtifactBytes: {
      prepare: stableArtifacts(first.prepare),
      show: stableArtifacts(first.show),
      combined: {
        r1cs: first.prepare.r1cs_bytes + first.show.r1cs_bytes,
        wasm: first.prepare.wasm_bytes + first.show.wasm_bytes,
        witness: first.prepare.witness_bytes + first.show.witness_bytes,
        provingKeys: first.prepare.proving_key_bytes + first.show.proving_key_bytes,
        verifyingKeys: first.prepare.verifying_key_bytes + first.show.verifying_key_bytes,
        transmittedProofPair: first.prepare.final_proof_bytes + first.show.final_proof_bytes,
        reusablePrepareState:
          first.prepare.pre_reblind_instance_bytes + first.prepare.assignment_bytes,
      },
    },
  },
  zkSdkHostOrchestration: zkHost,
  directAgeComparison: buildDirectAgeComparison(
    controls["age-over-18"], ageZkRawRuns, first, zkHost,
  ),
};

writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`);

function assertProfessionalSemanticParity(control: any, witness: any) {
  if (!control || !witness) return { checked: false };
  const standard = control.policy;
  const zk = witness.policy;
  const normalized = {
    acceptedVct: witness.vct,
    requiredValidUntil: Number(zk.requiredValidUntil),
    statusRequired: zk.statusRequired,
  };
  for (const key of ["acceptedVct", "requiredValidUntil", "statusRequired"]) {
    if (standard[key] !== normalized[key]) {
      throw new Error(
        `professional semantic mismatch for ${key}: control=${standard[key]} zk=${normalized[key]}`,
      );
    }
  }
  return { checked: true, standard, zk: normalized, equal: true };
}

function summarizeZk(runs: any[]) {
  const stagePaths = {
    prepareWitness: (run: any) => run.witnessGenerationWallMs.prepare,
    showWitness: (run: any) => run.witnessGenerationWallMs.show,
    prepareSetup: (run: any) => run.native.prepare.setup_ms,
    showSetup: (run: any) => run.native.show.setup_ms,
    prepareAssignment: (run: any) => run.native.prepare.assignment_ms,
    showAssignment: (run: any) => run.native.show.assignment_ms,
    prepareFinalProof: (run: any) => run.native.prepare.final_proof_ms,
    showFinalProof: (run: any) => run.native.show.final_proof_ms,
    prepareVerify: (run: any) => run.native.prepare.verify_ms,
    showVerify: (run: any) => run.native.show.verify_ms,
    oneTimeCircuitSetup: (run: any) => run.lifecycleWallMs.oneTimeCircuitSetup,
    perCredentialReusableWork: (run: any) => run.lifecycleWallMs.perCredentialReusableWork,
    perPresentationWalletWork: (run: any) => run.lifecycleWallMs.perPresentationWalletWork,
    perPresentationVerifierWork: (run: any) => run.lifecycleWallMs.perPresentationVerifierWork,
    firstPresentationWalletWork: (run: any) => run.lifecycleWallMs.firstPresentationWalletWork,
    processPeakRssBytes: (run: any) => run.native.process_peak_rss_bytes,
  };
  return Object.fromEntries(
    Object.entries(stagePaths).map(([name, get]) => [name, stats(runs.map(get))]),
  );
}

function buildDirectAgeComparison(control: any, zkRuns: any[], first: any, host: any) {
  if (!control) return undefined;
  const noZk = {
    oneTimeSetupWallMs: control.summary.oneTimeTrustMaterialSetup.wallMs.median,
    oneTimeSetupCpuMs: control.summary.oneTimeTrustMaterialSetup.cpuMs.median,
    perCredentialWalletWallMs: control.summary.perCredentialReusableWalletPreparation.wallMs.median,
    perCredentialWalletCpuMs: control.summary.perCredentialReusableWalletPreparation.cpuMs.median,
    perPresentationWalletWallMs: control.summary.perPresentationWallet.wallMs.median,
    perPresentationWalletCpuMs: control.summary.perPresentationWallet.cpuMs.median,
    perPresentationVerifierWallMs: control.summary.perPresentationVerifier.wallMs.median,
    perPresentationVerifierCpuMs: control.summary.perPresentationVerifier.cpuMs.median,
    transmittedBytes: control.rawRuns[0].sizes.transmittedPresentationBytes,
    reusableCredentialStorageBytes: control.rawRuns[0].sizes.preparedCredentialStorageBytes,
    processPeakRssBytes: stats(control.rawRuns.map((run: any) => run.processPeakRssBytes)),
  };
  const summary = summarizeZk(zkRuns);
  const hostPrepare = host?.summary.perCredentialPrepareSdk.wallMs.median ?? 0;
  const hostShow = host?.summary.perPresentationShowSdkWithFakeBoundaries.wallMs.median ?? 0;
  const hostFraming = host?.summary.exactSizedProofPairFraming.wallMs.median ?? 0;
  const hostVerify = host?.summary.perPresentationVerifierSdkWithFakeBoundary.wallMs.median ?? 0;
  const zk = {
    oneTimeSetupWallMs: summary.oneTimeCircuitSetup.median,
    perCredentialWalletWallMs:
      summary.perCredentialReusableWork.median + hostPrepare,
    perPresentationWalletWallMs:
      summary.perPresentationWalletWork.median + hostShow + hostFraming,
    perPresentationVerifierWallMs:
      summary.perPresentationVerifierWork.median + hostVerify,
    transmittedBytes: first.prepare.final_proof_bytes + first.show.final_proof_bytes,
    reusableCredentialStorageBytes:
      first.prepare.pre_reblind_instance_bytes + first.prepare.assignment_bytes,
    processPeakRssBytes: summary.processPeakRssBytes,
    cpuTiming: "not instrumented; native stage values are wall-clock",
    breakdown: {
      cryptoCoreWallMs: {
        perCredential: summary.perCredentialReusableWork.median,
        perPresentationWallet: summary.perPresentationWalletWork.median,
        perPresentationVerifier: summary.perPresentationVerifierWork.median,
      },
      sdkHostWallMs: {
        perCredentialPrepare: hostPrepare,
        perPresentationShowWithFakeBoundaries: hostShow,
        exactSizedProofPairFraming: hostFraming,
        perPresentationVerifierWithFakeBoundary: hostVerify,
      },
      caveat: host
        ? "SDK host timings use fake witness/proof boundaries and are added separately to crypto-core medians."
        : "No SDK host-orchestration report was supplied; totals equal crypto-core timings only.",
    },
  };
  return {
    noZk,
    zk,
    medianOverheadRatios: {
      oneTimeSetup: zk.oneTimeSetupWallMs / noZk.oneTimeSetupWallMs,
      perCredentialWallet: zk.perCredentialWalletWallMs / noZk.perCredentialWalletWallMs,
      perPresentationWallet: zk.perPresentationWalletWallMs / noZk.perPresentationWalletWallMs,
      perPresentationVerifier: zk.perPresentationVerifierWallMs / noZk.perPresentationVerifierWallMs,
      transmittedBytes: zk.transmittedBytes / noZk.transmittedBytes,
      reusableCredentialStorage: zk.reusableCredentialStorageBytes / noZk.reusableCredentialStorageBytes,
    },
  };
}

function stableArtifacts(stage: any) {
  return {
    constraints: stage.constraints,
    wires: stage.wires,
    r1cs: stage.r1cs_bytes,
    wasm: stage.wasm_bytes,
    witness: stage.witness_bytes,
    provingKey: stage.proving_key_bytes,
    verifyingKey: stage.verifying_key_bytes,
    proof: stage.final_proof_bytes,
  };
}

function stats(values: number[]) {
  const sorted = [...values].sort((a, b) => a - b);
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  const variance = values.length > 1
    ? values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / (values.length - 1)
    : 0;
  const standardDeviation = Math.sqrt(variance);
  const middle = Math.floor(sorted.length / 2);
  const median = sorted.length % 2
    ? sorted[middle]
    : (sorted[middle - 1] + sorted[middle]) / 2;
  return {
    samples: values,
    min: sorted[0],
    median,
    max: sorted.at(-1),
    mean,
    variance,
    standardDeviation,
    coefficientOfVariation: mean === 0 ? 0 : standardDeviation / mean,
  };
}

function readJson(path: string) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function required(name: string) {
  const value = arg(name);
  if (!value) throw new Error(`missing ${name}`);
  return value;
}

function arg(name: string) {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}

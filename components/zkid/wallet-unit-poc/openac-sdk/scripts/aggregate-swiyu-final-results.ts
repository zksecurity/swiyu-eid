/** Aggregate pinned-container evidence, including auxiliary new-profile controls. */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";

const root = required("--results-root");
const output = arg("--out") ?? `${root}/zk-overhead-results.json`;
const metadata = json(`${root}/metadata.json`);
validateProvenance(metadata);
const productionVerifierDocument = json(`${root}/raw/production-control/age-over-18.json`);
validateProductionVerifierControl(productionVerifierDocument, metadata);
const hostDocuments = Object.fromEntries(["age", "canton", "residence", "scoped-nullifier"].map((profile) => {
  const document = json(`${root}/raw/sdk-host/${profile}.json`);
  validateSdkHostRuns(profile, document);
  return [profile, document];
}));

const profiles = [
  aggregateProfile("age-over-18", "age"),
  aggregateProfile("resident-canton", "canton"),
  aggregateProfile("authoritative-residence-exact", "residence"),
  aggregateProfile("scoped-nullifier", "scoped-nullifier"),
];
const controlStudies = aggregateControlStudies();
const ageProfile = profiles.find((profile) => profile.profile === "age-over-18")!;
const nullifierProfile = profiles.find((profile) => profile.profile === "scoped-nullifier")!;
const residenceProfile = profiles.find((profile) =>
  profile.profile === "authoritative-residence-exact")!;
for (const profile of profiles.filter((value) => value.profile !== "resident-canton")) {
  const statusPreprocessing = composePackedStatusPreprocessing(profile);
  profile.directComparisonExcludingRequiredStatusPathDiagnostic =
    profile.directComparison;
  profile.directComparison =
    statusPreprocessing.directComparisonWithCachedAuthenticatedSnapshot;
  profile.zkStatusPreprocessing = statusPreprocessing;
}
nullifierProfile.directComparison.firstAcceptedClaimWithCommonDurableState =
  composeFirstAcceptedClaimWithState(
    nullifierProfile.directComparison,
    controlStudies.scopedNullifier.commonStateTransition,
  );

const report = {
  schema: "swiyu.final-container-zk-overhead.v3",
  classification: "final-container-candidate",
  generatedAt: new Date().toISOString(),
  methodology: {
    rawProcessModel: "fresh witness process plus fresh native process per ZK raw run; fresh Node worker per control raw run",
    runRule: "first two; 3 total unless any principal witness/native stage differs by >15% relative to their mean, then 7",
    execution: "strictly serialized round robin in one pinned offline ARM64 container and one fixed cpuset/memory envelope; replay concurrency is an isolated correctness/operational supplement",
    sdkHost: "adaptive 3/7 fresh workers x 1000 operations after 100 warmups; fake witness/proof boundaries, reported separately",
    timing: "all lifecycle totals are sums of independently timed components, not end-to-end latency; headline no-ZK/ZK ratios use the first measured operation from each fresh worker with fixtures and relation artifacts already materialized (and potentially page-cached), not an OS/storage cold start; the separately retained no-ZK steady-state summary uses 100 warmups and 1,000 timed operations",
    units: { timing: "milliseconds", storageAndTransmission: "bytes", memory: "bytes" },
  },
  provenance: {
    metadataSchema: metadata.schema,
    image: metadata.image,
    limits: metadata.limits,
    source: metadata.source,
    productionVerifierSource: metadata.productionVerifierSource,
    aggregationRecovery: metadata.aggregationRecovery,
    startedAt: metadata.startedAt,
    completedBeforeAggregation: metadata.completed,
  },
  productionVerifierControl: {
    role: "independent production swiyu over-18 verifier-core baseline; shown beside, never pooled with, the matched modeled-wallet full-path baseline because their lifecycle boundaries differ",
    implementation: productionVerifierDocument.implementation,
    boundary: productionVerifierDocument.rawRuns[0].boundary,
    policy: productionVerifierDocument.policy,
    repetitionRule: productionVerifierDocument.repetitionRule,
    iterationsPerRun: productionVerifierDocument.iterationsPerRun,
    warmupsPerRun: productionVerifierDocument.warmupsPerRun,
    exactSizes: productionVerifierDocument.exactSizes,
    processPeakRssBytes: productionVerifierDocument.processPeakRssBytes,
    summary: productionVerifierDocument.summary,
  },
  sdkHostOrchestration: hostDocuments,
  over18BaselineComparisons: {
    modeledWalletNoZkVersusNativeZkCore: ageProfile.directComparison,
    productionVerifierCore: ageProfile.productionOver18VerifierCoreComparison,
    legacyMonolithicAgeSdkSensitivity: ageProfile.zk.sdkHostComponent,
    interpretation: "The modeled no-ZK control and native packed-v2 relation provide the primary overhead ratio. The production swiyu verifier is a real but differently bounded over-18 verifier core. The existing monolithic age SDK timing is retained only as a non-composable sensitivity because it routes through swiyu_age18_status_2k, not the packed-v2 Prepare/Show adapter.",
  },
  profiles,
  marginalComparisons: {
    scopedNullifierVersusBaseAgeZk: marginalProfileComparison(
      ageProfile,
      nullifierProfile,
    ),
  },
  controlStudies,
};
writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`);

function aggregateControlStudies() {
  const exactResidence = readControlStudy("authoritative-residence-exact");
  const derivedResidence = readControlStudy("authoritative-residence-derived");
  const scopedNullifier = readControlStudy("scoped-nullifier");
  const state = json(`${root}/raw/nullifier-state/state.json`);
  validateNullifierState(state, scopedNullifier.policy);
  return {
    authoritativeResidence: {
      primaryExactPolicyControl: exactResidence,
      secondaryIssuerDerivedControl: derivedResidence,
      interpretation: "The exact-policy control matches verifier-owned municipality-list and whole-day duration evaluation but discloses the signed details. The derived control hides them but delegates policy evaluation/freshness to the issuer; it is a sensitivity control, not a substitute.",
      zkProfile: "See profiles[authoritative-residence-exact] for the matched native lifecycle and exact artifact comparison.",
    },
    scopedNullifier: {
      standardControl: scopedNullifier,
      commonStateTransition: {
        store: state.store,
        semantics: state.semantics,
        repetitionRule: state.repetitionRule,
        summary: state.summary,
        concurrency: state.concurrency,
        correctness: state.correctness,
        exactSizes: state.rawRuns[0].sizes,
        processPeakRssBytes: stats(state.rawRuns.map((run: any) => run.processPeakRssBytes)),
      },
      interpretation: "The ordinary SD-JWT control reveals a random credential UID; the ZK profile proves the UID plus wallet-secret commitment and exposes only the scoped nullifier. Both pay the identical post-verification atomic state transition. The report separately compares the integrated profile against base age ZK.",
      zkIntegrationPoint: "Compose firstClaimStateTransition onto the stateless verifier only after successful proof verification; invalid proofs must never mutate state.",
    },
  };
}

function readControlStudy(profile: string) {
  const control = json(`${root}/raw/controls/${profile}.json`);
  validateControlRuns(profile, control);
  return {
    profile,
    semantics: control.semantics,
    policy: control.policy,
    repetitionRule: control.repetitionRule,
    coldSummary: control.coldSummary,
    summary: control.summary,
    exactSizes: control.rawRuns[0].sizes,
    correctness: control.rawRuns.map((run: any) => run.correctness),
    processPeakRssBytes: stats(control.rawRuns.map((run: any) => run.processPeakRssBytes)),
  };
}

function validateNullifierState(state: any, controlPolicy: any) {
  const runs = state.rawRuns;
  const stages = state.repetitionRule?.principalStages;
  const requiredCorrectness = [
    "sequentialReplay",
    "injectedFailureRollsBackBothRows",
    "sameNullifierRacesExactlyOneWinner",
    "distinctNullifiersAllAccepted",
    "everyRaceWorkerUsesFullSynchronous",
    "everyRaceHasActualOverlap",
  ];
  if (state.schema !== "swiyu.nullifier-state-benchmark.v2" || !Array.isArray(runs) || runs.length < 2 ||
      !Array.isArray(stages) || stages.length === 0 ||
      state.store?.atomicClaim !== "BEGIN IMMEDIATE; insert spent key; insert paired accepted claim; COMMIT" ||
      state.store?.journalMode !== "WAL" || state.store?.synchronous !== "FULL") {
    throw new Error("scoped-nullifier state benchmark has an invalid schema or store contract");
  }
  const expanded = stages.some((stage: string) => relativeDelta(
    runs[0].timings?.[stage]?.wallMsPerOperation,
    runs[1].timings?.[stage]?.wallMsPerOperation,
  ) > 0.15);
  const expected = expanded ? 7 : 3;
  if (state.repetitionRule.expanded !== expanded || state.repetitionRule.requiredRuns !== expected || runs.length !== expected ||
      requiredCorrectness.some((field) => state.correctness?.[field] !== true) ||
      state.semantics?.scopeDigest !== controlPolicy?.scope?.digest ||
      state.semantics?.registryNamespaceId !== controlPolicy?.scope?.registryNamespaceId) {
    throw new Error("scoped-nullifier state benchmark failed repetition or replay/concurrency invariants");
  }
}

function aggregateProfile(controlName: string, zkName: string) {
  const control = json(`${root}/raw/controls/${controlName}.json`);
  validateControlRuns(controlName, control);
  const zkDir = `${root}/raw/${zkName}`;
  const rule = json(`${zkDir}/repetition-rule.json`);
  const runs = Array.from({ length: rule.requiredRuns }, (_, offset) =>
    normalizeRun(zkName, zkDir, offset + 1));
  validateZkRuns(zkName, rule, runs);
  assertExactSizesConsistent(zkName, runs);
  const parity = assertSemanticParity(controlName, control, runs[0].witnessDocument);
  runs.slice(1).forEach((run, index) => assertEqual(
    assertSemanticParity(controlName, control, run.witnessDocument),
    parity,
    `${controlName} semantic parity in ZK run ${index + 2}`,
  ));
  const lifecycle = summarizeLifecycle(runs);
  const exactArtifacts = artifacts(runs[0]);
  const hostDocument = hostDocuments[zkName];
  const hostComponent = hostDocument
    ? sdkHostComponent(zkName, hostDocument, exactArtifacts.combined.rawProofPair)
    : undefined;
  if (zkName === "residence") {
    const expectedStatus = runs[0].witnessDocument.policy.statusSnapshot.packedV2;
    for (const [index, hostRun] of hostDocument.rawRuns.entries()) {
      assertEqual(hostRun.authenticatedStatusBoundary, {
        classification: "untimed authenticated fixture setup",
        encoding: "statuslist+jwt with packed two-bit statuses",
        listLength: runs[0].witnessDocument.policy.statusSnapshot.listLength,
        epoch: runs[0].witnessDocument.policy.statusSnapshot.epoch,
        snapshotRoot: expectedStatus.root,
        treeProfile: expectedStatus.treeProfile,
        nativeWitnessRootContract:
          "same all-VALID packed bytes, list length, epoch, and packed-chunk v2 ternary construction; exact root must match",
      }, `residence SDK authenticated status boundary run ${index + 1}`);
    }
  }
  const direct = hostComponent?.composableWithNativeLifecycle
    ? directComparison(control, lifecycle, hostComponent, exactArtifacts)
    : directNativeComparison(control, lifecycle, exactArtifacts);
  const productionOver18VerifierCoreComparison = zkName === "age"
    ? compareAgeVerifierBaselines(control, lifecycle, hostComponent)
    : undefined;
  return {
    profile: controlName,
    semanticParity: parity,
    repetitionRule: rule,
    standardControl: {
      policy: control.policy,
      semantics: control.semantics,
      repetitionRule: control.repetitionRule,
      coldSummary: control.coldSummary,
      steadyStateSummary: control.summary,
      exactSizes: control.rawRuns[0].sizes,
      processPeakRssBytes: stats(control.rawRuns.map((run: any) => run.processPeakRssBytes)),
    },
    zk: {
      sdkHostComponent: hostComponent,
      lifecycle,
      exactArtifacts,
      processPeakRssBytes: {
        witnessProcess: stats(runs.map((run) => run.witnessPeakRssBytes)),
        nativeProductionProcess: stats(runs.map((run) => run.nativePeakRssBytes)),
        conservativePerRunMaximum: stats(runs.map((run) =>
          Math.max(run.witnessPeakRssBytes, run.nativePeakRssBytes))),
        ...(hostComponent ? { sdkHostProcess: hostComponent.processPeakRssBytes } : {}),
        conservativeMaximumAcrossAllMeasuredProcesses: Math.max(
          ...runs.map((run) => Math.max(run.witnessPeakRssBytes, run.nativePeakRssBytes)),
          ...(hostComponent ? [hostComponent.processPeakRssBytes.max] : []),
        ),
        interpretation: "separate fresh processes; maximum is a conservative non-concurrent lifecycle bound, not additive RSS",
      },
      normalizedRawRuns: runs.map(({ witnessDocument, nativeDocument, ...run }) => run),
    },
    directComparison: direct,
    ...(productionOver18VerifierCoreComparison
      ? { productionOver18VerifierCoreComparison }
      : {}),
  };
}

function compareAgeVerifierBaselines(control: any, lifecycle: any, hostPart: any) {
  const modeledWalletMs = control.coldSummary.perPresentationVerifier.wallMs.median;
  const productionVerifierMs = productionVerifierDocument.summary.wallMs.median;
  const zkNativeMs = lifecycle.perPresentationVerifierComponentSum.median;
  return {
    interpretation: "verifier-core comparison under documented but non-identical boundaries: the modeled-wallet value is a first operation in a fresh process; the production swiyu verifier value is a warmed 1,000-operation core benchmark with preloaded adapters. The old monolithic SDK measurement is not added to the packed-v2 native result.",
    wallMsPerPresentation: {
      modeledWalletBaseline: modeledWalletMs,
      productionSwiyuVerifierCore: productionVerifierMs,
      zkMeasuredNativeComponents: zkNativeMs,
      nonComposableLegacyMonolithicAgeSdkVerifierSensitivity:
        hostPart.perPresentationVerifierWallMs,
    },
    ratios: {
      productionVerifierToModeledWalletBaseline: productionVerifierMs / modeledWalletMs,
      zkMeasuredNativeComponentsToProductionVerifier: zkNativeMs / productionVerifierMs,
    },
    boundaryQualification: productionVerifierDocument.implementation.qualification,
  };
}

function normalizeRun(profile: string, dir: string, run: number) {
  const witnessDocument = json(`${dir}/witness-${run}.json`);
  const nativeDocument = json(`${dir}/native-${run}.json`);
  const genericSplit = nativeDocument.exact_sizes !== undefined;
  const native = genericSplit
    ? (nativeDocument.raw_runs?.[0] ?? nativeDocument.rawRuns?.[0])
    : nativeDocument;
  if (!native) throw new Error(`${profile} native-${run}.json is not a fixed single-run report`);
  if (profile === "canton" &&
      (witnessDocument.prepareWitnessMs?.length !== 1 || witnessDocument.showWitnessMs?.length !== 1 ||
       nativeDocument.raw_runs?.length !== 1)) {
    throw new Error(`${profile} run ${run} contains nested repetitions instead of one fresh-process sample`);
  }
  if (genericSplit && nativeDocument.raw_runs?.length !== 1) {
    throw new Error(`${profile} run ${run} contains nested repetitions instead of one fresh-process sample`);
  }
  const primaryWitnessShow = witnessDocument.witnessGenerationMs?.showPackedV2
    ?? witnessDocument.witnessGenerationMs?.show;
  const witness = profile === "age"
    ? {
        prepare: oneFreshSample(witnessDocument.witnessGenerationMs?.prepare,
          `${profile} Prepare witness`),
        show: oneFreshSample(primaryWitnessShow, `${profile} packed-v2 Show witness`),
      }
    : profile === "canton"
      ? { prepare: witnessDocument.prepareWitnessMs[0], show: witnessDocument.showWitnessMs[0] }
      : {
          prepare: oneFreshSample(witnessDocument.witnessGenerationMs?.prepare,
            `${profile} Prepare witness`),
          show: oneFreshSample(primaryWitnessShow, `${profile} packed-v2 Show witness`),
        };
  const sizes = genericSplit
    ? nativeDocument.exact_sizes
    : { prepare: native.prepare, show: native.show };
  const nativePeakRssBytes = genericSplit
    ? nativeDocument.production_peak_rss_bytes
    : native.process_peak_rss_bytes;
  const witnessPeakRssBytes = witnessDocument.processPeakRssBytes;
  assertOptimizedCircuitIdentity(profile, nativeDocument, witnessDocument);
  assertNativeValidity(profile, native, nativeDocument);
  return {
    run,
    witnessWallMs: witness,
    prepare: native.prepare,
    show: native.show,
    sizes,
    witnessPeakRssBytes,
    nativePeakRssBytes,
    linkage: native.linkage ?? {
      linked_commitments_equal: native.linked_commitments_equal,
      link_randomness_ms: native.link_randomness_ms,
    },
    timestamps: {
      witnessCommand: profile === "residence"
        ? {
            showControl: commandRecord(`residence-show-control-witness-${run}`),
            optimizedPrepare: commandRecord(`residence-optimized-prepare-witness-${run}`),
          }
        : commandRecord(`${profile}-witness-${run}`),
      nativeCommand: commandRecord(`${profile}-native-${run}`),
    },
    witnessDocument,
    nativeDocument,
    ...(witnessDocument.statusSnapshotStagesMs ? {
      packedStatusStagesMs: {
        packedV2TreeBuild: oneFreshSample(
          witnessDocument.statusSnapshotStagesMs.packedV2TreeBuild,
          "residence packed-v2 status tree build",
        ),
        packedV2PathGeneration: oneFreshSample(
          witnessDocument.statusSnapshotStagesMs.packedV2PathGeneration,
          "residence packed-v2 status path",
        ),
      },
    } : {}),
  };
}

function oneFreshSample(value: unknown, label: string): number {
  if (Array.isArray(value)) {
    if (value.length !== 1) throw new Error(`${label} must contain one fresh-process sample`);
    value = value[0];
  }
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`${label} is not a finite timing sample`);
  }
  return value;
}

function assertOptimizedCircuitIdentity(profile: string, native: any, witness: any) {
  const expected: Record<string, { profile: string; prepare: string; show: string }> = {
    age: {
      profile: "swiyu.age-over-18.packed-status-chunk.v2",
      prepare: "swiyu_age18_prepare_compact",
      show: "swiyu_age18_show_packed_chunk_v2",
    },
    canton: {
      profile: "swiyu.canton-eligibility.prepare-show.v1",
      prepare: "swiyu_canton_prepare_compact",
      show: "swiyu_canton_show_split",
    },
    residence: {
      profile: "swiyu.residence-eligibility.combined-disclosure.v1",
      prepare: "swiyu_residence_combined_prepare_compact",
      show: "swiyu_residence_show_packed_chunk_v2",
    },
    "scoped-nullifier": {
      profile: "swiyu.age-over-18.scoped-nullifier.v1",
      prepare: "swiyu_nullifier_age18_prepare",
      show: "swiyu_nullifier_age18_show_packed_chunk_v2",
    },
  };
  const identity = expected[profile];
  if (!identity || native.profile !== identity.profile ||
      native.prepare_circuit !== identity.prepare || native.show_circuit !== identity.show) {
    throw new Error(`${profile} native run does not use the optimized circuit identity`);
  }
  if (profile === "canton") return;
  const packed = profile === "residence"
    ? witness.policy?.primaryStatusProfile
    : witness.policy?.packedStatusShow;
  if (packed?.circuitId !== identity.show ||
      packed?.profile !== (profile === "residence"
        ? "swiyu.residence-eligibility.packed-status-chunk.v2"
        : profile === "age"
          ? "swiyu.age-over-18.packed-status-chunk.v2"
          : "swiyu.age-over-18.scoped-nullifier.packed-status-chunk.v2")) {
    throw new Error(`${profile} witness metadata does not bind the optimized Show profile`);
  }
}

function summarizeLifecycle(runs: any[]) {
  const raw = runs.map((run) => ({
    run: run.run,
    oneTimeCircuitSetupCoreComponentSum: run.prepare.setup_ms + run.show.setup_ms,
    oneTimeKeySerializationComponentSum:
      run.prepare.key_serialization_ms + run.show.key_serialization_ms,
    oneTimeSetupPlusKeySerializationToSinkComponentSum:
      run.prepare.setup_ms + run.show.setup_ms +
      run.prepare.key_serialization_ms + run.show.key_serialization_ms,
    perCredentialReusableCoreComponentSum:
      run.witnessWallMs.prepare + run.prepare.witness_handoff_ms + run.prepare.assignment_ms,
    optionalPreparedStateSerializationToSinkComponentSum:
      run.prepare.prepared_state_serialization_ms,
    perCredentialWithPreparedStateSerializationToSinkComponentSum:
      run.witnessWallMs.prepare + run.prepare.witness_handoff_ms + run.prepare.assignment_ms +
      run.prepare.prepared_state_serialization_ms,
    perPresentationWalletComponentSum:
      run.linkage.link_randomness_ms +
      run.prepare.final_proof_ms + run.prepare.proof_serialization_ms +
      run.witnessWallMs.show + run.show.witness_handoff_ms + run.show.assignment_ms +
      run.show.final_proof_ms + run.show.proof_serialization_ms,
    perPresentationVerifierComponentSum:
      run.prepare.proof_deserialization_ms + run.prepare.verify_ms +
      run.show.proof_deserialization_ms + run.show.verify_ms,
    firstPresentationWalletWithoutPreparedStateSerializationComponentSum:
      run.witnessWallMs.prepare + run.prepare.witness_handoff_ms + run.prepare.assignment_ms +
      run.linkage.link_randomness_ms +
      run.prepare.final_proof_ms + run.prepare.proof_serialization_ms +
      run.witnessWallMs.show + run.show.witness_handoff_ms + run.show.assignment_ms +
      run.show.final_proof_ms + run.show.proof_serialization_ms,
  }));
  const summarized = Object.fromEntries(
    Object.keys(raw[0]).filter((key) => key !== "run")
      .map((key) => [key, stats(raw.map((run: any) => run[key]))]),
  );
  return {
    raw,
    interpretation: "component-sum estimates from separately timed boundaries; not a single end-to-end latency sample. Key and prepared-state serialization timings encode to an I/O sink and do not include file writes, flush, fsync, atomic replacement, or durable storage latency.",
    ...summarized,
    principalStages: {
      prepareWitness: stats(runs.map((run) => run.witnessWallMs.prepare)),
      showWitness: stats(runs.map((run) => run.witnessWallMs.show)),
      prepareWitnessHandoff: stats(runs.map((run) => run.prepare.witness_handoff_ms)),
      showWitnessHandoff: stats(runs.map((run) => run.show.witness_handoff_ms)),
      prepareSetup: stats(runs.map((run) => run.prepare.setup_ms)),
      showSetup: stats(runs.map((run) => run.show.setup_ms)),
      prepareKeySerialization: stats(runs.map((run) => run.prepare.key_serialization_ms)),
      showKeySerialization: stats(runs.map((run) => run.show.key_serialization_ms)),
      prepareAssignment: stats(runs.map((run) => run.prepare.assignment_ms)),
      showAssignment: stats(runs.map((run) => run.show.assignment_ms)),
      prepareStateSerialization: stats(runs.map((run) => run.prepare.prepared_state_serialization_ms)),
      showStateSerializationDiagnostic: stats(runs.map((run) => run.show.prepared_state_serialization_ms)),
      linkRandomness: stats(runs.map((run) => run.linkage.link_randomness_ms)),
      prepareFinalProof: stats(runs.map((run) => run.prepare.final_proof_ms)),
      showFinalProof: stats(runs.map((run) => run.show.final_proof_ms)),
      prepareProofSerialization: stats(runs.map((run) => run.prepare.proof_serialization_ms)),
      showProofSerialization: stats(runs.map((run) => run.show.proof_serialization_ms)),
      prepareProofDeserialization: stats(runs.map((run) => run.prepare.proof_deserialization_ms)),
      showProofDeserialization: stats(runs.map((run) => run.show.proof_deserialization_ms)),
      prepareVerify: stats(runs.map((run) => run.prepare.verify_ms)),
      showVerify: stats(runs.map((run) => run.show.verify_ms)),
      ...(runs[0].packedStatusStagesMs ? {
        perStatusSnapshotPackedV2TreeBuild: stats(runs.map((run) =>
          run.packedStatusStagesMs.packedV2TreeBuild)),
        perCredentialPackedV2StatusPathGeneration: stats(runs.map((run) =>
          run.packedStatusStagesMs.packedV2PathGeneration)),
      } : {}),
    },
  };
}

function sdkHostComponent(profile: string, report: any, expectedProofPairBytes: number) {
  const summary = report.summary;
  if (report.profile !== profile || report.rawRuns.some((run: any) => run.profile !== profile)) {
    throw new Error(`${profile} SDK host output is mislabeled`);
  }
  if (profile !== "age" && report.implementation.exactProfileAdapter !== true) {
    throw new Error(`${profile} did not exercise its exact profile-specific split adapter`);
  }
  if (report.syntheticProofPairBytes !== expectedProofPairBytes) {
    throw new Error(`${profile} SDK framing size does not match the native proof-pair size`);
  }
  if (profile === "scoped-nullifier" && report.rawRuns.some((run: any) =>
    run.correctness?.invalidProofLeavesRegistryUnchanged !== true ||
    run.correctness?.acceptedUniqueClaims !==
      run.correctness?.expectedAcceptedUniqueClaims)) {
    throw new Error("scoped-nullifier SDK host violated verify-then-claim ordering");
  }
  const framedSizes = report.rawRuns.map((run: any) => run.sizes.transmittedEnvelopeJsonBytes);
  if (new Set(framedSizes).size !== 1) throw new Error(`${profile} framed proof size changed across workers`);
  return {
    composableWithNativeLifecycle: profile !== "age",
    applicability: profile === "age"
      ? "non-composable sensitivity: current monolithic age SDK path uses swiyu_age18_status_2k; only its separately timed exact-size split-envelope framing is representation-matched to the packed-v2 proof pair"
      : "partial exact profile-specific split adapter component: exact public policy/context/dispatch/framing, excluding private input, holder-signing, and status-witness orchestration",
    implementation: report.implementation,
    perCredentialPrepareWallMs: summary.perCredentialPrepareSdk.wallMs.median,
    perPresentationShowWallMs: summary.perPresentationShowSdkWithFakeBoundaries.wallMs.median,
    exactSizedProofPairFramingWallMs: summary.exactSizedProofPairFraming.wallMs.median,
    exactProofFramingIncludedInShow: report.exactProofFramingIncludedInShow,
    exactSizedProofPairRawBytes: expectedProofPairBytes,
    exactSizedProofPairFramedJsonBytes: framedSizes[0],
    perPresentationVerifierWallMs: summary.perPresentationVerifierSdkWithFakeBoundary.wallMs.median,
    ...(profile === "scoped-nullifier" ? {
      verifyThenClaimInMemoryRegistrySupplement: {
        wallMs: summary
          .perPresentationVerifyThenClaimSdkWithFakeProofBoundaryAndInMemoryRegistry
          .wallMs,
        correctness: report.rawRuns.map((run: any) => run.correctness),
        boundary: "SDK ordering/orchestration supplement only; excludes SQLite, durable I/O, transaction commit, and concurrency",
      },
    } : {}),
    processPeakRssBytes: stats(report.rawRuns.map((run: any) => run.processPeakRssBytes)),
    caveat: report.boundary.caveat,
  };
}

function directComparison(control: any, lifecycle: any, hostPart: any, artifacts: any) {
  const baseline = control.coldSummary;
  const noZk = {
    oneTimeSetupWallMs: baseline.oneTimeTrustMaterialSetup.wallMs.median,
    perCredentialWalletWallMs: baseline.perCredentialReusableWalletPreparation.wallMs.median,
    perPresentationWalletWallMs: baseline.perPresentationWallet.wallMs.median,
    perPresentationVerifierWallMs: baseline.perPresentationVerifier.wallMs.median,
    transmittedBytes: control.rawRuns[0].sizes.transmittedPresentationBytes,
  };
  const core = {
    oneTimeSetupWallMs:
      lifecycle.oneTimeSetupPlusKeySerializationToSinkComponentSum.median,
    perCredentialWalletWallMs: lifecycle.perCredentialReusableCoreComponentSum.median,
    perPresentationWalletWallMs: lifecycle.perPresentationWalletComponentSum.median,
    perPresentationVerifierWallMs: lifecycle.perPresentationVerifierComponentSum.median,
  };
  const withHost = {
    oneTimeSetupWallMs: core.oneTimeSetupWallMs,
    perCredentialWalletWallMs: core.perCredentialWalletWallMs + hostPart.perCredentialPrepareWallMs,
    perPresentationWalletWallMs:
      core.perPresentationWalletWallMs + hostPart.perPresentationShowWallMs +
      (hostPart.exactProofFramingIncludedInShow ? 0 : hostPart.exactSizedProofPairFramingWallMs),
    perPresentationVerifierWallMs:
      core.perPresentationVerifierWallMs + hostPart.perPresentationVerifierWallMs,
    transmittedBytes: hostPart.exactSizedProofPairFramedJsonBytes,
  };
  return {
    interpretation: "direct ratios compare medians of first-measured-operation fresh-worker no-ZK stages with fresh-worker ZK component sums; fixtures and relation artifacts already exist and may be page-cached, so these are not OS/storage cold starts; ZK SDK figures remain boundary-qualified and are not end-to-end latency samples",
    noZk,
    noZkWarmedSteadyStateSensitivity: control.summary,
    zkMeasuredNativeComponents: core,
    zkWithMeasuredSdkComponentsEstimate: withHost,
    sdkHostApplicability: hostPart.applicability,
    storageInventories: unmatchedStorageInventories(control, artifacts),
    overheadRatios: {
      measuredNativeComponents: ratios(noZk, { ...core,
        transmittedBytes: artifacts.combined.rawProofPair,
      }),
      withMeasuredSdkComponentsEstimate: ratios(noZk, withHost),
    },
  };
}

function directNativeComparison(control: any, lifecycle: any, artifacts: any) {
  const baseline = control.coldSummary;
  const noZk = {
    oneTimeSetupWallMs: baseline.oneTimeTrustMaterialSetup.wallMs.median,
    perCredentialWalletWallMs: baseline.perCredentialReusableWalletPreparation.wallMs.median,
    perPresentationWalletWallMs: baseline.perPresentationWallet.wallMs.median,
    perPresentationVerifierWallMs: baseline.perPresentationVerifier.wallMs.median,
    transmittedBytes: control.rawRuns[0].sizes.transmittedPresentationBytes,
  };
  const zk = {
    oneTimeSetupWallMs:
      lifecycle.oneTimeSetupPlusKeySerializationToSinkComponentSum.median,
    perCredentialWalletWallMs: lifecycle.perCredentialReusableCoreComponentSum.median,
    perPresentationWalletWallMs: lifecycle.perPresentationWalletComponentSum.median,
    perPresentationVerifierWallMs: lifecycle.perPresentationVerifierComponentSum.median,
    transmittedBytes: artifacts.combined.rawProofPair,
  };
  return {
    interpretation: "native relation component sums only; SDK orchestration/framing is not composed for this profile, transmitted bytes are the raw proof pair, and first measured operations run in fresh workers with already materialized, potentially page-cached artifacts",
    noZk,
    noZkWarmedSteadyStateSensitivity: control.summary,
    zkMeasuredNativeComponents: zk,
    storageInventories: unmatchedStorageInventories(control, artifacts),
    overheadRatios: { measuredNativeComponents: ratios(noZk, zk) },
  };
}

function unmatchedStorageInventories(control: any, artifacts: any) {
  return {
    comparable: false,
    noZkPreparedCredentialBytes:
      control.rawRuns[0].sizes.preparedCredentialStorageBytes,
    zkSerializedPrepareInstancePlusAssignmentBytes:
      artifacts.combined.reusablePrepareState,
    reason: "different persistence boundaries: the no-ZK inventory includes the compact credential and key/status metadata, while the ZK figure includes only the serialized Prepare instance and assignment; holder signing state, original credential, Show/status witness material, auxiliary attestation, and durable registry rows are not symmetrically inventoried",
  };
}

function composeFirstAcceptedClaimWithState(direct: any, state: any) {
  const stateSetup = state.summary.oneTimeStateStoreSetup.wallMs.median;
  const stateTransition = state.summary.firstClaimStateTransition.wallMs.median;
  const add = (value: any) => ({
    ...value,
    oneTimeSetupWallMs: value.oneTimeSetupWallMs + stateSetup,
    perPresentationVerifierWallMs:
      value.perPresentationVerifierWallMs + stateTransition,
  });
  const noZk = add(direct.noZk);
  const native = add(direct.zkMeasuredNativeComponents);
  const withSdk = direct.zkWithMeasuredSdkComponentsEstimate
    ? add(direct.zkWithMeasuredSdkComponentsEstimate)
    : undefined;
  const transmittedBytes = withSdk?.transmittedBytes ?? native.transmittedBytes;
  if (!Number.isFinite(transmittedBytes)) {
    throw new Error("scoped-nullifier comparison has no measured transmission size");
  }
  return {
    interpretation: "all-in first accepted claim: the identical FULL-sync WAL setup and transactional spent-nullifier plus accepted-claim insertion are added to both stateless verifier paths; replay and concurrency remain separate operational results",
    commonDurableStateWallMs: {
      oneTimeStoreSetup: stateSetup,
      firstClaimTransition: stateTransition,
    },
    noZk,
    zkMeasuredNativeComponents: native,
    ...(withSdk ? { zkWithMeasuredSdkComponentsEstimate: withSdk } : {}),
    overheadRatios: {
      measuredNativeComponents: ratios(noZk, {
        ...native,
        transmittedBytes,
      }),
      ...(withSdk ? { withMeasuredSdkComponentsEstimate: ratios(noZk, withSdk) } : {}),
    },
  };
}

function composePackedStatusPreprocessing(profile: any) {
  const stages = profile.zk.lifecycle.principalStages;
  const tree = stages.perStatusSnapshotPackedV2TreeBuild;
  const path = stages.perCredentialPackedV2StatusPathGeneration;
  const direct = profile.directComparison;
  const addToCredential = (value: any, addedWallMs: number) => ({
    ...value,
    perCredentialWalletWallMs: value.perCredentialWalletWallMs + addedWallMs,
  });
  const nativeTransmission = profile.zk.exactArtifacts.combined.rawProofPair;
  const comparison = (addedWallMs: number, interpretation: string) => {
    const native = addToCredential(direct.zkMeasuredNativeComponents, addedWallMs);
    const withSdk = direct.zkWithMeasuredSdkComponentsEstimate
      ? addToCredential(direct.zkWithMeasuredSdkComponentsEstimate, addedWallMs)
      : undefined;
    return {
      ...direct,
      interpretation,
      zkMeasuredNativeComponents: native,
      ...(withSdk ? { zkWithMeasuredSdkComponentsEstimate: withSdk } : {}),
      overheadRatios: {
        measuredNativeComponents: ratios(direct.noZk, {
          ...native,
          transmittedBytes: nativeTransmission,
        }),
        ...(withSdk ? {
          withMeasuredSdkComponentsEstimate: ratios(direct.noZk, withSdk),
        } : {}),
      },
    };
  };
  const cachedSnapshot = comparison(
    path.median,
    "primary comparison: both paths start from pre-authenticated packed status bytes; ZK additionally pays one measured packed-chunk Merkle-path derivation per credential, while the snapshot tree is reused",
  );
  const freshSnapshot = comparison(
    tree.median + path.median,
    "fresh-snapshot sensitivity: charges one complete packed-chunk ternary-tree construction plus one credential path to the first credential processed from a newly authenticated status snapshot",
  );
  return {
    interpretation: "The timing boundary for both primary paths begins with the same pre-authenticated packed status bytes. The ZK path then builds one packed-chunk ternary tree per snapshot and derives one path per credential. Where an SDK-host resolver is exercised, signed-status authentication is an untimed correctness check and is not included in either direct ratio.",
    perAuthoritativeSnapshotPackedV2TreeBuildWallMs: tree,
    perCredentialPerSnapshotPackedV2PathGenerationWallMs: path,
    freshSnapshotFirstCredentialAddedWalletWallMs: tree.median + path.median,
    directComparisonWithCachedAuthenticatedSnapshot: cachedSnapshot,
    directComparisonForFirstCredentialAfterFreshSnapshot: freshSnapshot,
  };
}

function marginalProfileComparison(base: any, extended: any) {
  const baseArtifacts = base.zk.exactArtifacts.combined;
  const extendedArtifacts = extended.zk.exactArtifacts.combined;
  const delta = (field: string) => extendedArtifacts[field] - baseArtifacts[field];
  const ratio = (field: string) => extendedArtifacts[field] / baseArtifacts[field];
  return {
    interpretation: "isolates the marginal integrated scoped-nullifier cost from the common age/status ZK relation; it is separate from the no-ZK functional control comparison",
    exactArtifacts: {
      constraints: { base: baseArtifacts.constraints, extended: extendedArtifacts.constraints, delta: delta("constraints"), ratio: ratio("constraints") },
      r1csBytes: { base: baseArtifacts.r1cs, extended: extendedArtifacts.r1cs, delta: delta("r1cs"), ratio: ratio("r1cs") },
      provingKeyBytes: { base: baseArtifacts.provingKeys, extended: extendedArtifacts.provingKeys, delta: delta("provingKeys"), ratio: ratio("provingKeys") },
      verifyingKeyBytes: { base: baseArtifacts.verifyingKeys, extended: extendedArtifacts.verifyingKeys, delta: delta("verifyingKeys"), ratio: ratio("verifyingKeys") },
      rawProofPairBytes: { base: baseArtifacts.rawProofPair, extended: extendedArtifacts.rawProofPair, delta: delta("rawProofPair"), ratio: ratio("rawProofPair") },
    },
    lifecycleMedianMs: Object.fromEntries([
      "oneTimeSetupPlusKeySerializationToSinkComponentSum",
      "perCredentialReusableCoreComponentSum",
      "perPresentationWalletComponentSum",
      "perPresentationVerifierComponentSum",
    ].map((stage) => [stage, {
      base: base.zk.lifecycle[stage].median,
      extended: extended.zk.lifecycle[stage].median,
      delta: extended.zk.lifecycle[stage].median - base.zk.lifecycle[stage].median,
      ratio: extended.zk.lifecycle[stage].median / base.zk.lifecycle[stage].median,
    }])),
  };
}

function artifacts(run: any) {
  const prepare = normalizeSizes(run.sizes.prepare);
  const show = normalizeSizes(run.sizes.show);
  return {
    prepare,
    show,
    combined: {
      constraints: prepare.constraints + show.constraints,
      wires: prepare.wires + show.wires,
      r1cs: prepare.r1cs + show.r1cs,
      wasm: prepare.wasm + show.wasm,
      witness: prepare.witness + show.witness,
      provingKeys: prepare.provingKey + show.provingKey,
      verifyingKeys: prepare.verifyingKey + show.verifyingKey,
      rawProofPair: prepare.proof + show.proof,
      reusablePrepareState: prepare.preReblindInstance + prepare.assignment,
    },
  };
}

function normalizeSizes(stage: any) {
  return {
    constraints: stage.constraints,
    wires: stage.wires,
    r1cs: stage.r1cs_bytes,
    wasm: stage.wasm_bytes,
    witness: stage.witness_bytes,
    provingKey: stage.proving_key_bytes,
    verifyingKey: stage.verifying_key_bytes,
    proof: stage.final_proof_bytes ?? stage.proof_bytes,
    preReblindInstance: stage.pre_reblind_instance_bytes,
    assignment: stage.assignment_bytes,
  };
}

function assertSemanticParity(profile: string, control: any, witness: any) {
  const standard = control.policy;
  if (profile === "age-over-18") {
    assertEqual(standard.disclosedClaim, witness.policy.derivedClaim, "age derived claim");
    assertEqual(witness.policy.statusRequired, "VALID (00)", "age status");
    assertPackedStatusParity(
      control.rawRuns[0].statusSnapshotIdentity,
      witness.policy.statusSnapshot,
      "age",
    );
    return { equal: true, standard, zk: witness.policy,
      qualification: "standard reveals issuer-derived Boolean; ZK derives the same outcome from birthdate and verifier cutoff" };
  }
  if (profile === "resident-canton") {
    assertEqual(standard.disclosedClaim, witness.policy.disclosedClaim, "canton disclosed claim");
    assertEqual(standard.allowedValues, witness.policy.allowedValues, "canton allow-list");
    assertEqual(witness.policy.statusRequired, "VALID (00)", "canton status");
    return { equal: true, standard, zk: witness.policy };
  }
  if (profile === "authoritative-residence-exact") {
    assertEqual(control.rawRuns[0].fixtureIdentity, witness.fixtureIdentity,
      "residence byte-identical credential fixture");
    assertEqual(standard.allowedMunicipalityBfsCodes, witness.policy.allowedMunicipalityBfs,
      "residence BFS allow-list");
    assertEqual(standard.minimumResidenceDays, witness.policy.minimumResidenceDays,
      "residence minimum duration");
    assertEqual(standard.municipalityDirectoryAsOf,
      witness.policy.municipalityDirectoryAsOf, "residence directory edition");
    assertEqual(standard.municipalityDirectorySha256,
      witness.policy.municipalityDirectorySha256, "residence directory artifact");
    assertEqual(standard.currentEpochDay,
      Math.floor(Number(witness.policy.currentTime) / 86_400),
      "residence verifier UTC day");
    assertEqual(control.rawRuns[0].statusSnapshotIdentity, {
      uri: "https://status.example.ch/lists/2026-07",
      index: 42,
      listLength: witness.policy.statusSnapshot.listLength,
      selectedValue: 0,
      epoch: witness.policy.statusSnapshot.epoch,
      treeProfile: witness.policy.statusSnapshot.packedV2.treeProfile,
      packedChunkRoot: witness.policy.statusSnapshot.packedV2.root,
    }, "residence status snapshot identity");
    assertEqual(witness.policy.statusRequired, "VALID (00)", "residence status");
    return {
      equal: true,
      standard,
      zk: witness.policy,
      qualification: "same issuer/VCT/status/policy inputs; standard SD-JWT discloses municipality and exact arrival date while ZK reveals only predicate success",
    };
  }
  if (profile === "scoped-nullifier") {
    assertEqual(standard.profileVersion, witness.policy.profileVersion,
      "nullifier profile version");
    assertEqual(standard.basePredicate, ["age_over_18", true],
      "nullifier no-ZK base predicate");
    assertEqual(witness.policy.sourceClaim, ["birthdate", "2000-02-29"],
      "nullifier ZK source claim");
    assertEqual(control.semantics.authoritativeLookup,
      witness.policy.acceptedLookup, "nullifier authoritative issuer/kid/VCT");
    assertEqual(standard.scope.digest, witness.policy.scopeDigestBase64url,
      "nullifier scope digest");
    assertEqual(standard.scope.epoch, witness.policy.epoch, "nullifier epoch");
    assertEqual(standard.currentTime, witness.policy.currentTime,
      "nullifier verifier time");
    assertEqual(witness.policy.statusRequired, "VALID (00)", "nullifier status");
    assertPackedStatusParity(
      control.rawRuns[0].statusSnapshotIdentity,
      witness.policy.statusSnapshot,
      "scoped-nullifier",
    );
    assertEqual(witness.policy.guarantee,
      "one claim per credential/nullifier attestation, not one person",
      "nullifier exact guarantee");
    return {
      equal: true,
      standard,
      zk: witness.policy,
      qualification: "functional parity: both enforce the same verifier scope and atomic registry state; the ordinary control reveals credential_uid whereas ZK reveals only a derived scoped nullifier",
    };
  }
  throw new Error(`unsupported semantic-parity profile: ${profile}`);
}

function assertPackedStatusParity(control: any, manifest: any, label: string) {
  assertEqual(control.uri, manifest.uri, `${label} status URI`);
  assertEqual(control.index, manifest.index, `${label} status index`);
  assertEqual(control.listLength, manifest.listLength, `${label} status list length`);
  assertEqual(control.epoch, manifest.epoch, `${label} status epoch`);
  assertEqual(control.treeProfile, manifest.treeProfile, `${label} status tree profile`);
  assertEqual(control.packedChunkRoot, manifest.snapshotRoot, `${label} status root`);
  assertEqual(control.selectedValue, 0, `${label} selected status`);
}

function validateControlRuns(profile: string, control: any) {
  const expected = control.repetitionRule.requiredRuns;
  const stages = control.repetitionRule?.principalStages;
  if (control.schema !== "swiyu.no-zk-sd-jwt-control-benchmark.v3" ||
      control.profile !== profile || !Number.isInteger(control.iterationsPerRun) ||
      control.iterationsPerRun <= 0 || control.coldIterationsPerRun !== 1 ||
      !Array.isArray(stages) || stages.length === 0 ||
      !Array.isArray(control.rawRuns) || control.rawRuns.length < 2) {
    throw new Error(`${profile} control has no declared principal-stage manifest`);
  }
  const expanded = stages.some((stage) => {
    const first = controlStageTiming(control.rawRuns[0], stage).wallMsPerOperation;
    const second = controlStageTiming(control.rawRuns[1], stage).wallMsPerOperation;
    return relativeDelta(first, second) > 0.15;
  });
  const sizes = control.rawRuns.map((run: any) => JSON.stringify(run.sizes));
  if (![3, 7].includes(expected) || control.rawRuns.length !== expected ||
      expected !== (expanded ? 7 : 3) || new Set(sizes).size !== 1 ||
      control.repetitionRule.firstTwoPrincipalStageVariationOver15Percent !== expanded ||
      control.repetitionRule.satisfied !== true) {
    throw new Error(`${profile} control does not satisfy adaptive 3/7 rule`);
  }
  const fixtureIdentities = control.rawRuns.map((run: any) =>
    JSON.stringify({ fixture: run.fixtureIdentity, status: run.statusSnapshotIdentity }));
  if (new Set(fixtureIdentities).size !== 1 || !control.coldSummary || !control.summary) {
    throw new Error(`${profile} control fixture identity or cold/steady summary changed across workers`);
  }
  for (const stage of [
    "oneTimeTrustMaterialSetup",
    "perCredentialReusableWalletPreparation",
    "perPresentationWallet",
    "perPresentationVerifierStateless",
    "perPresentationEndToEndWithUncachedCredentialValidation",
  ]) {
    assertEqual(control.coldSummary[stage].wallMs.raw,
      control.rawRuns.map((run: any) => run.coldTimings[stage].wallMsPerOperation),
      `${profile} cold ${stage} summary`);
    assertEqual(control.summary[stage].wallMs.raw,
      control.rawRuns.map((run: any) => run.timings[stage].wallMsPerOperation),
      `${profile} steady-state ${stage} summary`);
  }
  if (control.rawRuns.some((run: any) => run.correctness?.validPresentationAccepted !== true)) {
    throw new Error(`${profile} control did not accept its valid presentation fixture`);
  }
  if (profile === "authoritative-residence-exact" && control.rawRuns.some((run: any) =>
    Object.values(run.correctness?.exactCombinedDisclosureGrammarRejects ?? {})
      .length !== 4 ||
    Object.values(run.correctness.exactCombinedDisclosureGrammarRejects)
      .some((value) => value !== true))) {
    throw new Error("residence control did not reject every non-canonical wire fixture");
  }
  if (profile === "scoped-nullifier" && control.rawRuns.some((run: any) =>
    run.correctness?.deterministicWithinScope !== true ||
    run.correctness?.differentAcrossScopes !== true ||
    run.correctness?.stateEnforcementMeasuredSeparately !== true ||
    run.sizes?.scopeHashBytes !== 32 || run.sizes?.nullifierBytes !== 32)) {
    throw new Error("scoped-nullifier control failed scope separation or exact-size invariants");
  }
}

function controlStageTiming(run: any, qualifiedStage: string) {
  const separator = qualifiedStage.indexOf(".");
  if (separator < 1) throw new Error(`invalid qualified control stage ${qualifiedStage}`);
  const mode = qualifiedStage.slice(0, separator);
  const stage = qualifiedStage.slice(separator + 1);
  const bucket = mode === "cold" ? run.coldTimings
    : mode === "steadyState" ? run.timings : undefined;
  const timing = bucket?.[stage];
  if (!timing || !Number.isFinite(timing.wallMsPerOperation) ||
      !Number.isFinite(timing.cpuMsPerOperation)) {
    throw new Error(`control run is missing finite ${qualifiedStage}`);
  }
  return timing;
}

function validateSdkHostRuns(profile: string, report: any) {
  const expectedIdentity: Record<string, {
    implementationProfile: string;
    circuits?: { prepare: string; show: string };
    exactAdapter: boolean;
  }> = {
    age: {
      implementationProfile: "swiyu.age-over-18.status.v1",
      exactAdapter: false,
    },
    canton: {
      implementationProfile: "swiyu.canton-eligibility.prepare-show.v1",
      circuits: {
        prepare: "swiyu_canton_prepare_compact",
        show: "swiyu_canton_show_split",
      },
      exactAdapter: true,
    },
    residence: {
      implementationProfile: "swiyu.residence-eligibility.combined-disclosure.v1",
      circuits: {
        prepare: "swiyu_residence_combined_prepare_compact",
        show: "swiyu_residence_show_packed_chunk_v2",
      },
      exactAdapter: true,
    },
    "scoped-nullifier": {
      implementationProfile: "swiyu.age-over-18.scoped-nullifier.v1",
      circuits: {
        prepare: "swiyu_nullifier_age18_prepare",
        show: "swiyu_nullifier_age18_show_packed_chunk_v2",
      },
      exactAdapter: true,
    },
  };
  const identity = expectedIdentity[profile];
  const stages = Object.keys(report.rawRuns?.[0]?.timings ?? {});
  const expanded = stages.some((stage) => {
    const first = report.rawRuns[0].timings[stage].wallMsPerOperation;
    const second = report.rawRuns[1].timings[stage].wallMsPerOperation;
    const mean = (first + second) / 2;
    return mean !== 0 && Math.abs(first - second) / mean > 0.15;
  });
  const expected = expanded ? 7 : 3;
  if (report.schema !== "swiyu.zk-sdk-host-orchestration.v1" ||
      report.profile !== profile || !Number.isInteger(report.iterationsPerRun) ||
      report.iterationsPerRun <= 0 || report.warmupsPerWorker !== 100 ||
      stages.length === 0 || report.repetitionRule?.adaptive !== true ||
      report.repetitionRule?.thresholdRelativeToFirstTwoMean !== 0.15 ||
      report.repetitionRule?.firstTwoPrincipalStageVariationOver15Percent !== expanded ||
      report.repetitionRule?.requiredRuns !== expected ||
      report.repetitionRule?.satisfied !== true || report.rawRuns.length !== expected ||
      !identity || report.implementation?.exactProfileAdapter !== identity.exactAdapter) {
    throw new Error(`${profile} SDK host benchmark does not satisfy its adaptive 3/7 rule`);
  }
  for (const [index, run] of report.rawRuns.entries()) {
    if (run.profile !== profile || run.run !== index + 1 ||
        run.iterations !== report.iterationsPerRun ||
        run.implementationProfile !== identity.implementationProfile ||
        run.sizes?.syntheticProofPairRawBytes !== report.syntheticProofPairBytes ||
        run.processPeakRssBytes <= 0) {
      throw new Error(`${profile} SDK host worker ${index + 1} has invalid identity or sizes`);
    }
    if (identity.circuits) {
      assertEqual(run.circuitIds, identity.circuits,
        `${profile} SDK host worker ${index + 1} circuit ids`);
    }
  }
  for (const stage of stages) {
    assertEqual(report.summary?.[stage]?.wallMs?.samples,
      report.rawRuns.map((run: any) => run.timings[stage].wallMsPerOperation),
      `${profile} SDK host ${stage} wall summary`);
    assertEqual(report.summary?.[stage]?.cpuMs?.samples,
      report.rawRuns.map((run: any) => run.timings[stage].cpuMsPerOperation),
      `${profile} SDK host ${stage} CPU summary`);
  }
}

function validateProductionVerifierControl(report: any, metadata: any) {
  const runs = report.rawRuns;
  if (report.schema !== "swiyu.production-sd-jwt-dcql-control.v1" ||
      report.classification !== "production-verifier-supplement" ||
      !Array.isArray(runs) || runs.length < 2 ||
      !Number.isInteger(report.iterationsPerRun) || report.iterationsPerRun <= 0 ||
      !Number.isInteger(report.warmupsPerRun) || report.warmupsPerRun < 0) {
    throw new Error("production verifier supplement has an invalid schema or run configuration");
  }

  const wallDelta = relativeDelta(
    runs[0].timing?.wallMsPerOperation,
    runs[1].timing?.wallMsPerOperation,
  );
  const cpuDelta = relativeDelta(
    runs[0].timing?.cpuMsPerOperation,
    runs[1].timing?.cpuMsPerOperation,
  );
  const expanded = wallDelta > 0.15 || cpuDelta > 0.15;
  const expectedRuns = expanded ? 7 : 3;
  const rule = report.repetitionRule;
  if (rule?.threshold !== 0.15 || rule?.denominator !== "mean of first two" ||
      rule?.expanded !== expanded || rule?.requiredRuns !== expectedRuns ||
      rule?.satisfied !== true || runs.length !== expectedRuns) {
    throw new Error("production verifier supplement does not satisfy its adaptive 3/7 rule");
  }
  assertEqual(rule.firstTwoRelativeDeltas, { wall: wallDelta, cpu: cpuDelta },
    "production verifier first-two deltas");
  assertEqual(rule.principalStages,
    ["productionVerifierDcqlWall", "productionVerifierDcqlCpu"],
    "production verifier principal stages");

  const expectedSource = {
    commit: metadata.productionVerifierSource?.commit,
    treeSha256: metadata.productionVerifierSource?.treeSha256,
  };
  assertEqual(report.implementation?.source, expectedSource, "production verifier source provenance");
  if (metadata.productionVerifierSource?.dirty !== false ||
      typeof expectedSource.commit !== "string" || expectedSource.commit.length < 7 ||
      typeof expectedSource.treeSha256 !== "string" || expectedSource.treeSha256.length !== 64) {
    throw new Error("production verifier metadata lacks a clean, fingerprinted source");
  }
  assertEqual(report.policy?.claim, ["age_over_18", true], "production verifier age policy");
  if (report.policy?.holderBinding !== true || report.policy?.status !== "VALID") {
    throw new Error("production verifier supplement omitted holder binding or VALID status");
  }

  for (const [index, run] of runs.entries()) {
    if (run.schema !== "swiyu.production-sd-jwt-dcql-control-worker.v1" ||
        run.run !== index + 1 || run.iterations !== report.iterationsPerRun ||
        run.warmups !== report.warmupsPerRun || run.processPeakRssBytes <= 0) {
      throw new Error(`production verifier worker ${index + 1} has invalid identity or RSS`);
    }
    assertEqual(run.source, expectedSource, `production verifier worker ${index + 1} source`);
    assertEqual(run.policy, report.policy, `production verifier worker ${index + 1} policy`);
    assertEqual(run.sizes, report.exactSizes, `production verifier worker ${index + 1} sizes`);
    for (const field of ["wallMsPerOperation", "cpuMsPerOperation", "totalWallMs", "totalCpuMs"]) {
      if (typeof run.timing?.[field] !== "number" || !Number.isFinite(run.timing[field]) ||
          run.timing[field] < 0) {
        throw new Error(`production verifier worker ${index + 1} has invalid ${field}`);
      }
    }
  }
  if (report.exactSizes?.transmittedPresentationBytes <= 0) {
    throw new Error("production verifier supplement has no exact presentation size");
  }
  assertEqual(report.summary?.wallMs?.samples,
    runs.map((run: any) => run.timing.wallMsPerOperation),
    "production verifier wall samples");
  assertEqual(report.summary?.cpuMs?.samples,
    runs.map((run: any) => run.timing.cpuMsPerOperation),
    "production verifier CPU samples");
  assertEqual(report.processPeakRssBytes?.samples,
    runs.map((run: any) => run.processPeakRssBytes),
    "production verifier RSS samples");
}

function assertNativeValidity(profile: string, native: any, nativeDocument: any) {
  if (native.prepare?.verified !== true || native.show?.verified !== true) {
    throw new Error(`${profile} contains an unverified native proof`);
  }
  if (nativeDocument.exact_sizes !== undefined) {
    if (native.linked_commitments_equal !== true ||
        nativeDocument.negative_linkage?.unlinked_show_verified_independently !== true ||
        nativeDocument.negative_linkage?.unlinked_shared_commitment_rejected !== true) {
      throw new Error(`${profile} Prepare/Show commitments are not linked`);
    }
    return;
  }
  const linkage = native.linkage;
  if (linkage?.linked_outputs_identical !== true ||
      linkage?.pre_reblind_commitments_differ !== true ||
      linkage?.reblinded_commitments_equal !== true ||
      linkage?.unlinked_show_verified !== true ||
      linkage?.unlinked_commitment_rejected !== true) {
    throw new Error(`${profile} linkage or negative-control invariant failed`);
  }
}

function assertExactSizesConsistent(profile: string, runs: any[]) {
  const expected = JSON.stringify({
    prepare: normalizeSizes(runs[0].sizes.prepare),
    show: normalizeSizes(runs[0].sizes.show),
  });
  for (const run of runs.slice(1)) {
    const actual = JSON.stringify({
      prepare: normalizeSizes(run.sizes.prepare),
      show: normalizeSizes(run.sizes.show),
    });
    if (actual !== expected) throw new Error(`${profile} exact artifact sizes changed across raw runs`);
  }
}

function validateProvenance(value: any) {
  const recoveredAggregation = value.aggregationRecovery?.succeeded === true &&
    value.aggregationRecovery?.rawMeasurementsReused === true &&
    value.aggregationRecovery?.originalEntrypointExitCode === 1 &&
    typeof value.aggregationRecovery?.aggregatorSha256 === "string" &&
    value.aggregationRecovery.aggregatorSha256.length === 64;
  const hashes = [value.source?.diffSha256, value.source?.statusSha256,
    value.source?.treeSha256, value.image?.digest,
    value.productionVerifierSource?.treeSha256];
  if (value.schema !== "swiyu.pinned-container-benchmark-metadata.v1" ||
      value.completed !== true || (value.entrypointExitCode !== 0 && !recoveredAggregation) ||
      value.source?.dirty !== false || typeof value.source?.commit !== "string" ||
      value.productionVerifierSource?.dirty !== false ||
      typeof value.productionVerifierSource?.commit !== "string" ||
      typeof value.image?.mavenBase !== "string" ||
      hashes.some((hash) => typeof hash !== "string" || hash.length < 32) ||
      value.limits?.network !== "none" || value.limits?.enforcementValidated !== true) {
    throw new Error("container metadata is incomplete or lacks pinned source/image provenance");
  }
}

function validateZkRuns(profile: string, rule: any, runs: any[]) {
  const first = adaptiveZkStageValues(runs[0]);
  const second = adaptiveZkStageValues(runs[1]);
  const recomputedDeltas = Object.fromEntries(Object.keys(first).map((stage) => [
    stage,
    relativeDelta(first[stage], second[stage]),
  ]));
  assertEqual(rule.first, first, `${profile} adaptive first-run stage manifest`);
  assertEqual(rule.second, second, `${profile} adaptive second-run stage manifest`);
  assertEqual(rule.relativeDeltas, recomputedDeltas,
    `${profile} adaptive first-two relative deltas`);
  const deltas = Object.values(recomputedDeltas);
  if (deltas.length === 0 || deltas.some((value) => typeof value !== "number" || !Number.isFinite(value))) {
    throw new Error(`${profile} adaptive rule has no finite declared principal stages`);
  }
  const expanded = deltas.some((value: any) => value > 0.15);
  const expected = expanded ? 7 : 3;
  if (rule.threshold !== 0.15 || rule.denominator !== "mean of first two" ||
      rule.expanded !== expanded || rule.requiredRuns !== expected || runs.length !== expected) {
    throw new Error(`${profile} ZK runs do not satisfy the recorded adaptive 3/7 rule`);
  }
}

function adaptiveZkStageValues(run: any) {
  return {
    prepareWitnessMs: run.witnessWallMs.prepare,
    showWitnessMs: run.witnessWallMs.show,
    prepareWitnessHandoffMs: run.prepare.witness_handoff_ms,
    showWitnessHandoffMs: run.show.witness_handoff_ms,
    prepareSetupMs: run.prepare.setup_ms,
    prepareKeySerializationMs: run.prepare.key_serialization_ms,
    prepareAssignmentMs: run.prepare.assignment_ms,
    prepareStateSerializationMs: run.prepare.prepared_state_serialization_ms,
    prepareFinalProofMs: run.prepare.final_proof_ms,
    prepareProofSerializationMs: run.prepare.proof_serialization_ms,
    prepareProofDeserializationMs: run.prepare.proof_deserialization_ms,
    prepareVerifyMs: run.prepare.verify_ms,
    showSetupMs: run.show.setup_ms,
    showKeySerializationMs: run.show.key_serialization_ms,
    showAssignmentMs: run.show.assignment_ms,
    showStateSerializationMs: run.show.prepared_state_serialization_ms,
    showFinalProofMs: run.show.final_proof_ms,
    showProofSerializationMs: run.show.proof_serialization_ms,
    showProofDeserializationMs: run.show.proof_deserialization_ms,
    showVerifyMs: run.show.verify_ms,
    linkRandomnessMs: run.linkage.link_randomness_ms,
    ...(run.packedStatusStagesMs ? {
      perSnapshotPackedV2TreeBuildMs: run.packedStatusStagesMs.packedV2TreeBuild,
      perCredentialPackedV2StatusPathGenerationMs:
        run.packedStatusStagesMs.packedV2PathGeneration,
    } : {}),
  };
}

function ratios(base: any, zk: any) {
  return {
    oneTimeSetup: zk.oneTimeSetupWallMs / base.oneTimeSetupWallMs,
    perCredentialWallet: zk.perCredentialWalletWallMs / base.perCredentialWalletWallMs,
    perPresentationWallet: zk.perPresentationWalletWallMs / base.perPresentationWalletWallMs,
    perPresentationVerifier: zk.perPresentationVerifierWallMs / base.perPresentationVerifierWallMs,
    transmittedBytes: zk.transmittedBytes / base.transmittedBytes,
  };
}

function commandRecord(id: string) {
  const path = `${root}/command-log.jsonl`;
  if (!existsSync(path)) return undefined;
  return readFileSync(path, "utf8").trim().split("\n").filter(Boolean)
    .map((line) => JSON.parse(line)).find((entry) => entry.id === id);
}

function stats(values: number[]) {
  if (values.some((value) => typeof value !== "number" || !Number.isFinite(value))) {
    throw new Error(`invalid numeric samples: ${JSON.stringify(values)}`);
  }
  const sorted = [...values].sort((a, b) => a - b);
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  const variance = values.length > 1
    ? values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / (values.length - 1)
    : 0;
  const standardDeviation = Math.sqrt(variance);
  const middle = Math.floor(sorted.length / 2);
  return {
    samples: values,
    min: sorted[0],
    median: sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2,
    max: sorted.at(-1),
    mean,
    variance,
    standardDeviation,
    coefficientOfVariation: mean === 0 ? 0 : standardDeviation / mean,
  };
}

function relativeDelta(first: number, second: number) {
  if (![first, second].every((value) => typeof value === "number" && Number.isFinite(value))) {
    throw new Error(`invalid relative-delta inputs: ${JSON.stringify([first, second])}`);
  }
  const mean = (first + second) / 2;
  return mean === 0 ? 0 : Math.abs(first - second) / mean;
}

function assertEqual(actual: unknown, expected: unknown, label: string) {
  if (!isDeepStrictEqual(actual, expected)) {
    throw new Error(`${label} mismatch: ${JSON.stringify(actual)} != ${JSON.stringify(expected)}`);
  }
}
function json(path: string) { return JSON.parse(readFileSync(path, "utf8")); }
function required(name: string) {
  const value = arg(name);
  if (!value) throw new Error(`missing ${name}`);
  return value;
}
function arg(name: string) {
  const index = process.argv.indexOf(name);
  return index < 0 ? undefined : process.argv[index + 1];
}

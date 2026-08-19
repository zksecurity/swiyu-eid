import { copyFileSync, readFileSync, writeFileSync } from "node:fs";

const controlDirectory = process.argv[2];
const optimizedDirectory = process.argv[3];
if (!controlDirectory || !optimizedDirectory) {
  throw new Error("usage: merge-residence-witness CONTROL_DIR OPTIMIZED_DIR");
}

const control = json(`${controlDirectory}/witness-runs.json`);
const optimized = json(`${optimizedDirectory}/witness-runs.json`);
copyFileSync(
  `${controlDirectory}/show-packed-v2.wtns`,
  `${optimizedDirectory}/show.wtns`,
);
copyFileSync(
  `${controlDirectory}/show-unlinked-packed-v2.wtns`,
  `${optimizedDirectory}/show-unlinked.wtns`,
);

const merged = {
  profile: "swiyu.residence-eligibility.combined-disclosure.v1",
  controlProfile: control.profile,
  predicate: control.predicate,
  representation: optimized.representation,
  bounds: optimized.bounds,
  selectiveDisclosureTradeoff: optimized.selectiveDisclosureTradeoff,
  repetitions: 1,
  expandedAfterFirstTwo: false,
  processPeakRssBytes: Math.max(
    control.processPeakRssBytes,
    optimized.processPeakRssBytes,
  ),
  statusSnapshotStagesMs: control.statusSnapshotStagesMs,
  policy: {
    ...control.policy,
    disclosureShape: "[salt,residence,{municipality_bfs,since}]",
    primaryStatusProfile: control.policy.statusSnapshot.packedV2,
  },
  disclosure: optimized.disclosure,
  fixtureIdentity: optimized.fixtureIdentity,
  witnessGenerationMs: {
    prepare: optimized.prepareWitnessMs,
    show: control.witnessGenerationMs.showPackedV2,
  },
  witnessGenerationStats: {
    prepare: optimized.prepareWitnessStats,
    show: control.witnessGenerationStats.showPackedV2,
  },
  witnessBytes: {
    prepare: optimized.prepareWitnessBytes,
    show: control.witnessBytes.showPackedV2,
  },
  abControl: {
    prepareCircuit: "swiyu_residence_prepare_compact",
    prepareWitnessMs: control.witnessGenerationMs.prepare,
    prepareWitnessStats: control.witnessGenerationStats.prepare,
    prepareWitnessBytes: control.witnessBytes.prepare,
    legacyShowCircuit: "swiyu_residence_show_split",
    legacyShowWitnessMs: control.witnessGenerationMs.show,
    legacyShowWitnessStats: control.witnessGenerationStats.show,
    legacyShowWitnessBytes: control.witnessBytes.show,
  },
  circuits: {
    prepare: "swiyu_residence_combined_prepare_compact",
    show: "swiyu_residence_show_packed_chunk_v2",
  },
};
writeFileSync(
  `${optimizedDirectory}/witness-runs.json`,
  `${JSON.stringify(merged, null, 2)}\n`,
);

function json(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

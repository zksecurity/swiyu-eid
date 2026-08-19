import { readFileSync } from "node:fs";

const profile = process.argv[2];
const dir = process.argv[3];
if (!profile || !dir) throw new Error("usage: adaptive-profile-runs PROFILE RAW_DIR");

const first = extract(profile, 1);
const second = extract(profile, 2);
const deltas = Object.fromEntries(Object.keys(first).map((metric) => {
  const a = first[metric];
  const b = second[metric];
  const mean = (a + b) / 2;
  return [metric, mean === 0 ? 0 : Math.abs(a - b) / mean];
}));
const expanded = Object.values(deltas).some((delta) => delta > 0.15);
process.stdout.write(`${JSON.stringify({
  profile,
  threshold: 0.15,
  denominator: "mean of first two",
  first,
  second,
  relativeDeltas: deltas,
  expanded,
  requiredRuns: expanded ? 7 : 3,
}, null, 2)}\n`);

function extract(name, run) {
  const witness = json(`${dir}/witness-${run}.json`);
  const nativeDocument = json(`${dir}/native-${run}.json`);
  const native = nativeDocument.prepare && nativeDocument.show
    ? nativeDocument
    : (nativeDocument.raw_runs?.[0] ?? nativeDocument.rawRuns?.[0]);
  if (!native) throw new Error(`${name} native run ${run} has no single raw run`);
  const witnessValues = witnessStages(name, witness);
  const stages = {
    prepareWitnessMs: witnessValues.prepare,
    showWitnessMs: witnessValues.show,
    prepareWitnessHandoffMs: native.prepare.witness_handoff_ms,
    showWitnessHandoffMs: native.show.witness_handoff_ms,
    prepareSetupMs: native.prepare.setup_ms,
    prepareKeySerializationMs: native.prepare.key_serialization_ms,
    prepareAssignmentMs: native.prepare.assignment_ms,
    prepareStateSerializationMs: native.prepare.prepared_state_serialization_ms,
    prepareFinalProofMs: native.prepare.final_proof_ms,
    prepareProofSerializationMs: native.prepare.proof_serialization_ms,
    prepareProofDeserializationMs: native.prepare.proof_deserialization_ms,
    prepareVerifyMs: native.prepare.verify_ms,
    showSetupMs: native.show.setup_ms,
    showKeySerializationMs: native.show.key_serialization_ms,
    showAssignmentMs: native.show.assignment_ms,
    showStateSerializationMs: native.show.prepared_state_serialization_ms,
    showFinalProofMs: native.show.final_proof_ms,
    showProofSerializationMs: native.show.proof_serialization_ms,
    showProofDeserializationMs: native.show.proof_deserialization_ms,
    showVerifyMs: native.show.verify_ms,
    linkRandomnessMs: native.linkage?.link_randomness_ms ?? native.link_randomness_ms,
    ...packedStatusStages(witness),
  };
  for (const [stage, value] of Object.entries(stages)) {
    if (typeof value !== "number" || !Number.isFinite(value)) {
      throw new Error(`${name} run ${run} is missing finite principal stage ${stage}`);
    }
  }
  return stages;
}

function packedStatusStages(witness) {
  const stages = witness.statusSnapshotStagesMs;
  if (!stages) return {};
  const treeValues = stages?.packedV2TreeBuild ?? stages?.ternaryTreeBuild;
  const pathValues = stages?.packedV2PathGeneration ?? stages?.statusPathGeneration;
  const tree = Array.isArray(treeValues) ? treeValues[0] : treeValues;
  const path = Array.isArray(pathValues) ? pathValues[0] : pathValues;
  if (!Number.isFinite(tree) || !Number.isFinite(path)) {
    throw new Error("witness fixture is missing packed-v2 status stages");
  }
  return {
    perSnapshotPackedV2TreeBuildMs: tree,
    perCredentialPackedV2StatusPathGenerationMs: path,
  };
}

// Profile adapters emit slightly different fixture wrappers, but all of them
// must identify exactly one fresh-process Prepare and Show witness sample.
// Keeping this normalization structural prevents a new profile from silently
// falling through to an unrelated fixture shape.
function witnessStages(name, witness) {
  if (finitePair(witness.witnessGenerationMs)) {
    return {
      prepare: witness.witnessGenerationMs.prepare,
      show: Number.isFinite(witness.witnessGenerationMs.showPackedV2)
        ? witness.witnessGenerationMs.showPackedV2
        : witness.witnessGenerationMs.show,
    };
  }
  if (Array.isArray(witness.prepareWitnessMs) && Array.isArray(witness.showWitnessMs)) {
    return { prepare: witness.prepareWitnessMs[0], show: witness.showWitnessMs[0] };
  }
  const nested = witness.witnessGenerationMs;
  if (nested && typeof nested === "object") {
    const prepare = Array.isArray(nested.prepare) ? nested.prepare[0] : nested.prepare;
    const primaryShow = nested.showPackedV2 ?? nested.show;
    const show = Array.isArray(primaryShow) ? primaryShow[0] : primaryShow;
    if (Number.isFinite(prepare) && Number.isFinite(show)) return { prepare, show };
  }
  throw new Error(`${name} witness fixture has no recognizable Prepare/Show timing pair`);
}

function finitePair(value) {
  return value && typeof value === "object" &&
    Number.isFinite(value.prepare) && Number.isFinite(value.show);
}

function json(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

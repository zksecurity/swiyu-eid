import { readFileSync } from "node:fs";

const profile = process.argv[2];
const dir = process.argv[3];
if (!profile || !dir) {
  throw new Error("usage: adaptive-control-runs PROFILE RAW_WORKER_DIR");
}

const first = worker(1);
const second = worker(2);
const stageNames = ["cold", "steadyState"].flatMap((mode) => [
  "oneTimeTrustMaterialSetup",
  "perCredentialReusableWalletPreparation",
  "perPresentationWallet",
  "perPresentationVerifierStateless",
  "perPresentationEndToEndWithUncachedCredentialValidation",
].map((stage) => `${mode}.${stage}`));
const relativeDeltas = Object.fromEntries(stageNames.map((stage) => {
  const firstValue = timing(first, stage).wallMsPerOperation;
  const secondValue = timing(second, stage).wallMsPerOperation;
  const mean = (firstValue + secondValue) / 2;
  return [stage, mean === 0 ? 0 : Math.abs(firstValue - secondValue) / mean];
}));
const expanded = Object.values(relativeDeltas).some((delta) => delta > 0.15);

process.stdout.write(`${JSON.stringify({
  profile,
  threshold: 0.15,
  denominator: "mean of first two",
  principalStages: stageNames,
  relativeDeltas,
  expanded,
  requiredRuns: expanded ? 7 : 3,
}, null, 2)}\n`);

function worker(run) {
  const value = JSON.parse(readFileSync(`${dir}/worker-${run}.json`, "utf8"));
  if (value.profile !== profile || value.run !== run) {
    throw new Error(`${profile} control worker ${run} has inconsistent identity`);
  }
  return value;
}

function timing(run, qualifiedStage) {
  const separator = qualifiedStage.indexOf(".");
  const mode = qualifiedStage.slice(0, separator);
  const stage = qualifiedStage.slice(separator + 1);
  const value = (mode === "cold" ? run.coldTimings : run.timings)?.[stage];
  if (!Number.isFinite(value?.wallMsPerOperation)) {
    throw new Error(`${profile} control worker is missing finite ${qualifiedStage}`);
  }
  return value;
}

import { spawnSync } from "node:child_process";

const iterations = Number(arg("--iterations") ?? "1000");
const warmups = Number(arg("--warmups") ?? "100");
const java = arg("--java") ?? "java";
const classpath = arg("--classpath") ?? "/opt/swiyu/classes:/opt/swiyu/benchmark:/opt/swiyu/lib/*";
const main = "ch.admin.bj.swiyu.verifier.benchmark.SwiyuProductionControlBenchmark";
const runs = [worker(1), worker(2)];
const firstTwoDeltas = {
  wall: relativeDelta(runs[0].timing.wallMsPerOperation, runs[1].timing.wallMsPerOperation),
  cpu: relativeDelta(runs[0].timing.cpuMsPerOperation, runs[1].timing.cpuMsPerOperation),
};
const expanded = Object.values(firstTwoDeltas).some((value) => value > 0.15);
const requiredRuns = expanded ? 7 : 3;
while (runs.length < requiredRuns) runs.push(worker(runs.length + 1));

process.stdout.write(`${JSON.stringify({
  schema: "swiyu.production-sd-jwt-dcql-control.v1",
  classification: "production-verifier-supplement",
  generatedAt: new Date().toISOString(),
  implementation: {
    repository: "swiyu-verifier",
    source: runs[0].source,
    classes: runs[0].boundary.productionClasses,
    qualification: "production verifier/DCQL classes with preloaded issuer-key and VALID-status adapters; wallet presentation construction and network/database/controller work excluded",
  },
  iterationsPerRun: iterations,
  warmupsPerRun: warmups,
  repetitionRule: {
    threshold: 0.15,
    denominator: "mean of first two",
    principalStages: ["productionVerifierDcqlWall", "productionVerifierDcqlCpu"],
    firstTwoRelativeDeltas: firstTwoDeltas,
    expanded,
    requiredRuns,
    satisfied: runs.length === requiredRuns,
  },
  policy: runs[0].policy,
  exactSizes: runs[0].sizes,
  processPeakRssBytes: stats(runs.map((run) => run.processPeakRssBytes)),
  summary: {
    wallMs: stats(runs.map((run) => run.timing.wallMsPerOperation)),
    cpuMs: stats(runs.map((run) => run.timing.cpuMsPerOperation)),
  },
  rawRuns: runs,
}, null, 2)}\n`);

function worker(run) {
  const result = spawnSync(java, [
    "-cp", classpath, main,
    "--run", String(run),
    "--iterations", String(iterations),
    "--warmups", String(warmups),
  ], { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`production control worker ${run} failed: ${result.stderr}`);
  return JSON.parse(result.stdout);
}

function relativeDelta(a, b) {
  const mean = (a + b) / 2;
  return mean === 0 ? 0 : Math.abs(a - b) / mean;
}

function stats(values) {
  const ordered = [...values].sort((a, b) => a - b);
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  const variance = values.length > 1
    ? values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / (values.length - 1)
    : 0;
  const middle = Math.floor(ordered.length / 2);
  return {
    samples: values,
    min: ordered[0],
    median: ordered.length % 2 ? ordered[middle] : (ordered[middle - 1] + ordered[middle]) / 2,
    max: ordered.at(-1),
    mean,
    variance,
    standardDeviation: Math.sqrt(variance),
    coefficientOfVariation: mean === 0 ? 0 : Math.sqrt(variance) / mean,
  };
}

function arg(name) {
  const index = process.argv.indexOf(name);
  return index < 0 ? undefined : process.argv[index + 1];
}

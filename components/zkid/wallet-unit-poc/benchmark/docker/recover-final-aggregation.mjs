import { createHash } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { isDeepStrictEqual } from "node:util";

const root = required("--results-root");
const aggregator = required("--aggregator");
const metadataPath = `${root}/metadata.json`;
const commandLogPath = `${root}/command-log.jsonl`;
const metadata = json(metadataPath);
const commands = readFileSync(commandLogPath, "utf8").trim().split("\n")
  .filter(Boolean).map((line) => JSON.parse(line));
const aggregatorSha256 = sha256(aggregator);

if (metadata.completed === true && metadata.aggregationRecovery?.succeeded === true) {
  validateCompletedRecovery(metadata, commands, aggregatorSha256);
  process.stdout.write("aggregation recovery already completed and verified; no changes made\n");
  process.exit(0);
}

// If a prior recovery was interrupted after publishing its command record but
// before publishing metadata, discard only that trailing recovery record and
// replay from the immutable original failure state.
const originalCommands = [...commands];
while (originalCommands.at(-1)?.id === "aggregate-final-overhead-recovery") {
  originalCommands.pop();
}
const failed = originalCommands.at(-1);

if (metadata.completed !== false || metadata.entrypointExitCode !== 1 ||
    failed?.id !== "aggregate-final-overhead" || failed.exitCode !== 1 ||
    originalCommands.slice(0, -1).some((command) => command.exitCode !== 0)) {
  throw new Error("result is not an otherwise-successful run with one failed final aggregation");
}
const productionControl = json(`${root}/raw/production-control/age-over-18.json`);
const expectedSource = {
  commit: metadata.productionVerifierSource?.commit,
  treeSha256: metadata.productionVerifierSource?.treeSha256,
};
const workerSources = productionControl.rawRuns?.map((run) => run.source) ?? [];
if (workerSources.length === 0 ||
    workerSources.some((source) => !isDeepStrictEqual(source, expectedSource)) ||
    workerSources.every((source) => JSON.stringify(source) === JSON.stringify(expectedSource))) {
  throw new Error("aggregation failure is not the audited object-key-order mismatch");
}

const startedAt = new Date().toISOString();
const rawTreeSha256 = treeSha256(`${root}/raw`);
const recovery = {
  succeeded: true,
  rawMeasurementsReused: true,
  originalEntrypointExitCode: 1,
  reason: "The original deterministic aggregation rejected equal provenance objects whose keys had different insertion order; deep structural equality fixes reporting only.",
  aggregatorSha256,
  rawTreeSha256,
  runtime: process.version,
  startedAt,
};
const staged = mkdtempSync(join(tmpdir(), "swiyu-aggregation-recovery-"));
try {
  // Aggregate a private copy: recovery code receives no writable path to the
  // original raw measurements.
  cpSync(`${root}/raw`, `${staged}/raw`, { recursive: true });
  cpSync(commandLogPath, `${staged}/command-log.jsonl`);
  writeFileSync(`${staged}/metadata.json`, `${JSON.stringify({
    ...metadata,
    completed: true,
    aggregationRecovery: recovery,
  }, null, 2)}\n`);

  const result = spawnSync(process.execPath, [
    "--experimental-strip-types",
    aggregator,
    "--results-root", staged,
    "--out", `${staged}/zk-overhead-results.json`,
  ], { encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(`recovery aggregation failed: ${result.stderr || result.stdout}`);
  }
  if (treeSha256(`${root}/raw`) !== rawTreeSha256 ||
      treeSha256(`${staged}/raw`) !== rawTreeSha256) {
    throw new Error("raw measurement tree changed during recovery");
  }
  const recoveredResult = json(`${staged}/zk-overhead-results.json`);
  if (recoveredResult.provenance?.aggregationRecovery?.aggregatorSha256 !== aggregatorSha256 ||
      recoveredResult.provenance?.aggregationRecovery?.rawTreeSha256 !== rawTreeSha256) {
    throw new Error("recovered report does not carry its aggregation provenance");
  }

  const endedAt = new Date().toISOString();
  const recoveryCommand = {
    id: "aggregate-final-overhead-recovery",
    startedAt,
    endedAt,
    cwd: process.cwd(),
    argv: [
      process.execPath, "--experimental-strip-types", aggregator,
      "--results-root", staged, "--out", `${staged}/zk-overhead-results.json`,
    ],
    environmentOverrides: {},
    stdoutPath: `${root}/aggregate-recovery.log`,
    exitCode: 0,
    signal: null,
    rawMeasurementsReused: true,
    aggregatorSha256,
    rawTreeSha256,
  };
  atomicWrite(`${root}/zk-overhead-results.json`, readFileSync(`${staged}/zk-overhead-results.json`));
  atomicWrite(`${root}/aggregate-recovery.log`, result.stdout);
  atomicWrite(commandLogPath,
    `${[...originalCommands, recoveryCommand].map((command) => JSON.stringify(command)).join("\n")}\n`);
  // Publish completion last. An interruption before this point is replayable;
  // a completed metadata record makes subsequent invocations verified no-ops.
  atomicWrite(metadataPath, `${JSON.stringify({
    ...metadata,
    completed: true,
    finishedAt: endedAt,
    commands: [...originalCommands, recoveryCommand],
    aggregationRecovery: { ...recovery, endedAt },
  }, null, 2)}\n`);
} finally {
  rmSync(staged, { recursive: true, force: true });
}

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}
function treeSha256(rootPath) {
  const entries = [];
  const visit = (directory, prefix = "") => {
    for (const entry of cpEntries(directory)) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      const absolute = join(directory, entry.name);
      if (entry.isDirectory()) visit(absolute, relative);
      else entries.push([relative, sha256(absolute)]);
    }
  };
  visit(rootPath);
  return createHash("sha256")
    .update(entries.map(([path, digest]) => `${path}\0${digest}\n`).join(""))
    .digest("hex");
}
function cpEntries(path) {
  return [...readdirSync(path, { withFileTypes: true })]
    .sort((left, right) => left.name.localeCompare(right.name));
}
function atomicWrite(path, contents) {
  const temporary = `${path}.tmp-${process.pid}`;
  writeFileSync(temporary, contents);
  renameSync(temporary, path);
}
function validateCompletedRecovery(value, commandRecords, expectedAggregatorSha256) {
  const recovery = value.aggregationRecovery;
  const command = commandRecords.at(-1);
  const reportPath = `${root}/zk-overhead-results.json`;
  if (value.entrypointExitCode !== recovery.originalEntrypointExitCode ||
      recovery.originalEntrypointExitCode !== 1 ||
      recovery.rawMeasurementsReused !== true ||
      recovery.aggregatorSha256 !== expectedAggregatorSha256 ||
      (recovery.rawTreeSha256 !== undefined &&
        recovery.rawTreeSha256 !== treeSha256(`${root}/raw`)) ||
      command?.id !== "aggregate-final-overhead-recovery" || command.exitCode !== 0 ||
      command.aggregatorSha256 !== recovery.aggregatorSha256 ||
      !existsSync(reportPath)) {
    throw new Error("existing aggregation recovery is incomplete or does not match this aggregator");
  }
  const reportRecovery = json(reportPath).provenance?.aggregationRecovery;
  if (reportRecovery?.aggregatorSha256 !== recovery.aggregatorSha256 ||
      reportRecovery?.rawMeasurementsReused !== true) {
    throw new Error("existing recovered report lacks matching recovery provenance");
  }
  // Legacy recoveries did not record rawTreeSha256. Re-derive the report in a
  // private directory so idempotent validation still proves that the retained
  // raw files, current hashed aggregator, and published report agree exactly.
  const staged = mkdtempSync(join(tmpdir(), "swiyu-aggregation-validation-"));
  try {
    cpSync(`${root}/raw`, `${staged}/raw`, { recursive: true });
    cpSync(commandLogPath, `${staged}/command-log.jsonl`);
    writeFileSync(`${staged}/metadata.json`, `${JSON.stringify({
      ...value,
      completed: true,
      aggregationRecovery: reportRecovery,
    }, null, 2)}\n`);
    const validation = spawnSync(process.execPath, [
      "--experimental-strip-types",
      aggregator,
      "--results-root", staged,
      "--out", `${staged}/zk-overhead-results.json`,
    ], { encoding: "utf8" });
    if (validation.status !== 0) {
      throw new Error(`completed recovery cannot be re-aggregated: ${validation.stderr || validation.stdout}`);
    }
    const published = json(reportPath);
    const rederived = json(`${staged}/zk-overhead-results.json`);
    published.generatedAt = rederived.generatedAt;
    if (!isDeepStrictEqual(published, rederived)) {
      throw new Error("published recovered report does not match the retained raw measurements");
    }
  } finally {
    rmSync(staged, { recursive: true, force: true });
  }
}
function json(path) { return JSON.parse(readFileSync(path, "utf8")); }
function required(name) {
  const index = process.argv.indexOf(name);
  const value = index < 0 ? undefined : process.argv[index + 1];
  if (!value) throw new Error(`missing ${name}`);
  return value;
}

/**
 * File-backed scoped-nullifier state benchmark shared by the no-ZK and ZK
 * profiles. Cryptography is deliberately outside this harness: both verifier
 * paths consume the same verified 32-byte nullifier and pay this identical
 * lookup/atomic-claim cost.
 */
import { fork, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";

const SELF = fileURLToPath(import.meta.url);
const ITERATIONS = Number(arg("--iterations") ?? "1000");
const RUNS = Number(arg("--runs") ?? "3");
const ADAPTIVE = process.argv.includes("--adaptive");
const OUTPUT = arg("--out");
const STORE_BUSY_TIMEOUT_MS = 5000;
const SQLITE_SYNCHRONOUS_FULL = 2;
const INJECTED_ROLLBACK_ERROR = "injected failure after spent-nullifier insert";
const RACE_START_GATE_LEAD_MS = 50;
const RACE_ACCEPTED_TRANSACTION_HOLD_MS = 25;
// Exact canonical values emitted by the scoped-nullifier control fixture and
// SDK profile. The aggregate asserts the digest against the control policy so
// state measurements cannot silently drift to another namespace/scope.
const NAMESPACE = Buffer.from("9kqRGZrFjDRXZwGF6wUVoA3lGIV3PaMAon1n059_ObQ", "base64url");
const SCOPE_HASH = Buffer.from("7btu2jTuYE3p4jXUQOTDYligVCObaNNCZ5LrIfFqDQM", "base64url");

if (process.argv.includes("--race-worker")) {
  raceWorker();
} else if (process.argv.includes("--worker")) {
  process.stdout.write(`${JSON.stringify(runWorker(Number(arg("--run") ?? "1")))}\n`);
} else {
  const rawRuns = [runFreshProcess(1), runFreshProcess(2)];
  const relativeDeltas = stateRelativeDeltas(rawRuns[0], rawRuns[1]);
  const expanded = Object.values(relativeDeltas).some((value) => value > 0.15);
  const requiredRuns = ADAPTIVE ? (expanded ? 7 : 3) : RUNS;
  while (rawRuns.length < requiredRuns) rawRuns.push(runFreshProcess(rawRuns.length + 1));
  const concurrency = [];
  for (const workers of [2, 4, 8]) {
    concurrency.push(await runConcurrency(workers, "same-nullifier"));
    concurrency.push(await runConcurrency(workers, "distinct-nullifiers"));
  }
  const report = {
    schema: "swiyu.nullifier-state-benchmark.v2",
    generatedAt: new Date().toISOString(),
    runtime: { node: process.version, platform: process.platform, arch: process.arch },
    store: {
      engine: "node:sqlite DatabaseSync / SQLite",
      journalMode: "WAL",
      synchronous: "FULL",
      busyTimeoutMs: STORE_BUSY_TIMEOUT_MS,
      tables: [
        "consumed_nullifiers WITHOUT ROWID; PRIMARY KEY(namespace, scope_hash, nullifier)",
        "accepted_claims WITHOUT ROWID; PRIMARY KEY(namespace, scope_hash, nullifier); foreign key to consumed_nullifiers",
      ],
      atomicClaim: "BEGIN IMMEDIATE; insert spent key; insert paired accepted claim; COMMIT",
    },
    semantics: {
      lookupIsAdvisory: true,
      acceptanceRequiresAtomicInsert: true,
      acceptanceTransaction: "spent-nullifier and accepted-claim rows commit or roll back together",
      insertionOccursOnlyAfterCryptographicVerification: "enforced by caller lifecycle; this state-only harness receives verified nullifiers",
      sharedByProfiles: ["scoped-nullifier no-ZK", "scoped-nullifier ZK"],
      registryNamespaceId: NAMESPACE.toString("base64url"),
      scopeDigest: SCOPE_HASH.toString("base64url"),
    },
    iterationsPerRun: ITERATIONS,
    repetitionRule: {
      adaptive: ADAPTIVE,
      thresholdRelativeToFirstTwoMean: 0.15,
      principalStages: principalStages(),
      firstTwoRelativeDeltas: relativeDeltas,
      expanded,
      requiredRuns,
      satisfied: rawRuns.length === requiredRuns,
    },
    rawRuns,
    summary: summarize(rawRuns),
    concurrency,
    correctness: {
      sequentialReplay: rawRuns.every((run) =>
        run.correctness.firstClaimAccepted && run.correctness.replayLookupHit && run.correctness.replayRejected),
      injectedFailureRollsBackBothRows: rawRuns.every((run) =>
        run.correctness.injectedFailureObserved && run.correctness.rollbackLeftCountsUnchanged &&
        run.correctness.rollbackKeyAbsent && run.correctness.noOrphans),
      sameNullifierRacesExactlyOneWinner: concurrency.filter((run) => run.mode === "same-nullifier").every((run) =>
        run.accepted === 1 && run.rejected === run.workers - 1 && run.outcomes === run.workers &&
        run.errors.length === 0 && run.finalCardinality.spentRows === 1 &&
        run.finalCardinality.claimRows === 1 && run.finalCardinality.noOrphans),
      distinctNullifiersAllAccepted: concurrency.filter((run) => run.mode === "distinct-nullifiers").every((run) =>
        run.accepted === run.workers && run.rejected === 0 && run.outcomes === run.workers &&
        run.errors.length === 0 && run.finalCardinality.spentRows === run.workers &&
        run.finalCardinality.claimRows === run.workers && run.finalCardinality.noOrphans),
      everyRaceWorkerUsesFullSynchronous: concurrency.every((run) =>
        run.rawWorkers.every((worker) => worker.storeConfiguration?.synchronous === SQLITE_SYNCHRONOUS_FULL)),
      everyRaceHasActualOverlap: concurrency.every((run) =>
        Number.isInteger(run.overlap.maxConcurrentWorkers) && run.overlap.maxConcurrentWorkers >= 2 &&
        Number.isInteger(run.overlap.pairwiseOverlaps) && run.overlap.pairwiseOverlaps >= 1 &&
        run.overlap.possibleWorkerPairs === run.workers * (run.workers - 1) / 2 &&
        Number.isFinite(run.overlap.operationWindowMs)),
    },
  };
  if (Object.values(report.correctness).some((value) => value !== true)) {
    throw new Error(`nullifier state correctness failed: ${JSON.stringify(report.correctness)}`);
  }
  const rendered = `${JSON.stringify(report, null, 2)}\n`;
  if (OUTPUT) await import("node:fs").then(({ writeFileSync }) => writeFileSync(OUTPUT, rendered));
  process.stdout.write(rendered);
}

function runFreshProcess(run) {
  const argv = ["--no-warnings", SELF, "--worker", "--run", String(run), "--iterations", String(ITERATIONS)];
  return JSON.parse(execFileSync(process.execPath, argv, { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 }));
}

function runWorker(run) {
  const directory = mkdtempSync(join(tmpdir(), `swiyu-nullifier-state-${run}-`));
  const databasePath = join(directory, "nullifiers.sqlite");
  try {
    const setupCpu = process.cpuUsage();
    const setupWall = process.hrtime.bigint();
    const db = openStore(databasePath);
    const setup = elapsed(1, setupWall, setupCpu);
    const storeConfiguration = readStoreConfiguration(db);
    assertStoreConfiguration(storeConfiguration, "serial benchmark worker");
    const operations = prepareStoreOperations(db);

    // Warm statement compilation, page-cache, and transaction paths in a
    // disjoint namespace. Warmup cardinality never contaminates measured keys.
    const warmNamespace = Buffer.from("warmup");
    for (let i = 0; i < 100; i++) {
      const key = digest("warmup", i);
      operations.lookup.get(warmNamespace, SCOPE_HASH, key);
      if (!operations.acceptVerifiedClaim(warmNamespace, SCOPE_HASH, key, i)) {
        throw new Error("warmup claim unexpectedly conflicted");
      }
    }
    const physicalBeforeMeasuredBatch = physicalSizes(databasePath);

    const missKeys = keys("lookup-miss", ITERATIONS);
    const successKeys = keys("insert-success", ITERATIONS);
    const transitionKeys = keys("transition", ITERATIONS);
    const lookupMiss = measure(ITERATIONS, (index) => {
      if (operations.lookup.get(NAMESPACE, SCOPE_HASH, missKeys[index])) throw new Error("unexpected lookup hit");
    });
    const atomicClaimTransactionSuccess = measure(ITERATIONS, (index) => {
      if (!operations.acceptVerifiedClaim(NAMESPACE, SCOPE_HASH, successKeys[index], index)) {
        throw new Error("unique claim transaction rejected");
      }
    });
    const lookupHit = measure(ITERATIONS, (index) => {
      if (!operations.lookup.get(NAMESPACE, SCOPE_HASH, successKeys[index])) throw new Error("inserted nullifier absent");
    });
    const atomicClaimTransactionConflict = measure(ITERATIONS, (index) => {
      if (operations.acceptVerifiedClaim(NAMESPACE, SCOPE_HASH, successKeys[index], index)) {
        throw new Error("replay claim transaction accepted");
      }
    });
    const firstClaimStateTransition = measure(ITERATIONS, (index) => {
      if (operations.lookup.get(NAMESPACE, SCOPE_HASH, transitionKeys[index])) throw new Error("transition key already spent");
      if (!operations.acceptVerifiedClaim(NAMESPACE, SCOPE_HASH, transitionKeys[index], index)) {
        throw new Error("atomic claim transaction lost");
      }
    });

    const replayKey = digest("sequential-replay", run);
    const firstClaimAccepted = operations.acceptVerifiedClaim(NAMESPACE, SCOPE_HASH, replayKey, NOW_MS());
    const replayLookupHit = Boolean(operations.lookup.get(NAMESPACE, SCOPE_HASH, replayKey));
    const replayRejected = !operations.acceptVerifiedClaim(NAMESPACE, SCOPE_HASH, replayKey, NOW_MS());

    const rollbackKey = digest("injected-rollback", run);
    const beforeRollback = readCardinality(db);
    let injectedFailureObserved = false;
    try {
      operations.acceptVerifiedClaim(NAMESPACE, SCOPE_HASH, rollbackKey, NOW_MS(), true);
    } catch (error) {
      if (String(error).includes(INJECTED_ROLLBACK_ERROR)) injectedFailureObserved = true;
      else throw error;
    }
    const afterRollback = readCardinality(db);
    const rollbackLeftCountsUnchanged = sameCardinality(beforeRollback, afterRollback);
    const rollbackKeyAbsent = !operations.lookup.get(NAMESPACE, SCOPE_HASH, rollbackKey);
    const finalCardinality = readCardinality(db);
    const expectedRows = 100 + ITERATIONS * 2 + 1;
    if (finalCardinality.spentRows !== expectedRows || finalCardinality.claimRows !== expectedRows ||
        !finalCardinality.noOrphans) {
      throw new Error(`paired state cardinality mismatch: ${JSON.stringify({ expectedRows, finalCardinality })}`);
    }
    const physicalBeforeCheckpoint = physicalSizes(databasePath);
    db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    db.close();
    const physicalAfterCheckpoint = physicalSizes(databasePath);
    return {
      run,
      iterations: ITERATIONS,
      timings: {
        oneTimeStateStoreSetup: setup,
        lookupMiss,
        atomicClaimTransactionSuccess,
        lookupHit,
        atomicClaimTransactionConflict,
        firstClaimStateTransition,
      },
      storeConfiguration,
      correctness: {
        firstClaimAccepted,
        replayLookupHit,
        replayRejected,
        injectedFailureObserved,
        rollbackLeftCountsUnchanged,
        rollbackKeyAbsent,
        noOrphans: finalCardinality.noOrphans,
        beforeRollback,
        afterRollback,
      },
      sizes: {
        nullifierBytes: 32,
        scopeHashBytes: 32,
        namespaceBytes: NAMESPACE.length,
        logicalPrimaryKeyBytes: NAMESPACE.length + SCOPE_HASH.length + 32,
        expectedRowsPerTable: expectedRows,
        spentRowsAfterRun: finalCardinality.spentRows,
        acceptedClaimRowsAfterRun: finalCardinality.claimRows,
        physicalBeforeMeasuredBatch,
        physicalBeforeCheckpoint,
        physicalAfterCheckpoint,
        physicalGrowthDuringMeasuredBatchBytes:
          totalPhysicalBytes(physicalBeforeCheckpoint) - totalPhysicalBytes(physicalBeforeMeasuredBatch),
      },
      processPeakRssBytes: process.resourceUsage().maxRSS * 1024,
    };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function openStore(path) {
  const db = new DatabaseSync(path);
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=${STORE_BUSY_TIMEOUT_MS}; PRAGMA foreign_keys=ON;`);
  db.exec(`
    CREATE TABLE IF NOT EXISTS consumed_nullifiers(
      namespace BLOB NOT NULL,
      scope_hash BLOB NOT NULL,
      nullifier BLOB NOT NULL,
      accepted_at INTEGER NOT NULL,
      PRIMARY KEY(namespace, scope_hash, nullifier)
    ) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS accepted_claims(
      namespace BLOB NOT NULL,
      scope_hash BLOB NOT NULL,
      nullifier BLOB NOT NULL,
      claim_digest BLOB NOT NULL,
      accepted_at INTEGER NOT NULL,
      PRIMARY KEY(namespace, scope_hash, nullifier),
      FOREIGN KEY(namespace, scope_hash, nullifier)
        REFERENCES consumed_nullifiers(namespace, scope_hash, nullifier)
        ON DELETE RESTRICT
    ) WITHOUT ROWID;
  `);
  assertStoreConfiguration(readStoreConfiguration(db), "opened state store");
  return db;
}

function prepareStoreOperations(db) {
  const lookup = db.prepare("SELECT 1 AS present FROM consumed_nullifiers WHERE namespace = ? AND scope_hash = ? AND nullifier = ?");
  const insertSpent = db.prepare(`
    INSERT INTO consumed_nullifiers(namespace, scope_hash, nullifier, accepted_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(namespace, scope_hash, nullifier) DO NOTHING
    RETURNING 1 AS accepted
  `);
  const insertClaim = db.prepare(`
    INSERT INTO accepted_claims(namespace, scope_hash, nullifier, claim_digest, accepted_at)
    VALUES (?, ?, ?, ?, ?)
  `);
  return {
    lookup,
    acceptVerifiedClaim(
      namespace,
      scopeHash,
      nullifier,
      acceptedAt,
      injectFailureAfterSpentInsert = false,
      holdAcceptedTransactionMs = 0,
    ) {
      let transactionOpen = false;
      try {
        db.exec("BEGIN IMMEDIATE");
        transactionOpen = true;
        const accepted = Boolean(insertSpent.get(namespace, scopeHash, nullifier, acceptedAt));
        if (accepted) {
          if (injectFailureAfterSpentInsert) throw new Error(INJECTED_ROLLBACK_ERROR);
          const result = insertClaim.run(
            namespace,
            scopeHash,
            nullifier,
            claimDigest(nullifier),
            acceptedAt,
          );
          if (Number(result.changes) !== 1) throw new Error("paired accepted-claim insert failed");
          if (holdAcceptedTransactionMs > 0) sleepBlocking(holdAcceptedTransactionMs);
        }
        db.exec("COMMIT");
        transactionOpen = false;
        return accepted;
      } catch (error) {
        if (transactionOpen) db.exec("ROLLBACK");
        throw error;
      }
    },
  };
}

function readStoreConfiguration(db) {
  return {
    journalMode: String(pragmaValue(db, "journal_mode")).toUpperCase(),
    synchronous: Number(pragmaValue(db, "synchronous")),
    busyTimeoutMs: Number(pragmaValue(db, "busy_timeout")),
    foreignKeys: Number(pragmaValue(db, "foreign_keys")),
  };
}

function assertStoreConfiguration(configuration, label) {
  if (configuration.journalMode !== "WAL" ||
      configuration.synchronous !== SQLITE_SYNCHRONOUS_FULL ||
      configuration.busyTimeoutMs !== STORE_BUSY_TIMEOUT_MS ||
      configuration.foreignKeys !== 1) {
    throw new Error(`${label} has unexpected SQLite configuration: ${JSON.stringify(configuration)}`);
  }
}

function pragmaValue(db, name) {
  const row = db.prepare(`PRAGMA ${name}`).get();
  return Object.values(row)[0];
}

function readCardinality(db) {
  const spentRows = Number(db.prepare("SELECT count(*) AS count FROM consumed_nullifiers").get().count);
  const claimRows = Number(db.prepare("SELECT count(*) AS count FROM accepted_claims").get().count);
  const spentWithoutClaim = Number(db.prepare(`
    SELECT count(*) AS count
    FROM consumed_nullifiers AS spent
    LEFT JOIN accepted_claims AS claim
      USING(namespace, scope_hash, nullifier)
    WHERE claim.nullifier IS NULL
  `).get().count);
  const claimsWithoutSpent = Number(db.prepare(`
    SELECT count(*) AS count
    FROM accepted_claims AS claim
    LEFT JOIN consumed_nullifiers AS spent
      USING(namespace, scope_hash, nullifier)
    WHERE spent.nullifier IS NULL
  `).get().count);
  return {
    spentRows,
    claimRows,
    spentWithoutClaim,
    claimsWithoutSpent,
    noOrphans: spentWithoutClaim === 0 && claimsWithoutSpent === 0,
  };
}

function sameCardinality(left, right) {
  return left.spentRows === right.spentRows && left.claimRows === right.claimRows &&
    left.spentWithoutClaim === right.spentWithoutClaim &&
    left.claimsWithoutSpent === right.claimsWithoutSpent;
}

function intervalOverlap(results) {
  const intervals = results.map((result) => ({
    start: BigInt(result.startedMonotonicNs),
    end: BigInt(result.endedMonotonicNs),
  }));
  const latestStart = intervals.reduce((maximum, interval) => interval.start > maximum ? interval.start : maximum, intervals[0].start);
  const earliestEnd = intervals.reduce((minimum, interval) => interval.end < minimum ? interval.end : minimum, intervals[0].end);
  const earliestStart = intervals.reduce((minimum, interval) => interval.start < minimum ? interval.start : minimum, intervals[0].start);
  const latestEnd = intervals.reduce((maximum, interval) => interval.end > maximum ? interval.end : maximum, intervals[0].end);
  let pairwiseOverlaps = 0;
  for (let left = 0; left < intervals.length; left++) {
    for (let right = left + 1; right < intervals.length; right++) {
      if (intervals[left].start < intervals[right].end && intervals[right].start < intervals[left].end) {
        pairwiseOverlaps++;
      }
    }
  }
  const events = intervals.flatMap((interval) => [
    { at: interval.start, delta: 1 },
    { at: interval.end, delta: -1 },
  ]).sort((left, right) => left.at === right.at ? left.delta - right.delta : left.at < right.at ? -1 : 1);
  let active = 0;
  let maxConcurrentWorkers = 0;
  for (const event of events) {
    active += event.delta;
    maxConcurrentWorkers = Math.max(maxConcurrentWorkers, active);
  }
  return {
    allWorkersOverlap: earliestEnd > latestStart,
    allWorkerOverlapMs: Number(earliestEnd > latestStart ? earliestEnd - latestStart : 0n) / 1e6,
    pairwiseOverlaps,
    possibleWorkerPairs: intervals.length * (intervals.length - 1) / 2,
    maxConcurrentWorkers,
    operationWindowMs: Number(latestEnd - earliestStart) / 1e6,
  };
}

function sleepBlocking(milliseconds) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

async function runConcurrency(workers, mode) {
  const directory = mkdtempSync(join(tmpdir(), `swiyu-nullifier-race-${workers}-`));
  const databasePath = join(directory, "nullifiers.sqlite");
  openStore(databasePath).close();
  try {
    const children = Array.from({ length: workers }, (_, index) => fork(SELF, [
      "--race-worker",
      "--database", databasePath,
      "--mode", mode,
      "--index", String(index),
    ], { stdio: ["ignore", "ignore", "inherit", "ipc"], execArgv: [...new Set([...process.execArgv, "--no-warnings"])] }));
    let results;
    let started;
    try {
      await Promise.all(children.map((child) => waitReady(child, 10_000)));
      const resultsPromise = Promise.all(children.map((child) => waitResult(child, 15_000)));
      started = process.hrtime.bigint();
      const startGateNs = started + BigInt(RACE_START_GATE_LEAD_MS) * 1_000_000n;
      for (const child of children) child.send({ startGateNs: startGateNs.toString() });
      results = await resultsPromise;
    } catch (error) {
      for (const child of children) if (child.exitCode === null) child.kill("SIGTERM");
      throw error;
    }
    const wallMs = Number(process.hrtime.bigint() - started) / 1e6;
    const finalDb = openStore(databasePath);
    const finalCardinality = readCardinality(finalDb);
    finalDb.close();
    const overlap = intervalOverlap(results);
    return {
      mode,
      workers,
      accepted: results.filter((result) => result.accepted).length,
      rejected: results.filter((result) => !result.accepted && !result.error).length,
      outcomes: results.length,
      errors: results.filter((result) => result.error).map((result) => result.error),
      finalCardinality,
      overlap,
      raceInstrumentation: {
        startGateLeadMs: RACE_START_GATE_LEAD_MS,
        acceptedTransactionHoldMs: RACE_ACCEPTED_TRANSACTION_HOLD_MS,
        note: "The accepted writer holds its transaction only in this correctness stress test; serial latency excludes this hold.",
      },
      wallMs,
      summedCpuMs: results.reduce((sum, result) => sum + result.cpuMs, 0),
      maxWorkerRssBytes: Math.max(...results.map((result) => result.processPeakRssBytes)),
      summedWorkerPeakRssUpperBoundBytes: results.reduce((sum, result) => sum + result.processPeakRssBytes, 0),
      rawWorkers: results,
    };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function raceWorker() {
  // Journal mode and schema are established once by the parent before any
  // worker starts. Reissuing PRAGMA journal_mode=WAL concurrently can itself
  // require a lock and deadlock the readiness barrier.
  const db = new DatabaseSync(requiredArg("--database"));
  // Install the busy handler before touching any other connection-local
  // setting: workers open concurrently and WAL recovery/configuration may
  // briefly hold a database lock.
  db.exec(`PRAGMA busy_timeout=${STORE_BUSY_TIMEOUT_MS}; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;`);
  const storeConfiguration = readStoreConfiguration(db);
  assertStoreConfiguration(storeConfiguration, `race worker ${process.pid}`);
  const index = Number(requiredArg("--index"));
  const mode = requiredArg("--mode");
  const operations = prepareStoreOperations(db);
  process.send?.({ ready: true, storeConfiguration });
  process.once("message", (message) => {
    const startGateNs = BigInt(message.startGateNs);
    const delayMs = Math.max(0, Number(startGateNs - process.hrtime.bigint()) / 1e6);
    setTimeout(() => {
    const key = digest("race", mode === "same-nullifier" ? 0 : index);
    const cpu = process.cpuUsage();
    const wall = process.hrtime.bigint();
    const startedMonotonicNs = wall.toString();
    try {
      const accepted = operations.acceptVerifiedClaim(
        NAMESPACE,
        SCOPE_HASH,
        key,
        NOW_MS(),
        false,
        RACE_ACCEPTED_TRANSACTION_HOLD_MS,
      );
      const endedMonotonicNs = process.hrtime.bigint().toString();
      const timing = elapsed(1, wall, cpu);
      db.close();
      process.send?.({
        index,
        accepted,
        keyDigest: key.toString("base64url"),
        startedMonotonicNs,
        endedMonotonicNs,
        wallMs: timing.wallMsPerOperation,
        cpuMs: timing.cpuMsPerOperation,
        processPeakRssBytes: process.resourceUsage().maxRSS * 1024,
        storeConfiguration,
      });
    } catch (error) {
      const endedMonotonicNs = process.hrtime.bigint().toString();
      db.close();
      process.send?.({
        index,
        accepted: false,
        keyDigest: key.toString("base64url"),
        startedMonotonicNs,
        endedMonotonicNs,
        error: String(error),
        cpuMs: 0,
        processPeakRssBytes: process.resourceUsage().maxRSS * 1024,
        storeConfiguration,
      });
    }
    }, delayMs);
  });
}

function waitReady(child, timeoutMs) {
  return new Promise((resolve, reject) => {
    let ready = false;
    const timer = setTimeout(() => finish(new Error(`race worker ${child.pid} did not become ready within ${timeoutMs} ms`)), timeoutMs);
    const finish = (error) => {
      clearTimeout(timer);
      child.off("error", onError);
      child.off("exit", onExit);
      child.off("message", onMessage);
      if (error) reject(error); else resolve();
    };
    const onError = (error) => finish(error);
    const onExit = (code, signal) => { if (!ready) finish(new Error(`race worker ${child.pid} exited before ready: code=${code} signal=${signal}`)); };
    const onMessage = (message) => { if (message?.ready) { ready = true; finish(); } };
    child.once("error", onError);
    child.once("exit", onExit);
    child.on("message", onMessage);
  });
}
function waitResult(child, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => finish(new Error(`race worker ${child.pid} did not return within ${timeoutMs} ms`)), timeoutMs);
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.off("error", onError);
      child.off("exit", onExit);
      child.off("message", onMessage);
      if (error) reject(error); else resolve(value);
    };
    const onError = (error) => finish(error);
    const onExit = (code, signal) => finish(new Error(`race worker ${child.pid} exited before result: code=${code} signal=${signal}`));
    const onMessage = (message) => {
      if (!message?.ready) {
        finish(undefined, message);
        child.disconnect();
      }
    };
    child.once("error", onError);
    child.once("exit", onExit);
    child.on("message", onMessage);
  });
}

function principalStages() {
  return ["lookupMiss", "atomicClaimTransactionSuccess", "lookupHit", "atomicClaimTransactionConflict", "firstClaimStateTransition"];
}
function stateRelativeDeltas(first, second) {
  return Object.fromEntries(principalStages().map((stage) => {
    const a = first.timings[stage].wallMsPerOperation;
    const b = second.timings[stage].wallMsPerOperation;
    return [stage, Math.abs(a - b) / ((a + b) / 2)];
  }));
}
function summarize(runs) {
  return Object.fromEntries(["oneTimeStateStoreSetup", ...principalStages()].map((stage) => [stage, {
    wallMs: stats(runs.map((run) => run.timings[stage].wallMsPerOperation)),
    cpuMs: stats(runs.map((run) => run.timings[stage].cpuMsPerOperation)),
  }]));
}
function measure(iterations, operation) {
  const cpu = process.cpuUsage();
  const wall = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) operation(i);
  return elapsed(iterations, wall, cpu);
}
function elapsed(iterations, wall, cpu) {
  const wallMs = Number(process.hrtime.bigint() - wall) / 1e6;
  const used = process.cpuUsage(cpu);
  const cpuMs = (used.user + used.system) / 1000;
  return { wallMsPerOperation: wallMs / iterations, cpuMsPerOperation: cpuMs / iterations, totalWallMs: wallMs, totalCpuMs: cpuMs };
}
function stats(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  const variance = values.length > 1 ? values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / (values.length - 1) : 0;
  const standardDeviation = Math.sqrt(variance);
  const median = sorted[Math.floor(sorted.length / 2)];
  const deviations = values.map((value) => Math.abs(value - median)).sort((a, b) => a - b);
  return { min: sorted[0], median, max: sorted.at(-1), mean, variance, standardDeviation, coefficientOfVariation: mean === 0 ? 0 : standardDeviation / mean, medianAbsoluteDeviation: deviations[Math.floor(deviations.length / 2)], raw: values };
}
function physicalSizes(path) {
  return {
    databaseFileBytes: existsSync(path) ? statSync(path).size : 0,
    walFileBytes: existsSync(`${path}-wal`) ? statSync(`${path}-wal`).size : 0,
    shmFileBytes: existsSync(`${path}-shm`) ? statSync(`${path}-shm`).size : 0,
  };
}
function totalPhysicalBytes(value) { return value.databaseFileBytes + value.walFileBytes + value.shmFileBytes; }
function keys(label, count) { return Array.from({ length: count }, (_, index) => digest(label, index)); }
function digest(label, index) { return createHash("sha256").update(`${label}:${index}`).digest(); }
function claimDigest(nullifier) { return createHash("sha256").update("verified-claim:").update(nullifier).digest(); }
function NOW_MS() { return Date.now(); }
function arg(name) { const index = process.argv.indexOf(name); return index === -1 ? undefined : process.argv[index + 1]; }
function requiredArg(name) { const value = arg(name); if (value === undefined) throw new Error(`missing ${name}`); return value; }

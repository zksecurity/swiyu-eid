import { mkdirSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  FixedIndexStatusTree,
  type StatusBit,
} from "../../openac-sdk/src/status-designs/fixed-index-merkle.ts";
import { SparseStatusTree } from "../../openac-sdk/src/status-designs/sparse-merkle.ts";
import {
  byte,
  hashDomain,
  u64,
} from "../../openac-sdk/src/status-designs/hashing.ts";

export const STATUS_PROOF_BENCHMARK_EPOCH = 1_725_000_000;
export const STATUS_PROOF_BENCHMARK_QUERY = 42;
export const STATUS_PROOF_BENCHMARK_QUERY_SALT = Uint8Array.from(
  createHash("sha256")
    .update("swiyu-status-proof-benchmark-query-salt-v1", "utf8")
    .digest(),
);

export interface StatusProofBenchmarkFixture {
  readonly profile: "dense-fixed-index-status-v1" | "sparse-valid-nonmembership-v1";
  readonly circuit: "swiyu_status_dense_17_bench" | "swiyu_status_sparse_64_bench";
  readonly input: Readonly<Record<string, unknown>>;
}

function hexBytes(hash: string): number[] {
  if (!/^[0-9a-f]{64}$/u.test(hash)) {
    throw new Error("expected a lowercase 32-byte hash");
  }
  return Array.from(hash.matchAll(/../gu), ([octet]) => Number.parseInt(octet, 16));
}

function digestLimbs(hash: string): readonly [string, string] {
  return [
    BigInt(`0x${hash.slice(0, 32)}`).toString(10),
    BigInt(`0x${hash.slice(32)}`).toString(10),
  ];
}

export function createStatusProofBenchmarkFixtures(): readonly [
  StatusProofBenchmarkFixture,
  StatusProofBenchmarkFixture,
] {
  const statuses = Array<StatusBit>(256).fill(0);
  for (const revoked of [3, 64, 191, 255]) statuses[revoked] = 1;
  const denseTree = FixedIndexStatusTree.buildSwiyuProfile(
    statuses,
    STATUS_PROOF_BENCHMARK_EPOCH,
  );
  const denseWitness = denseTree.witness(STATUS_PROOF_BENCHMARK_QUERY);
  const [denseRootHi, denseRootLo] = digestLimbs(denseWitness.root);
  const [denseHandleHi, denseHandleLo] = digestLimbs(
    hashDomain(
      "swiyu-status-query-v1",
      byte(1),
      u64(STATUS_PROOF_BENCHMARK_QUERY),
      STATUS_PROOF_BENCHMARK_QUERY_SALT,
    ),
  );

  const sparseTree = SparseStatusTree.build(
    [3n, 64n, 191n, 255n],
    STATUS_PROOF_BENCHMARK_EPOCH,
  );
  const sparseWitness = sparseTree.witness(STATUS_PROOF_BENCHMARK_QUERY);
  if (sparseWitness.revoked) throw new Error("benchmark query must be valid");
  const [sparseRootHi, sparseRootLo] = digestLimbs(sparseWitness.root);
  const [sparseHandleHi, sparseHandleLo] = digestLimbs(
    hashDomain(
      "swiyu-status-query-v1",
      byte(2),
      u64(STATUS_PROOF_BENCHMARK_QUERY),
      STATUS_PROOF_BENCHMARK_QUERY_SALT,
    ),
  );

  return [
    {
      profile: "dense-fixed-index-status-v1",
      circuit: "swiyu_status_dense_17_bench",
      input: {
        statusIndex: denseWitness.index,
        statusValue: denseWitness.status,
        siblings: denseWitness.siblings.map(hexBytes),
        listLength: denseWitness.entryCount,
        querySalt: [...STATUS_PROOF_BENCHMARK_QUERY_SALT],
        snapshotEpoch: denseWitness.epoch,
        expectedSnapshotRootHi: denseRootHi,
        expectedSnapshotRootLo: denseRootLo,
        expectedQueryHandleHi: denseHandleHi,
        expectedQueryHandleLo: denseHandleLo,
      },
    },
    {
      profile: "sparse-valid-nonmembership-v1",
      circuit: "swiyu_status_sparse_64_bench",
      input: {
        identifier: sparseWitness.identifier,
        revoked: 0,
        siblings: sparseWitness.siblings.map(hexBytes),
        querySalt: [...STATUS_PROOF_BENCHMARK_QUERY_SALT],
        snapshotEpoch: sparseWitness.epoch,
        expectedSnapshotRootHi: sparseRootHi,
        expectedSnapshotRootLo: sparseRootLo,
        expectedQueryHandleHi: sparseHandleHi,
        expectedQueryHandleLo: sparseHandleLo,
      },
    },
  ];
}

export function writeStatusProofBenchmarkFixtures(outputDirectory: string): void {
  mkdirSync(outputDirectory, { recursive: true });
  for (const fixture of createStatusProofBenchmarkFixtures()) {
    writeFileSync(
      resolve(outputDirectory, `${fixture.circuit}.json`),
      `${JSON.stringify(fixture.input, null, 2)}\n`,
      { encoding: "utf8", mode: 0o600 },
    );
  }
}

const invokedPath = process.argv[1];
if (invokedPath && import.meta.url === pathToFileURL(resolve(invokedPath)).href) {
  const here = dirname(fileURLToPath(import.meta.url));
  const outputDirectory = resolve(
    process.argv[2] ?? resolve(here, "../build/status-proof-benchmark-inputs"),
  );
  writeStatusProofBenchmarkFixtures(outputDirectory);
  process.stdout.write(`${outputDirectory}\n`);
}

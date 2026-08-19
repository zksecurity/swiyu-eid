import { performance } from "node:perf_hooks";
import { p256 } from "@noble/curves/p256";
import { describe, expect, it } from "vitest";
import {
  FixedIndexStatusTree,
  LeanImtPlusTree,
  SparseStatusTree,
  Ts13AdjacentPairRegistry,
  type StatusBit,
} from "../src/status-designs/index.js";

const ENABLED = process.env.STATUS_DESIGN_BENCHMARK === "1";
const SIZES = [256, 4_096, 65_536] as const;
const EPOCH = 1_725;
const PRIVATE_KEY = Uint8Array.from([
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
]);
const PUBLIC_KEY = p256.getPublicKey(PRIVATE_KEY, false);

interface Timing {
  readonly p50: number;
  readonly p95: number;
}

interface BenchmarkRow {
  readonly design: string;
  readonly issuedSlots: number;
  readonly revokedEntries: number;
  readonly build: Timing;
  readonly update: Timing;
  readonly witness: Timing;
  readonly witnessBytes: number;
  readonly verifierInput: string;
}

describe.runIf(ENABLED)("Prototype B deterministic status-design benchmark", () => {
  it(
    "reports build, update, witness p50/p95 and serialized witness bytes",
    () => {
      const rows = SIZES.flatMap((size) => benchmarkSize(size));
      expect(rows).toHaveLength(SIZES.length * 4);
      for (const row of rows) {
        expect(row.build.p50).toBeGreaterThanOrEqual(0);
        expect(row.update.p95).toBeGreaterThanOrEqual(row.update.p50);
        expect(row.witnessBytes).toBeGreaterThan(0);
      }
      console.log(renderMarkdown(rows));
    },
    180_000,
  );
});

function benchmarkSize(size: number): BenchmarkRow[] {
  // This fixture models a 1.5625% revoked population: one deterministic entry
  // per 64 issued slots. "Size" is issued capacity, not revoked-set size.
  const revoked = Array.from(
    { length: Math.ceil(size / 64) },
    (_, index) => BigInt(index * 64 + 32),
  ).filter((identifier) => identifier < BigInt(size));
  // Pick a non-revoked interior identifier so LeanIMT+ measures a normal path,
  // not the unusually cheap repeated promotions of the physical tail.
  const target = BigInt(Math.floor(size / 2) + 1);
  const statuses = Array<StatusBit>(size).fill(0);
  for (const identifier of revoked) statuses[Number(identifier)] = 1;

  let dense = FixedIndexStatusTree.buildSwiyuProfile(statuses, EPOCH);
  const denseBuild = sample(5, () => {
    dense = FixedIndexStatusTree.buildSwiyuProfile(statuses, EPOCH);
  });
  const denseUpdate = sample(5, (iteration) => {
    dense = dense.update(
      Number(target),
      (iteration % 2 === 0 ? 1 : 0) as StatusBit,
      EPOCH,
    );
  });
  if (dense.witness(Number(target)).status !== 1) {
    dense = dense.update(Number(target), 1, EPOCH);
  }
  const denseWitnessTiming = sample(25, () => dense.witness(Number(target)));
  const denseWitness = dense.witness(Number(target));
  expect(
    FixedIndexStatusTree.verify(denseWitness, {
      root: dense.root,
      epoch: dense.epoch,
      expectedStatus: denseWitness.status,
      fixedDepth: dense.depth,
    }),
  ).toBe(true);

  let sparse = SparseStatusTree.build(revoked, EPOCH);
  const sparseBuild = sample(5, () => {
    sparse = SparseStatusTree.build(revoked, EPOCH);
  });
  const sparseUpdate = sample(5, (iteration) => {
    sparse.setRevoked(target, iteration % 2 === 0);
  });
  sparse.setRevoked(target, false);
  const sparseWitnessTiming = sample(25, () => sparse.witness(target));
  const sparseWitness = sparse.witness(target);
  expect(
    SparseStatusTree.verify(sparseWitness, {
      root: sparse.root,
      epoch: sparse.epoch,
      expectedRevoked: false,
    }),
  ).toBe(true);

  let lean = LeanImtPlusTree.build(revoked, EPOCH);
  const leanBuild = sample(5, () => {
    lean = LeanImtPlusTree.build(revoked, EPOCH);
  });
  const leanUpdate = sample(5, (iteration) => {
    if (iteration % 2 === 0) lean.insert(target);
    else lean.remove(target);
  });
  if (lean.has(target)) lean.remove(target);
  const leanWitnessTiming = sample(25, () => lean.nonMembershipWitness(target));
  const leanWitness = lean.nonMembershipWitness(target);
  expect(
    LeanImtPlusTree.verify(leanWitness, {
      root: lean.root,
      epoch: lean.epoch,
      expectedMode: "non-membership",
    }),
  ).toBe(true);
  const leanHashes = leanWitness.path.filter((step) => step.sibling !== null).length;

  let ts13 = Ts13AdjacentPairRegistry.build(revoked, EPOCH, PRIVATE_KEY);
  const ts13Build = sample(5, () => {
    ts13 = Ts13AdjacentPairRegistry.build(revoked, EPOCH, PRIVATE_KEY);
  });
  const ts13Update = sample(5, (iteration) => {
    ts13 = Ts13AdjacentPairRegistry.build(
      [...revoked, target],
      EPOCH + iteration + 1,
      PRIVATE_KEY,
    );
  });
  ts13 = Ts13AdjacentPairRegistry.build(revoked, EPOCH, PRIVATE_KEY);
  const ts13WitnessTiming = sample(25, () => ts13.witness(target));
  const ts13Witness = ts13.witness(target);
  expect(
    Ts13AdjacentPairRegistry.verify(ts13Witness, {
      epoch: ts13.epoch,
      revokerPublicKey: PUBLIC_KEY,
    }),
  ).toBe(true);

  return [
    {
      design: "selected dense fixed-index",
      issuedSlots: size,
      revokedEntries: revoked.length,
      build: denseBuild,
      update: denseUpdate,
      witness: denseWitnessTiming,
      witnessBytes: serializedBytes(denseWitness),
      verifierInput: `${denseWitness.siblings.length} SHA-256 path siblings + 2-bit status`,
    },
    {
      design: "sparse revoked set",
      issuedSlots: size,
      revokedEntries: revoked.length,
      build: sparseBuild,
      update: sparseUpdate,
      witness: sparseWitnessTiming,
      witnessBytes: serializedBytes(sparseWitness),
      verifierInput: `${sparseWitness.siblings.length} SHA-256 path siblings + membership bit`,
    },
    {
      design: "zkID LeanIMT+",
      issuedSlots: size,
      revokedEntries: revoked.length,
      build: leanBuild,
      update: leanUpdate,
      witness: leanWitnessTiming,
      witnessBytes: serializedBytes(leanWitness),
      verifierInput: `${leanHashes} SHA-256 path siblings + predecessor ordering`,
    },
    {
      design: "EUDI TS13 adjacent pair",
      issuedSlots: size,
      revokedEntries: revoked.length,
      build: ts13Build,
      update: ts13Update,
      witness: ts13WitnessTiming,
      witnessBytes: serializedBytes(ts13Witness),
      verifierInput: "1 P-256 signature + 2 uint64 strict comparisons",
    },
  ];
}

function sample(
  count: number,
  operation: (iteration: number) => unknown,
): Timing {
  const samples: number[] = [];
  for (let iteration = 0; iteration < count; iteration += 1) {
    const start = performance.now();
    operation(iteration);
    samples.push(performance.now() - start);
  }
  samples.sort((left, right) => left - right);
  return {
    p50: percentile(samples, 0.5),
    p95: percentile(samples, 0.95),
  };
}

function percentile(sorted: readonly number[], fraction: number): number {
  return sorted[Math.ceil(sorted.length * fraction) - 1]!;
}

function serializedBytes(value: unknown): number {
  return new TextEncoder().encode(JSON.stringify(value)).length;
}

function renderMarkdown(rows: readonly BenchmarkRow[]): string {
  const header = [
    "",
    "Prototype B executable benchmark (milliseconds; witness size is JSON bytes)",
    "",
    "| design | issued | revoked | build p50/p95 | update p50/p95 | witness p50/p95 | witness bytes | verifier / circuit input |",
    "|---|---:|---:|---:|---:|---:|---:|---|",
  ];
  const body = rows.map(
    (row) =>
      `| ${row.design} | ${row.issuedSlots} | ${row.revokedEntries} | ${format(row.build)} | ${format(row.update)} | ${format(row.witness)} | ${row.witnessBytes} | ${row.verifierInput} |`,
  );
  return [...header, ...body, ""].join("\n");
}

function format(timing: Timing): string {
  return `${timing.p50.toFixed(3)}/${timing.p95.toFixed(3)}`;
}

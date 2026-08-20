import assert from "node:assert/strict";
import type { WitnessTester } from "circomkit";

import {
  createStatusProofBenchmarkFixtures,
  STATUS_PROOF_BENCHMARK_EPOCH,
  STATUS_PROOF_BENCHMARK_QUERY,
} from "../../src/status-proof-benchmark-fixtures.ts";
import { circomkit } from "../common/index.ts";

type BenchmarkInput = Record<string, unknown>;

const clone = (input: Readonly<Record<string, unknown>>): BenchmarkInput =>
  structuredClone(input) as BenchmarkInput;

const expectRejected = async (
  circuit: WitnessTester<string[], ["valid"]>,
  input: BenchmarkInput,
): Promise<void> => {
  await assert.rejects(circuit.calculateWitness(input));
};

describe("Prototype B same-system status proof benchmarks", function () {
  this.timeout(1_200_000);
  const [denseFixture, sparseFixture] = createStatusProofBenchmarkFixtures();

  describe("benchmark-only query composition anchor", () => {
    let denseAnchor: WitnessTester<["query", "salt"], ["hi", "lo"]>;
    let sparseAnchor: WitnessTester<["query", "salt"], ["hi", "lo"]>;

    before(async () => {
      [denseAnchor, sparseAnchor] = await Promise.all([
        circomkit.WitnessTester("SwiyuDenseStatusQueryHandle", {
          file: "swiyu/status-proof-benchmark",
          template: "SwiyuStatusQueryHandle",
          params: [1],
          recompile: true,
        }),
        circomkit.WitnessTester("SwiyuSparseStatusQueryHandle", {
          file: "swiyu/status-proof-benchmark",
          template: "SwiyuStatusQueryHandle",
          params: [2],
          recompile: true,
        }),
      ]);
    });

    it("matches the external TypeScript handles and separates both designs", async () => {
      const input = {
        query: STATUS_PROOF_BENCHMARK_QUERY,
        salt: denseFixture.input.querySalt,
      };
      const denseWitness = await denseAnchor.calculateWitness(input);
      const sparseWitness = await sparseAnchor.calculateWitness(input);
      await denseAnchor.expectConstraintPass(denseWitness);
      await sparseAnchor.expectConstraintPass(sparseWitness);
      assert.deepEqual(
        await denseAnchor.readWitnessSignals(denseWitness, ["hi", "lo"]),
        {
          hi: BigInt(denseFixture.input.expectedQueryHandleHi as string),
          lo: BigInt(denseFixture.input.expectedQueryHandleLo as string),
        },
      );
      assert.deepEqual(
        await sparseAnchor.readWitnessSignals(sparseWitness, ["hi", "lo"]),
        {
          hi: BigInt(sparseFixture.input.expectedQueryHandleHi as string),
          lo: BigInt(sparseFixture.input.expectedQueryHandleLo as string),
        },
      );
    });
  });

  describe("fixed depth-17 dense VALID proof", () => {
    let circuit: WitnessTester<string[], ["valid"]>;

    before(async () => {
      circuit = await circomkit.WitnessTester("SwiyuDenseStatusBenchmark", {
        file: "swiyu/status-proof-benchmark",
        template: "SwiyuDenseStatusBenchmark",
        params: [],
        recompile: true,
      });
    });

    it("accepts the deterministic TypeScript fixture and exposes only success", async () => {
      const witness = await circuit.calculateWitness(denseFixture.input);
      await circuit.expectConstraintPass(witness);
      // Circom witness slot zero is the constant and slot one is the sole
      // public output. Avoid loading the multi-gigabyte debug-symbol map just
      // to read this fixed output.
      assert.equal(witness[1], 1n);
      assert.equal(denseFixture.input.statusIndex, STATUS_PROOF_BENCHMARK_QUERY);
      assert.equal(denseFixture.input.snapshotEpoch, STATUS_PROOF_BENCHMARK_EPOCH);
    });

    it("rejects tampered root, path, index, status, epoch, and query anchor", async () => {
      const root = clone(denseFixture.input);
      root.expectedSnapshotRootLo = (BigInt(root.expectedSnapshotRootLo as string) + 1n).toString();
      await expectRejected(circuit, root);

      const path = clone(denseFixture.input);
      (path.siblings as number[][])[0]![0] ^= 1;
      await expectRejected(circuit, path);

      const index = clone(denseFixture.input);
      index.statusIndex = STATUS_PROOF_BENCHMARK_QUERY + 1;
      await expectRejected(circuit, index);

      const status = clone(denseFixture.input);
      status.statusValue = 1;
      await expectRejected(circuit, status);

      const epoch = clone(denseFixture.input);
      epoch.snapshotEpoch = STATUS_PROOF_BENCHMARK_EPOCH + 1;
      await expectRejected(circuit, epoch);

      const handle = clone(denseFixture.input);
      handle.expectedQueryHandleLo = (
        BigInt(handle.expectedQueryHandleLo as string) + 1n
      ).toString();
      await expectRejected(circuit, handle);

      const salt = clone(denseFixture.input);
      (salt.querySalt as number[])[0] ^= 1;
      await expectRejected(circuit, salt);
    });
  });

  describe("depth-64 sparse valid non-membership proof", () => {
    let circuit: WitnessTester<string[], ["valid"]>;

    before(async () => {
      circuit = await circomkit.WitnessTester("SwiyuSparseStatusBenchmark", {
        file: "swiyu/status-proof-benchmark",
        template: "SwiyuSparseStatusBenchmark",
        params: [],
        recompile: true,
      });
    });

    it("accepts the deterministic TypeScript fixture and exposes only success", async () => {
      const witness = await circuit.calculateWitness(sparseFixture.input);
      await circuit.expectConstraintPass(witness);
      assert.equal(witness[1], 1n);
      assert.equal(sparseFixture.input.identifier, STATUS_PROOF_BENCHMARK_QUERY.toString());
      assert.equal(sparseFixture.input.snapshotEpoch, STATUS_PROOF_BENCHMARK_EPOCH);
    });

    it("rejects tampered root, path, identifier, status, epoch, and query anchor", async () => {
      const root = clone(sparseFixture.input);
      root.expectedSnapshotRootHi = (BigInt(root.expectedSnapshotRootHi as string) + 1n).toString();
      await expectRejected(circuit, root);

      const path = clone(sparseFixture.input);
      (path.siblings as number[][])[63]![31] ^= 1;
      await expectRejected(circuit, path);

      const identifier = clone(sparseFixture.input);
      identifier.identifier = (BigInt(identifier.identifier as string) + 1n).toString();
      await expectRejected(circuit, identifier);

      const status = clone(sparseFixture.input);
      status.revoked = 1;
      await expectRejected(circuit, status);

      const epoch = clone(sparseFixture.input);
      epoch.snapshotEpoch = STATUS_PROOF_BENCHMARK_EPOCH + 1;
      await expectRejected(circuit, epoch);

      const handle = clone(sparseFixture.input);
      handle.expectedQueryHandleHi = (
        BigInt(handle.expectedQueryHandleHi as string) + 1n
      ).toString();
      await expectRejected(circuit, handle);

      const salt = clone(sparseFixture.input);
      (salt.querySalt as number[])[31] ^= 1;
      await expectRejected(circuit, salt);
    });
  });
});

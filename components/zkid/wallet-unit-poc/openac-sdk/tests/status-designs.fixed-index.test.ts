import { describe, expect, it } from "vitest";
import {
  FixedIndexStatusTree,
  SWIYU_FIXED_STATUS_DEPTH,
  type StatusBit,
} from "../src/status-designs/fixed-index-merkle.js";

describe("fixed-index Token Status List Merkle candidate", () => {
  it("builds a snapshot and verifies an unrevoked status witness", () => {
    const tree = FixedIndexStatusTree.build([0, 1, 0, 0], 7);
    const witness = tree.witness(2);

    expect(
      FixedIndexStatusTree.verify(witness, {
        root: tree.root,
        epoch: 7,
        expectedStatus: 0,
      }),
    ).toBe(true);
  });

  it("rotates the snapshot when an entry is revoked and rejects the stale witness", () => {
    const original = FixedIndexStatusTree.build([0, 0, 0, 0], 7);
    const staleWitness = original.witness(2);
    const updated = original.update(2, 1, 8);

    expect(updated.root).not.toBe(original.root);
    expect(
      FixedIndexStatusTree.verify(staleWitness, {
        root: updated.root,
        epoch: updated.epoch,
        expectedStatus: 0,
      }),
    ).toBe(false);
    expect(
      FixedIndexStatusTree.verify(updated.witness(2), {
        root: updated.root,
        epoch: updated.epoch,
        expectedStatus: 0,
      }),
    ).toBe(false);
    expect(
      FixedIndexStatusTree.verify(updated.witness(2), {
        root: updated.root,
        epoch: updated.epoch,
        expectedStatus: 1,
      }),
    ).toBe(true);
    expect(original.witness(2).status).toBe(0);
  });

  it("commits all four exact 2-bit Token Status List values", () => {
    const tree = FixedIndexStatusTree.build([0, 1, 2, 3], 9);
    const lossyRemap = FixedIndexStatusTree.build([0, 1, 1, 3], 9);
    expect(lossyRemap.root).not.toBe(tree.root);
    for (const status of [0, 1, 2, 3] as const) {
      const witness = tree.witness(status);
      expect(witness.status).toBe(status);
      expect(
        FixedIndexStatusTree.verify(witness, {
          root: tree.root,
          epoch: tree.epoch,
          expectedStatus: status,
        }),
      ).toBe(true);
    }
    expect(() =>
      FixedIndexStatusTree.build([4 as StatusBit], 9),
    ).toThrow(/2-bit value/);
  });

  it("pads real swiyu list sizes to a fixed depth-17 profile", () => {
    for (const size of [255, 65_536, 102_400] as const) {
      const statuses = Array<StatusBit>(size).fill(0);
      statuses[size - 1] = 2;
      const tree = FixedIndexStatusTree.buildSwiyuProfile(statuses, 12);
      const witness = tree.witness(size - 1);

      expect(tree.entryCount).toBe(size);
      expect(tree.depth).toBe(SWIYU_FIXED_STATUS_DEPTH);
      expect(witness.siblings).toHaveLength(SWIYU_FIXED_STATUS_DEPTH);
      expect(
        FixedIndexStatusTree.verify(witness, {
          root: tree.root,
          epoch: tree.epoch,
          expectedStatus: 2,
          fixedDepth: SWIYU_FIXED_STATUS_DEPTH,
        }),
      ).toBe(true);
    }
  }, 30_000);

  it("keeps default next-power roots while preserving fixed depth across updates", () => {
    const statuses: StatusBit[] = [0, 0, 0, 0];
    const defaultTree = FixedIndexStatusTree.build(statuses, 1);
    const fixedTree = FixedIndexStatusTree.build(statuses, 1, { fixedDepth: 4 });
    const updated = fixedTree.update(1, 3, 2);

    expect(defaultTree.depth).toBe(2);
    expect(fixedTree.depth).toBe(4);
    expect(fixedTree.root).not.toBe(defaultTree.root);
    expect(updated.depth).toBe(4);
    expect(updated.witness(1).siblings).toHaveLength(4);
    expect(
      FixedIndexStatusTree.verify(updated.witness(1), {
        root: updated.root,
        epoch: updated.epoch,
        expectedStatus: 3,
        fixedDepth: 4,
      }),
    ).toBe(true);
    expect(() =>
      FixedIndexStatusTree.build([0, 0, 0], 1, { fixedDepth: 1 }),
    ).toThrow(/exceeds fixed depth/);
  });

  it("keeps roots and every witness byte-identical to a full rebuild", () => {
    const statuses = Array.from<StatusBit>({ length: 257 }, (_, index) =>
      (index % 4) as StatusBit,
    );
    const original = FixedIndexStatusTree.build(statuses, 21, { fixedDepth: 10 });
    const originalWitness = original.witness(173);
    const updated = original.update(173, 3, 22);
    const rebuiltStatuses = [...statuses];
    rebuiltStatuses[173] = 3;
    const rebuilt = FixedIndexStatusTree.build(rebuiltStatuses, 22, {
      fixedDepth: 10,
    });

    expect(updated.root).toBe(rebuilt.root);
    for (let index = 0; index < statuses.length; index += 1) {
      expect(updated.witness(index)).toEqual(rebuilt.witness(index));
    }
    expect(original.witness(173)).toEqual(originalWitness);
  });

  it("handles repeated depth-17 updates without any hidden full-tree rebuild", () => {
    const statuses = Array<StatusBit>(65_536).fill(0);
    const original = FixedIndexStatusTree.buildSwiyuProfile(statuses, 30);
    let updated = original;
    for (let index = 0; index < 64; index += 1) {
      const position = index * 997;
      const status = ((index % 3) + 1) as StatusBit;
      statuses[position] = status;
      updated = updated.update(position, status, 31 + index);
    }
    const rebuilt = FixedIndexStatusTree.buildSwiyuProfile(statuses, 94);

    expect(updated.root).toBe(rebuilt.root);
    expect(original.witness(0).status).toBe(0);
    for (const index of [0, 997, 31_904, 62_811]) {
      expect(updated.witness(index)).toEqual(rebuilt.witness(index));
    }
  }, 20_000);
});

import { describe, expect, it } from "vitest";
import {
  TernaryFixedIndexStatusTree,
} from "../src/status-designs/ternary-fixed-index-merkle.js";

describe("ternary fixed-index status tree", () => {
  it("round-trips witnesses from every child position", () => {
    const tree = TernaryFixedIndexStatusTree.build(
      [0, 0, 0, 0, 0, 0, 0, 0],
      7,
      { fixedDepth: 2 },
    );
    expect(tree.depth).toBe(2);
    for (const index of [3, 4, 5]) {
      const witness = tree.witness(index);
      expect(witness.siblings).toHaveLength(2);
      expect(
        TernaryFixedIndexStatusTree.verify(witness, {
          root: tree.root,
          epoch: 7,
          expectedStatus: 0,
          fixedDepth: 2,
        }),
      ).toBe(true);
    }
  });

  it("rejects a modified path and supports logarithmic updates", () => {
    const tree = TernaryFixedIndexStatusTree.build(
      [0, 0, 0, 0, 0, 0, 0, 0],
      7,
      { fixedDepth: 2 },
    );
    const witness = tree.witness(5);
    const firstSibling = witness.siblings[0]![0];
    const changedSibling = `${firstSibling[0] === "0" ? "1" : "0"}${firstSibling.slice(1)}`;
    expect(
      TernaryFixedIndexStatusTree.verify(
        {
          ...witness,
          siblings: [
            [changedSibling, witness.siblings[0]![1]],
            witness.siblings[1]!,
          ],
        },
        { root: tree.root, epoch: 7, expectedStatus: 0, fixedDepth: 2 },
      ),
    ).toBe(false);

    const updated = tree.update(5, 1, 8);
    expect(updated.root).not.toBe(tree.root);
    expect(
      TernaryFixedIndexStatusTree.verify(updated.witness(5), {
        root: updated.root,
        epoch: 8,
        expectedStatus: 1,
        fixedDepth: 2,
      }),
    ).toBe(true);
  });

  it("enforces fixed-depth capacity", () => {
    expect(() =>
      TernaryFixedIndexStatusTree.build(Array(10).fill(0), 1, {
        fixedDepth: 2,
      }),
    ).toThrow(/capacity/);
  });
});

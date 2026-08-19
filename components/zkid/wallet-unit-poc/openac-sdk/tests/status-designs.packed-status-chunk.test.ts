import { describe, expect, it } from "vitest";

import {
  PackedStatusChunkTree,
  SWIYU_PACKED_STATUS_MAX_ENTRIES,
} from "../src/status-designs/packed-status-chunk-merkle.js";

describe("packed 2-bit status chunk tree v2", () => {
  it("extracts all four LSB-first slots and crosses the 255/256 boundary", () => {
    const packed = new Uint8Array(65);
    packed[0] = 0xe4; // [0, 1, 2, 3]
    packed[63] = 0x00;
    packed[64] = 0x39; // [1, 2, 3, 0]
    const tree = PackedStatusChunkTree.buildSwiyuProfile(packed, 7);
    expect([0, 1, 2, 3].map((index) => tree.witness(index).status))
      .toEqual([0, 1, 2, 3]);
    expect(tree.witness(255)).toMatchObject({ status: 0 });
    expect(tree.witness(256)).toMatchObject({ status: 1 });
    expect(tree.witness(259)).toMatchObject({ status: 0 });
    expect(tree.witness(255).chunk).not.toEqual(tree.witness(256).chunk);
  });

  it("round-trips every ternary child position and binds root, epoch, and path", () => {
    const packed = new Uint8Array(64 * 7);
    const tree = PackedStatusChunkTree.buildSwiyuProfile(packed, 17);
    for (const chunkIndex of [3, 4, 5]) {
      const witness = tree.witness(chunkIndex * 256);
      expect(PackedStatusChunkTree.verify(witness, {
        root: tree.root,
        epoch: 17,
        expectedStatus: 0,
      })).toBe(true);
      expect(PackedStatusChunkTree.verify(
        { ...witness, epoch: 18 },
        { root: tree.root, epoch: 18, expectedStatus: 0 },
      )).toBe(false);
      const changed = witness.siblings.map((pair) => [...pair] as [string, string]);
      changed[0]![0] = `${changed[0]![0][0] === "0" ? "1" : "0"}${changed[0]![0].slice(1)}`;
      expect(PackedStatusChunkTree.verify(
        { ...witness, siblings: changed },
        { root: tree.root, epoch: 17, expectedStatus: 0 },
      )).toBe(false);
    }
  });

  it("copies source bytes, freezes witnesses, and authenticates final zero padding", () => {
    const packed = new Uint8Array(65);
    const tree = PackedStatusChunkTree.buildSwiyuProfile(packed, 23);
    packed[64] = 0xff;
    const witness = tree.witness(256);
    expect(witness.status).toBe(0);
    expect(Object.isFrozen(witness)).toBe(true);
    expect(Object.isFrozen(witness.chunk)).toBe(true);
    expect(Object.isFrozen(witness.siblings)).toBe(true);
    expect(witness.chunk.slice(1)).toEqual(Array(63).fill(0));
    expect(PackedStatusChunkTree.verify(witness, {
      root: tree.root,
      epoch: 23,
      expectedStatus: 0,
    })).toBe(true);
    const nonCanonicalTail = [...witness.chunk];
    nonCanonicalTail[63] = 1;
    expect(PackedStatusChunkTree.verify(
      { ...witness, chunk: nonCanonicalTail },
      { root: tree.root, epoch: 23, expectedStatus: 0 },
    )).toBe(false);
  });

  it("pins deterministic roots and keeps v1/v2 domains non-interchangeable", () => {
    const residence = PackedStatusChunkTree.buildSwiyuProfile(
      new Uint8Array(65_536 / 4),
      1_749_999_970,
    );
    expect(residence.root).toBe(
      "8c9b118e9feea73867dfe6bf8e28bb19acacfe5da1d45961b5691993019035c2",
    );
    expect(residence.root).not.toBe(
      "0c5ff2d21a2425ba5f5497b19a04feace17592249fdb1902805a4829f0ea1162",
    );
  });

  it("accepts the exact profile maximum and rejects empty or oversized lists", () => {
    expect(() => PackedStatusChunkTree.buildSwiyuProfile(
      new Uint8Array(SWIYU_PACKED_STATUS_MAX_ENTRIES / 4),
      1,
    )).not.toThrow();
    expect(() => PackedStatusChunkTree.buildSwiyuProfile(new Uint8Array(), 1))
      .toThrow(/at least one byte/);
    expect(() => PackedStatusChunkTree.buildSwiyuProfile(
      new Uint8Array(SWIYU_PACKED_STATUS_MAX_ENTRIES / 4 + 1),
      1,
    )).toThrow(/exceeds/);
  });
});

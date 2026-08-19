import { p256 } from "@noble/curves/p256";
import { describe, expect, it } from "vitest";
import {
  LeanImtPlusTree,
  SparseStatusTree,
  Ts13AdjacentPairRegistry,
  TS13_RIGHT_SENTINEL,
  encodeTs13PairMessage,
  type LeanImtPlusPathStep,
  type LeanImtPlusWitness,
} from "../src/status-designs/index.js";
import {
  byte,
  hashDomain,
  hexToBytes,
  u64,
  type HashHex,
} from "../src/status-designs/hashing.js";

const REVOCATION_PRIVATE_KEY = Uint8Array.from([
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
]);
const REVOCATION_PUBLIC_KEY = p256.getPublicKey(REVOCATION_PRIVATE_KEY, false);

describe("sparse Merkle revoked-set candidate", () => {
  it("proves both revoked membership and default-valid non-membership", () => {
    const tree = SparseStatusTree.build([2, 42, 65_535], 19);
    const revoked = tree.witness(42);
    const valid = tree.witness(43);

    expect(revoked.siblings).toHaveLength(64);
    expect(valid.revoked).toBe(false);
    expect(
      SparseStatusTree.verify(revoked, {
        root: tree.root,
        epoch: tree.epoch,
        expectedRevoked: true,
      }),
    ).toBe(true);
    expect(
      SparseStatusTree.verify(valid, {
        root: tree.root,
        epoch: tree.epoch,
        expectedRevoked: false,
      }),
    ).toBe(true);
  });

  it("updates one depth-64 path and returns to the canonical empty root", () => {
    const tree = SparseStatusTree.build([], 20);
    const emptyRoot = tree.root;
    const before = tree.witness(0xffff_ffff_ffff_ffffn);

    tree.setRevoked(0xffff_ffff_ffff_ffffn, true);
    expect(tree.root).not.toBe(emptyRoot);
    expect(tree.witness(0xffff_ffff_ffff_ffffn).revoked).toBe(true);
    tree.setRevoked(0xffff_ffff_ffff_ffffn, false);

    expect(tree.root).toBe(emptyRoot);
    expect(tree.witness(0xffff_ffff_ffff_ffffn)).toEqual(before);
  });

  it("rejects tampered paths, identifiers, status claims, roots, and epochs", () => {
    const tree = SparseStatusTree.build([42], 21);
    const witness = tree.witness(43);
    const context = {
      root: tree.root,
      epoch: tree.epoch,
      expectedRevoked: false,
    } as const;
    const wrongFirstByte = witness.siblings[0]!.startsWith("00") ? "01" : "00";
    const wrongSibling = `${wrongFirstByte}${witness.siblings[0]!.slice(2)}`;

    expect(
      SparseStatusTree.verify(
        { ...witness, siblings: [wrongSibling, ...witness.siblings.slice(1)] },
        context,
      ),
    ).toBe(false);
    expect(SparseStatusTree.verify({ ...witness, identifier: "44" }, context)).toBe(
      false,
    );
    expect(SparseStatusTree.verify({ ...witness, revoked: true }, context)).toBe(
      false,
    );
    expect(
      SparseStatusTree.verify(witness, { ...context, root: "00".repeat(32) }),
    ).toBe(false);
    expect(
      SparseStatusTree.verify(witness, { ...context, epoch: context.epoch + 1 }),
    ).toBe(false);
    expect(() => SparseStatusTree.build(["01"], 1)).toThrow(/canonical/);
    expect(() => SparseStatusTree.build([42, 42], 1)).toThrow(/duplicate/);
  });

  it("keeps a canonical root across deterministic update orderings", () => {
    const tree = SparseStatusTree.build([], 22);
    const revoked = new Set<bigint>();
    let state = 0x5eed_1234;
    for (let iteration = 0; iteration < 160; iteration += 1) {
      state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
      const identifier = BigInt(state % 512);
      const nextStatus = !revoked.has(identifier);
      tree.setRevoked(identifier, nextStatus);
      if (nextStatus) revoked.add(identifier);
      else revoked.delete(identifier);
      const witness = tree.witness(identifier);
      expect(
        SparseStatusTree.verify(witness, {
          root: tree.root,
          epoch: tree.epoch,
          expectedRevoked: nextStatus,
        }),
      ).toBe(true);
    }
    const rebuilt = SparseStatusTree.build([...revoked].reverse(), 22);
    expect(tree.root).toBe(rebuilt.root);
  });
});

describe("zkID LeanIMT+ SHA-256 candidate", () => {
  it("supports membership and predecessor non-membership across every interval", () => {
    const tree = LeanImtPlusTree.build([20, 5, 10], 31);
    for (const member of [5, 10, 20]) {
      const witness = tree.membershipWitness(member);
      expect(
        LeanImtPlusTree.verify(witness, {
          root: tree.root,
          epoch: tree.epoch,
          expectedMode: "membership",
        }),
      ).toBe(true);
    }

    for (const absent of [1, 7, 15, 99]) {
      const witness = tree.nonMembershipWitness(absent);
      expect(
        LeanImtPlusTree.verify(witness, {
          root: tree.root,
          epoch: tree.epoch,
          expectedMode: "non-membership",
        }),
      ).toBe(true);
    }
    expect(tree.nonMembershipWitness(1).leafIndex).toBe(0);
    expect(tree.nonMembershipWitness(99).leaf.nextValue).toBe("0");
  });

  it("promotes unpaired odd nodes without injecting a zero hash", () => {
    const tree = LeanImtPlusTree.build([20, 5, 10, 30], 32);
    const witness = tree.membershipWitness(30);
    expect(tree.leafCount).toBe(5);
    expect(witness.path.some((step) => step.sibling === null)).toBe(true);
    expect(
      LeanImtPlusTree.verify(witness, {
        root: tree.root,
        epoch: tree.epoch,
        expectedMode: "membership",
      }),
    ).toBe(true);

    const promotedIndex = witness.path.findIndex((step) => step.sibling === null);
    const tamperedPath = [...witness.path];
    tamperedPath[promotedIndex] = {
      sibling: "00".repeat(32),
      side: "left",
    };
    expect(
      LeanImtPlusTree.verify(
        { ...witness, path: tamperedPath },
        { root: tree.root, epoch: tree.epoch, expectedMode: "membership" },
      ),
    ).toBe(false);
  });

  it("repairs links, authenticates tombstones, and never reuses their slots", () => {
    const tree = LeanImtPlusTree.build([5, 10, 20], 33);
    const removedIndex = tree.membershipWitness(10).leafIndex;
    const oldRoot = tree.root;
    tree.remove(10);

    expect(tree.root).not.toBe(oldRoot);
    expect(tree.has(10)).toBe(false);
    const nonMember = tree.nonMembershipWitness(10);
    expect(nonMember.leaf.value).toBe("5");
    expect(nonMember.leaf.nextValue).toBe("20");
    expect(
      LeanImtPlusTree.verify(nonMember, {
        root: tree.root,
        epoch: tree.epoch,
        expectedMode: "non-membership",
      }),
    ).toBe(true);

    // Exercise the verifier's explicit tombstone replay guard with a genuine
    // authenticated path to the removed physical slot.
    const pathFor = (
      tree as unknown as { pathFor(index: number): LeanImtPlusPathStep[] }
    ).pathFor.bind(tree);
    const forgedFromTombstone: LeanImtPlusWitness = {
      ...nonMember,
      query: "15",
      leafIndex: removedIndex,
      leaf: { value: "0", nextValue: "0" },
      path: pathFor(removedIndex),
    };
    expect(
      LeanImtPlusTree.verify(forgedFromTombstone, {
        root: tree.root,
        epoch: tree.epoch,
        expectedMode: "non-membership",
      }),
    ).toBe(false);

    const leafCountWithTombstone = tree.leafCount;
    tree.insert(10);
    expect(tree.membershipWitness(10).leafIndex).toBe(leafCountWithTombstone);
    expect(tree.leafCount).toBe(leafCountWithTombstone + 1);
  });

  it("rejects mode, ordering, path, root, epoch, duplicate, and sentinel attacks", () => {
    const tree = LeanImtPlusTree.build([5, 10, 20], 34);
    const witness = tree.nonMembershipWitness(7);
    const context = {
      root: tree.root,
      epoch: tree.epoch,
      expectedMode: "non-membership",
    } as const;

    expect(
      LeanImtPlusTree.verify({ ...witness, query: "4" }, context),
    ).toBe(false);
    expect(
      LeanImtPlusTree.verify(
        { ...witness, leaf: { ...witness.leaf, nextValue: "6" } },
        context,
      ),
    ).toBe(false);
    expect(
      LeanImtPlusTree.verify({ ...witness, path: witness.path.slice(1) }, context),
    ).toBe(false);
    expect(
      LeanImtPlusTree.verify(witness, { ...context, root: "ff".repeat(32) }),
    ).toBe(false);
    expect(
      LeanImtPlusTree.verify(witness, { ...context, epoch: context.epoch + 1 }),
    ).toBe(false);
    expect(
      LeanImtPlusTree.verify(witness, { ...context, expectedMode: "membership" }),
    ).toBe(false);
    expect(() => tree.insert(5)).toThrow(/already exists/);
    expect(() => tree.insert(0)).toThrow(/sentinel/);
    expect(() => tree.remove(99)).toThrow(/absent/);
  });

  it("keeps AVL predecessor links and incremental hashes sound under churn", () => {
    const insertionOrder = Array.from({ length: 128 }, (_, index) => index * 2 + 1)
      .sort((left, right) => ((left * 73) % 257) - ((right * 73) % 257));
    const tree = LeanImtPlusTree.build(insertionOrder, 35);
    for (const value of insertionOrder.filter((_, index) => index % 3 === 0)) {
      tree.remove(value);
    }
    const active = new Set(insertionOrder.filter((_, index) => index % 3 !== 0));

    for (let query = 1; query < 256; query += 1) {
      const witness = active.has(query)
        ? tree.membershipWitness(query)
        : tree.nonMembershipWitness(query);
      expect(
        LeanImtPlusTree.verify(witness, {
          root: tree.root,
          epoch: tree.epoch,
          expectedMode: active.has(query) ? "membership" : "non-membership",
        }),
      ).toBe(true);
    }
    expect(tree.root).toBe(independentLeanRoot(tree));
  });
});

describe("EUDI TS13-style signed adjacent-pair candidate", () => {
  it("matches the TS13 uint64/uint64/uint32 little-endian message example", () => {
    expect(bytesToHex(encodeTs13PairMessage(10, 11, 2))).toBe(
      "0a000000000000000b0000000000000002000000",
    );
  });

  it("verifies first, middle, and final intervals using real raw ES256 signatures", () => {
    const registry = Ts13AdjacentPairRegistry.build(
      [10, 11, 14, 96],
      2,
      REVOCATION_PRIVATE_KEY,
    );
    const cases = [
      { identifier: 1, left: "0", right: "10" },
      { identifier: 12, left: "11", right: "14" },
      {
        identifier: 100,
        left: "96",
        right: TS13_RIGHT_SENTINEL.toString(10),
      },
    ];
    for (const expected of cases) {
      const witness = registry.witness(expected.identifier);
      expect(witness.left).toBe(expected.left);
      expect(witness.right).toBe(expected.right);
      expect(witness.rawSignature).toMatch(/^[0-9a-f]{128}$/);
      expect(
        Ts13AdjacentPairRegistry.verify(witness, {
          epoch: registry.epoch,
          revokerPublicKey: REVOCATION_PUBLIC_KEY,
        }),
      ).toBe(true);
    }
    expect(() => registry.witness(10)).toThrow(/revoked/);
  });

  it("covers an empty revoked set with the two signed boundary sentinels", () => {
    const registry = Ts13AdjacentPairRegistry.build([], 8, REVOCATION_PRIVATE_KEY);
    const witness = registry.witness(42);
    expect(witness.left).toBe("0");
    expect(witness.right).toBe(TS13_RIGHT_SENTINEL.toString(10));
    expect(
      Ts13AdjacentPairRegistry.verify(witness, {
        epoch: 8,
        revokerPublicKey: REVOCATION_PUBLIC_KEY,
      }),
    ).toBe(true);
    expect(() => registry.witness(0)).toThrow(/reserved/);
    expect(() => registry.witness(TS13_RIGHT_SENTINEL)).toThrow(/reserved/);
  });

  it("rejects identifier, interval, epoch, signature, and signer tampering", () => {
    const registry = Ts13AdjacentPairRegistry.build(
      [10, 20],
      9,
      REVOCATION_PRIVATE_KEY,
    );
    const witness = registry.witness(15);
    const context = {
      epoch: registry.epoch,
      revokerPublicKey: REVOCATION_PUBLIC_KEY,
    };
    const otherKey = Uint8Array.from(REVOCATION_PRIVATE_KEY);
    otherKey[31] = 8;

    expect(
      Ts13AdjacentPairRegistry.verify({ ...witness, identifier: "20" }, context),
    ).toBe(false);
    expect(
      Ts13AdjacentPairRegistry.verify({ ...witness, left: "11" }, context),
    ).toBe(false);
    expect(
      Ts13AdjacentPairRegistry.verify(witness, { ...context, epoch: 10 }),
    ).toBe(false);
    expect(
      Ts13AdjacentPairRegistry.verify(
        {
          ...witness,
          rawSignature: `${witness.rawSignature.startsWith("00") ? "01" : "00"}${witness.rawSignature.slice(2)}`,
        },
        context,
      ),
    ).toBe(false);
    expect(
      Ts13AdjacentPairRegistry.verify(witness, {
        ...context,
        revokerPublicKey: p256.getPublicKey(otherKey, false),
      }),
    ).toBe(false);
  });

  it("forces a new epoch and signatures for each status change", () => {
    const original = Ts13AdjacentPairRegistry.build(
      [10, 20],
      10,
      REVOCATION_PRIVATE_KEY,
    );
    const oldWitness = original.witness(15);
    const updated = original.revoke(15, 11, REVOCATION_PRIVATE_KEY);

    expect(
      Ts13AdjacentPairRegistry.verify(oldWitness, {
        epoch: updated.epoch,
        revokerPublicKey: REVOCATION_PUBLIC_KEY,
      }),
    ).toBe(false);
    expect(() => updated.witness(15)).toThrow(/revoked/);

    const restored = updated.restore(15, 12, REVOCATION_PRIVATE_KEY);
    expect(
      Ts13AdjacentPairRegistry.verify(restored.witness(15), {
        epoch: restored.epoch,
        revokerPublicKey: REVOCATION_PUBLIC_KEY,
      }),
    ).toBe(true);
    expect(() => original.revoke(10, 11, REVOCATION_PRIVATE_KEY)).toThrow(
      /already revoked/,
    );
  });
});

function bytesToHex(value: Uint8Array): string {
  return Array.from(value, (octet) => octet.toString(16).padStart(2, "0")).join("");
}

function independentLeanRoot(tree: LeanImtPlusTree): HashHex {
  const leaves = (
    tree as unknown as {
      leaves: readonly { readonly value: bigint; readonly nextValue: bigint }[];
    }
  ).leaves;
  let layer = leaves.map((leaf) =>
    hashDomain(
      "zkid-leanimt-plus-leaf-v1",
      u64(leaf.value),
      u64(leaf.nextValue),
      byte(1),
    ),
  );
  while (layer.length > 1) {
    const next: HashHex[] = [];
    for (let index = 0; index < layer.length; index += 2) {
      const left = layer[index]!;
      const right = layer[index + 1];
      next.push(
        right === undefined
          ? left
          : hashDomain(
              "zkid-leanimt-plus-node-v1",
              hexToBytes(left),
              hexToBytes(right),
            ),
      );
    }
    layer = next;
  }
  return hashDomain(
    "zkid-leanimt-plus-snapshot-v1",
    u64(tree.epoch),
    u64(tree.leafCount),
    hexToBytes(layer[0]!),
  );
}

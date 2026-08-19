import {
  assertEpoch,
  byte,
  hashDomain,
  hexToBytes,
  nextPowerOfTwo,
  u32,
  u64,
  type HashHex,
} from "./hashing.js";

export type StatusBit = 0 | 1 | 2 | 3;

export const SWIYU_FIXED_STATUS_DEPTH = 17;

export interface FixedIndexStatusTreeOptions {
  /** Pad to exactly 2^fixedDepth leaves instead of the default next power of two. */
  readonly fixedDepth?: number;
}

export interface FixedIndexStatusWitness {
  readonly design: "fixed-index-status-merkle-v1";
  readonly index: number;
  readonly status: StatusBit;
  readonly entryCount: number;
  readonly epoch: number;
  readonly root: HashHex;
  readonly siblings: readonly HashHex[];
}

export interface FixedIndexVerificationContext {
  readonly root: HashHex;
  readonly epoch: number;
  readonly expectedStatus: StatusBit;
  /** Required when the snapshot was built with explicit fixed-depth padding. */
  readonly fixedDepth?: number;
}

interface MerkleNode {
  readonly hash: HashHex;
  readonly left?: MerkleNode;
  readonly right?: MerkleNode;
  /** Present only for real (non-padding) leaves. */
  readonly status?: StatusBit;
}

export class FixedIndexStatusTree {
  readonly entryCount: number;
  readonly epoch: number;
  readonly root: HashHex;
  readonly depth: number;

  private constructor(
    private readonly treeRoot: MerkleNode,
    entryCount: number,
    epoch: number,
    depth: number,
    private readonly fixedDepth?: number,
  ) {
    this.entryCount = entryCount;
    this.epoch = epoch;
    this.depth = depth;
    this.root = snapshotRoot(treeRoot.hash, entryCount, epoch);
  }

  static build(
    statuses: readonly StatusBit[],
    epoch: number,
    options: FixedIndexStatusTreeOptions = {},
  ): FixedIndexStatusTree {
    assertEpoch(epoch);
    if (statuses.length === 0) {
      throw new Error("a fixed-index status tree needs at least one entry");
    }
    const copiedStatuses = statuses.map((status, index) => {
      assertStatus(status, `status at index ${index}`);
      return status;
    });
    const depth = resolveDepth(copiedStatuses.length, options.fixedDepth);
    return new FixedIndexStatusTree(
      buildTree(copiedStatuses, depth),
      copiedStatuses.length,
      epoch,
      depth,
      options.fixedDepth,
    );
  }

  /** Build the fixed depth-17 tree consumed by the swiyu age/status relation. */
  static buildSwiyuProfile(
    statuses: readonly StatusBit[],
    epoch: number,
  ): FixedIndexStatusTree {
    return FixedIndexStatusTree.build(statuses, epoch, {
      fixedDepth: SWIYU_FIXED_STATUS_DEPTH,
    });
  }

  /**
   * Return a new snapshot in O(depth): structurally share every unchanged hash
   * and recompute only the selected leaf-to-root path.
   */
  update(index: number, status: StatusBit, epoch: number): FixedIndexStatusTree {
    assertIndex(index, this.entryCount);
    assertStatus(status, "updated status");
    assertEpoch(epoch);
    return new FixedIndexStatusTree(
      updateTree(this.treeRoot, this.depth, index, status),
      this.entryCount,
      epoch,
      this.depth,
      this.fixedDepth,
    );
  }

  witness(index: number): FixedIndexStatusWitness {
    assertIndex(index, this.entryCount);
    const topDownSiblings: HashHex[] = [];
    let node = this.treeRoot;
    for (let remainingDepth = this.depth; remainingDepth > 0; remainingDepth -= 1) {
      const left = node.left;
      const right = node.right;
      if (!left || !right) throw new Error("malformed internal Merkle node");
      const stride = 2 ** (remainingDepth - 1);
      const goRight = Math.floor(index / stride) % 2 === 1;
      topDownSiblings.push(goRight ? left.hash : right.hash);
      node = goRight ? right : left;
    }
    if (node.status === undefined) throw new Error("selected a padding Merkle leaf");
    return {
      design: "fixed-index-status-merkle-v1",
      index,
      status: node.status,
      entryCount: this.entryCount,
      epoch: this.epoch,
      root: this.root,
      siblings: topDownSiblings.reverse(),
    };
  }

  static verify(
    witness: FixedIndexStatusWitness,
    context: FixedIndexVerificationContext,
  ): boolean {
    try {
      assertEpoch(context.epoch);
      assertEpoch(witness.epoch);
      assertStatus(context.expectedStatus, "expected status");
      assertStatus(witness.status, "witness status");
      if (
        witness.design !== "fixed-index-status-merkle-v1" ||
        witness.epoch !== context.epoch ||
        witness.root !== context.root ||
        witness.status !== context.expectedStatus
      ) {
        return false;
      }
      assertIndex(witness.index, witness.entryCount);
      const expectedDepth = resolveDepth(
        witness.entryCount,
        context.fixedDepth,
      );
      if (witness.siblings.length !== expectedDepth) {
        return false;
      }

      let hash = statusLeaf(witness.index, witness.status);
      let position = witness.index;
      for (const sibling of witness.siblings) {
        hash =
          position % 2 === 0
            ? statusNode(hash, sibling)
            : statusNode(sibling, hash);
        position = Math.floor(position / 2);
      }
      return snapshotRoot(hash, witness.entryCount, witness.epoch) === context.root;
    } catch {
      return false;
    }
  }
}

function buildTree(
  statuses: readonly StatusBit[],
  depth: number,
): MerkleNode {
  const leafCount = 2 ** depth;
  let current: MerkleNode[] = Array.from({ length: leafCount }, (_, index) =>
    index < statuses.length
      ? { hash: statusLeaf(index, statuses[index]!), status: statuses[index]! }
      : { hash: paddingLeaf(index) },
  );
  while (current.length > 1) {
    const next: MerkleNode[] = [];
    for (let index = 0; index < current.length; index += 2) {
      const left = current[index]!;
      const right = current[index + 1]!;
      next.push({
        hash: statusNode(left.hash, right.hash),
        left,
        right,
      });
    }
    current = next;
  }
  return current[0]!;
}

function updateTree(
  node: MerkleNode,
  remainingDepth: number,
  index: number,
  status: StatusBit,
): MerkleNode {
  if (remainingDepth === 0) {
    return { hash: statusLeaf(index, status), status };
  }
  const left = node.left;
  const right = node.right;
  if (!left || !right) throw new Error("malformed internal Merkle node");
  const stride = 2 ** (remainingDepth - 1);
  const goRight = Math.floor(index / stride) % 2 === 1;
  const updatedLeft = goRight
    ? left
    : updateTree(left, remainingDepth - 1, index, status);
  const updatedRight = goRight
    ? updateTree(right, remainingDepth - 1, index, status)
    : right;
  return {
    hash: statusNode(updatedLeft.hash, updatedRight.hash),
    left: updatedLeft,
    right: updatedRight,
  };
}

function statusLeaf(index: number, status: StatusBit): HashHex {
  return hashDomain("swiyu-status-leaf-v1", u32(index), byte(status));
}

function paddingLeaf(index: number): HashHex {
  return hashDomain("swiyu-status-padding-v1", u32(index));
}

function statusNode(left: HashHex, right: HashHex): HashHex {
  return hashDomain("swiyu-status-node-v1", hexToBytes(left), hexToBytes(right));
}

function snapshotRoot(treeRoot: HashHex, entryCount: number, epoch: number): HashHex {
  return hashDomain(
    "swiyu-status-snapshot-v1",
    u32(entryCount),
    u64(epoch),
    hexToBytes(treeRoot),
  );
}

function assertStatus(status: number, label: string): asserts status is StatusBit {
  if (status !== 0 && status !== 1 && status !== 2 && status !== 3) {
    throw new RangeError(
      `${label} must be a 2-bit value: 0 (valid), 1 (revoked), 2 (suspended), or 3 (reserved)`,
    );
  }
}

function resolveDepth(entryCount: number, fixedDepth?: number): number {
  if (!Number.isSafeInteger(entryCount) || entryCount < 1) {
    throw new RangeError("entry count must be a positive safe integer");
  }
  if (fixedDepth === undefined) {
    return Math.log2(nextPowerOfTwo(entryCount));
  }
  if (!Number.isInteger(fixedDepth) || fixedDepth < 0 || fixedDepth > 31) {
    throw new RangeError("fixed depth must be an integer in 0..31");
  }
  if (entryCount > 2 ** fixedDepth) {
    throw new RangeError(
      `entry count ${entryCount} exceeds fixed depth ${fixedDepth} capacity`,
    );
  }
  return fixedDepth;
}

function assertIndex(index: number, entryCount: number): void {
  if (!Number.isSafeInteger(entryCount) || entryCount < 1) {
    throw new RangeError("entry count must be a positive safe integer");
  }
  if (!Number.isSafeInteger(index) || index < 0 || index >= entryCount) {
    throw new RangeError(`status index ${index} is outside 0..${entryCount - 1}`);
  }
}

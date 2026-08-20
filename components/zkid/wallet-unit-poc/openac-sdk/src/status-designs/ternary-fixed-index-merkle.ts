import {
  assertEpoch,
  byte,
  hashDomain,
  hexToBytes,
  u32,
  u64,
  type HashHex,
} from "./hashing.js";
import type { StatusBit } from "./fixed-index-merkle.js";

export const SWIYU_TERNARY_STATUS_DEPTH = 11;

export interface TernaryStatusTreeOptions {
  readonly fixedDepth?: number;
}

export interface TernaryStatusWitness {
  readonly design: "fixed-index-status-ternary-merkle-v1";
  readonly index: number;
  readonly status: StatusBit;
  readonly entryCount: number;
  readonly epoch: number;
  readonly root: HashHex;
  /** Two siblings per level, ordered by child position after omitting the path child. */
  readonly siblings: readonly (readonly [HashHex, HashHex])[];
}

export interface TernaryStatusVerificationContext {
  readonly root: HashHex;
  readonly epoch: number;
  readonly expectedStatus: StatusBit;
  readonly fixedDepth?: number;
}

interface TernaryNode {
  readonly hash: HashHex;
  readonly children?: readonly [TernaryNode, TernaryNode, TernaryNode];
  readonly status?: StatusBit;
}

/** SDK counterpart of `SwiyuTernaryStatusMerkle`. */
export class TernaryFixedIndexStatusTree {
  readonly entryCount: number;
  readonly epoch: number;
  readonly root: HashHex;
  readonly depth: number;

  private constructor(
    private readonly treeRoot: TernaryNode,
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
    options: TernaryStatusTreeOptions = {},
  ): TernaryFixedIndexStatusTree {
    assertEpoch(epoch);
    if (statuses.length === 0) {
      throw new Error("a ternary status tree needs at least one entry");
    }
    const copied = statuses.map((status, index) => {
      assertStatus(status, `status at index ${index}`);
      return status;
    });
    const depth = resolveDepth(copied.length, options.fixedDepth);
    return new TernaryFixedIndexStatusTree(
      buildTree(copied, depth),
      copied.length,
      epoch,
      depth,
      options.fixedDepth,
    );
  }

  static buildSwiyuProfile(
    statuses: readonly StatusBit[],
    epoch: number,
  ): TernaryFixedIndexStatusTree {
    return TernaryFixedIndexStatusTree.build(statuses, epoch, {
      fixedDepth: SWIYU_TERNARY_STATUS_DEPTH,
    });
  }

  update(index: number, status: StatusBit, epoch: number): TernaryFixedIndexStatusTree {
    assertIndex(index, this.entryCount);
    assertStatus(status, "updated status");
    assertEpoch(epoch);
    return new TernaryFixedIndexStatusTree(
      updateTree(this.treeRoot, this.depth, index, status),
      this.entryCount,
      epoch,
      this.depth,
      this.fixedDepth,
    );
  }

  witness(index: number): TernaryStatusWitness {
    assertIndex(index, this.entryCount);
    const topDownSiblings: Array<[HashHex, HashHex]> = [];
    let node = this.treeRoot;
    for (let remaining = this.depth; remaining > 0; remaining -= 1) {
      const children = node.children;
      if (!children) throw new Error("malformed ternary Merkle node");
      const stride = 3 ** (remaining - 1);
      const position = Math.floor(index / stride) % 3;
      const siblings = children
        .filter((_, child) => child !== position)
        .map((child) => child.hash) as [HashHex, HashHex];
      topDownSiblings.push(siblings);
      node = children[position]!;
    }
    if (node.status === undefined) throw new Error("selected a padding Merkle leaf");
    return {
      design: "fixed-index-status-ternary-merkle-v1",
      index,
      status: node.status,
      entryCount: this.entryCount,
      epoch: this.epoch,
      root: this.root,
      siblings: topDownSiblings.reverse(),
    };
  }

  static verify(
    witness: TernaryStatusWitness,
    context: TernaryStatusVerificationContext,
  ): boolean {
    try {
      assertEpoch(context.epoch);
      assertEpoch(witness.epoch);
      assertStatus(context.expectedStatus, "expected status");
      assertStatus(witness.status, "witness status");
      if (
        witness.design !== "fixed-index-status-ternary-merkle-v1" ||
        witness.epoch !== context.epoch ||
        witness.root !== context.root ||
        witness.status !== context.expectedStatus
      ) return false;
      assertIndex(witness.index, witness.entryCount);
      const expectedDepth = resolveDepth(witness.entryCount, context.fixedDepth);
      if (witness.siblings.length !== expectedDepth) return false;

      let hash = statusLeaf(witness.index, witness.status);
      let position = witness.index;
      for (const siblings of witness.siblings) {
        if (siblings.length !== 2) return false;
        const trit = position % 3;
        const children = trit === 0
          ? [hash, siblings[0], siblings[1]]
          : trit === 1
            ? [siblings[0], hash, siblings[1]]
            : [siblings[0], siblings[1], hash];
        hash = statusNode3(children[0]!, children[1]!, children[2]!);
        position = Math.floor(position / 3);
      }
      return snapshotRoot(hash, witness.entryCount, witness.epoch) === context.root;
    } catch {
      return false;
    }
  }
}

function buildTree(statuses: readonly StatusBit[], depth: number): TernaryNode {
  const leafCount = 3 ** depth;
  let current: TernaryNode[] = Array.from({ length: leafCount }, (_, index) =>
    index < statuses.length
      ? { hash: statusLeaf(index, statuses[index]!), status: statuses[index]! }
      : { hash: paddingLeaf(index) },
  );
  while (current.length > 1) {
    const next: TernaryNode[] = [];
    for (let index = 0; index < current.length; index += 3) {
      const children = [current[index]!, current[index + 1]!, current[index + 2]!] as const;
      next.push({
        hash: statusNode3(children[0].hash, children[1].hash, children[2].hash),
        children,
      });
    }
    current = next;
  }
  return current[0]!;
}

function updateTree(
  node: TernaryNode,
  remainingDepth: number,
  index: number,
  status: StatusBit,
): TernaryNode {
  if (remainingDepth === 0) return { hash: statusLeaf(index, status), status };
  const children = node.children;
  if (!children) throw new Error("malformed ternary Merkle node");
  const stride = 3 ** (remainingDepth - 1);
  const position = Math.floor(index / stride) % 3;
  const updated = children.map((child, childIndex) =>
    childIndex === position
      ? updateTree(child, remainingDepth - 1, index, status)
      : child,
  ) as unknown as [TernaryNode, TernaryNode, TernaryNode];
  return {
    hash: statusNode3(updated[0].hash, updated[1].hash, updated[2].hash),
    children: updated,
  };
}

function statusLeaf(index: number, status: StatusBit): HashHex {
  return hashDomain("swiyu-status-leaf-v1", u32(index), byte(status));
}

function paddingLeaf(index: number): HashHex {
  return hashDomain("swiyu-status-padding-v1", u32(index));
}

function statusNode3(a: HashHex, b: HashHex, c: HashHex): HashHex {
  return hashDomain(
    "swiyu-status-node3-v1",
    hexToBytes(a),
    hexToBytes(b),
    hexToBytes(c),
  );
}

function snapshotRoot(treeRoot: HashHex, entryCount: number, epoch: number): HashHex {
  return hashDomain(
    "swiyu-status-snapshot-v1",
    u32(entryCount),
    u64(epoch),
    hexToBytes(treeRoot),
  );
}

function resolveDepth(entryCount: number, fixedDepth?: number): number {
  if (!Number.isSafeInteger(entryCount) || entryCount < 1) {
    throw new RangeError("entry count must be a positive safe integer");
  }
  if (fixedDepth === undefined) return Math.ceil(Math.log(entryCount) / Math.log(3));
  if (!Number.isInteger(fixedDepth) || fixedDepth < 0 || fixedDepth > 20) {
    throw new RangeError("fixed depth must be an integer in 0..20");
  }
  if (entryCount > 3 ** fixedDepth) {
    throw new RangeError(`entry count ${entryCount} exceeds ternary depth ${fixedDepth} capacity`);
  }
  return fixedDepth;
}

function assertStatus(status: number, label: string): asserts status is StatusBit {
  if (status !== 0 && status !== 1 && status !== 2 && status !== 3) {
    throw new RangeError(`${label} must be a 2-bit status value`);
  }
}

function assertIndex(index: number, entryCount: number): void {
  if (!Number.isSafeInteger(index) || index < 0 || index >= entryCount) {
    throw new RangeError(`status index ${index} is outside 0..${entryCount - 1}`);
  }
}

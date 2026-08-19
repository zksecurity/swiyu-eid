import {
  assertEpoch,
  byte,
  hashDomain,
  hexToBytes,
  u64,
  type HashHex,
} from "./hashing.js";

const MAX_U64 = 0xffff_ffff_ffff_ffffn;

export interface LeanImtPlusLeaf {
  readonly value: string;
  readonly nextValue: string;
}

export interface LeanImtPlusPathStep {
  /** Null means the current odd node was promoted without a hash. */
  readonly sibling: HashHex | null;
  readonly side: "left" | "right";
}

export interface LeanImtPlusWitness {
  readonly design: "zkid-leanimt-plus-v1";
  readonly mode: "membership" | "non-membership";
  readonly query: string;
  readonly epoch: number;
  readonly root: HashHex;
  readonly leafCount: number;
  readonly leafIndex: number;
  readonly leaf: LeanImtPlusLeaf;
  readonly path: readonly LeanImtPlusPathStep[];
}

export interface LeanImtPlusVerificationContext {
  readonly root: HashHex;
  readonly epoch: number;
  readonly expectedMode: "membership" | "non-membership";
}

interface MutableLeaf {
  value: bigint;
  nextValue: bigint;
}

/**
 * SHA-256 instantiation of zkID's LeanIMT+ construction.
 *
 * Physical leaves are append-only. Logical ordering is held in the linked
 * `nextValue` fields and an AVL predecessor index; removals leave `{0, 0}`
 * tombstones. Odd nodes are promoted unchanged, so path depth grows only with
 * the physical leaf count.
 */
export class LeanImtPlusTree {
  readonly epoch: number;

  private readonly leaves: MutableLeaf[] = [{ value: 0n, nextValue: 0n }];
  private readonly physicalIndex = new Map<bigint, number>();
  private readonly orderedValues = new AvlSet();
  private readonly layers: HashHex[][] = [[leanLeaf(0n, 0n)]];

  private constructor(epoch: number) {
    assertEpoch(epoch);
    this.epoch = epoch;
  }

  static build(
    values: readonly (bigint | number | string)[],
    epoch: number,
  ): LeanImtPlusTree {
    const tree = new LeanImtPlusTree(epoch);
    for (const value of values) tree.insert(value);
    return tree;
  }

  get leafCount(): number {
    return this.leaves.length;
  }

  get activeCount(): number {
    return this.physicalIndex.size;
  }

  get root(): HashHex {
    const treeRoot = this.layers[this.layers.length - 1]![0]!;
    return leanSnapshot(treeRoot, this.leafCount, this.epoch);
  }

  has(valueInput: bigint | number | string): boolean {
    return this.physicalIndex.has(parseNonSentinel(valueInput));
  }

  /** Append and rewire in O(log n), including the AVL lookup and Merkle paths. */
  insert(valueInput: bigint | number | string): HashHex {
    const value = parseNonSentinel(valueInput);
    if (this.physicalIndex.has(value)) {
      throw new Error(`LeanIMT+ value ${value} already exists`);
    }
    const predecessorValue = this.orderedValues.predecessor(value);
    const predecessorIndex =
      predecessorValue === undefined
        ? 0
        : this.requiredPhysicalIndex(predecessorValue);
    const predecessor = this.leaves[predecessorIndex]!;
    const inheritedNext = predecessor.nextValue;

    predecessor.nextValue = value;
    const newIndex = this.leaves.length;
    this.leaves.push({ value, nextValue: inheritedNext });
    this.physicalIndex.set(value, newIndex);
    this.orderedValues.add(value);

    this.layers[0]![predecessorIndex] = leanLeaf(
      predecessor.value,
      predecessor.nextValue,
    );
    this.layers[0]!.push(leanLeaf(value, inheritedNext));
    this.recompute([predecessorIndex, newIndex]);
    return this.root;
  }

  /** Repair the linked list and retain an authenticated tombstone at its slot. */
  remove(valueInput: bigint | number | string): HashHex {
    const value = parseNonSentinel(valueInput);
    const removedIndex = this.requiredPhysicalIndex(value);
    const removed = this.leaves[removedIndex]!;
    const predecessorValue = this.orderedValues.predecessor(value);
    const predecessorIndex =
      predecessorValue === undefined
        ? 0
        : this.requiredPhysicalIndex(predecessorValue);
    const predecessor = this.leaves[predecessorIndex]!;

    predecessor.nextValue = removed.nextValue;
    removed.value = 0n;
    removed.nextValue = 0n;
    this.physicalIndex.delete(value);
    this.orderedValues.delete(value);

    this.layers[0]![predecessorIndex] = leanLeaf(
      predecessor.value,
      predecessor.nextValue,
    );
    this.layers[0]![removedIndex] = leanLeaf(0n, 0n);
    this.recompute([predecessorIndex, removedIndex]);
    return this.root;
  }

  membershipWitness(valueInput: bigint | number | string): LeanImtPlusWitness {
    const query = parseNonSentinel(valueInput);
    const leafIndex = this.requiredPhysicalIndex(query);
    return this.makeWitness("membership", query, leafIndex);
  }

  nonMembershipWitness(
    valueInput: bigint | number | string,
  ): LeanImtPlusWitness {
    const query = parseNonSentinel(valueInput);
    if (this.physicalIndex.has(query)) {
      throw new Error(`LeanIMT+ value ${query} is a member`);
    }
    const predecessorValue = this.orderedValues.predecessor(query);
    const leafIndex =
      predecessorValue === undefined
        ? 0
        : this.requiredPhysicalIndex(predecessorValue);
    return this.makeWitness("non-membership", query, leafIndex);
  }

  static verify(
    witness: LeanImtPlusWitness,
    context: LeanImtPlusVerificationContext,
  ): boolean {
    try {
      assertEpoch(witness.epoch);
      assertEpoch(context.epoch);
      const supportedMode =
        witness.mode === "membership" || witness.mode === "non-membership";
      const supportedExpectedMode =
        context.expectedMode === "membership" ||
        context.expectedMode === "non-membership";
      if (
        witness.design !== "zkid-leanimt-plus-v1" ||
        !supportedMode ||
        !supportedExpectedMode ||
        witness.mode !== context.expectedMode ||
        witness.epoch !== context.epoch ||
        witness.root !== context.root ||
        !Number.isSafeInteger(witness.leafCount) ||
        witness.leafCount < 1 ||
        !Number.isSafeInteger(witness.leafIndex) ||
        witness.leafIndex < 0 ||
        witness.leafIndex >= witness.leafCount
      ) {
        return false;
      }

      const query = parseNonSentinel(witness.query);
      const value = parseU64(witness.leaf.value);
      const nextValue = parseU64(witness.leaf.nextValue);
      if (value === 0n && witness.leafIndex !== 0) {
        // A {0,0} leaf outside slot zero is a tombstone, never a low leaf.
        return false;
      }
      if (value > 0n && value === nextValue) return false;

      let hash = leanLeaf(value, nextValue);
      let position = witness.leafIndex;
      let width = witness.leafCount;
      let pathOffset = 0;
      while (width > 1) {
        const step = witness.path[pathOffset];
        if (!step) return false;
        const hasRightSibling = position % 2 === 0 && position + 1 < width;
        const isRightChild = position % 2 === 1;
        if (!hasRightSibling && !isRightChild) {
          if (step.sibling !== null || step.side !== "left") return false;
          // LeanIMT promotes the unpaired node without hashing it.
        } else {
          if (step.sibling === null) return false;
          hexToBytes(step.sibling);
          if (isRightChild) {
            if (step.side !== "right") return false;
            hash = leanNode(step.sibling, hash);
          } else {
            if (step.side !== "left") return false;
            hash = leanNode(hash, step.sibling);
          }
        }
        position = Math.floor(position / 2);
        width = Math.ceil(width / 2);
        pathOffset += 1;
      }
      if (pathOffset !== witness.path.length) return false;
      if (leanSnapshot(hash, witness.leafCount, witness.epoch) !== context.root) {
        return false;
      }

      if (witness.mode === "membership") {
        return value > 0n && value === query;
      }
      return value < query && (nextValue === 0n || query < nextValue);
    } catch {
      return false;
    }
  }

  private makeWitness(
    mode: "membership" | "non-membership",
    query: bigint,
    leafIndex: number,
  ): LeanImtPlusWitness {
    const leaf = this.leaves[leafIndex]!;
    return {
      design: "zkid-leanimt-plus-v1",
      mode,
      query: query.toString(10),
      epoch: this.epoch,
      root: this.root,
      leafCount: this.leafCount,
      leafIndex,
      leaf: {
        value: leaf.value.toString(10),
        nextValue: leaf.nextValue.toString(10),
      },
      path: this.pathFor(leafIndex),
    };
  }

  private pathFor(leafIndex: number): LeanImtPlusPathStep[] {
    const path: LeanImtPlusPathStep[] = [];
    let position = leafIndex;
    let width = this.leafCount;
    let level = 0;
    while (width > 1) {
      if (position % 2 === 1) {
        path.push({
          sibling: this.layers[level]![position - 1]!,
          side: "right",
        });
      } else if (position + 1 < width) {
        path.push({
          sibling: this.layers[level]![position + 1]!,
          side: "left",
        });
      } else {
        path.push({ sibling: null, side: "left" });
      }
      position = Math.floor(position / 2);
      width = Math.ceil(width / 2);
      level += 1;
    }
    return path;
  }

  private recompute(changedLeafIndices: readonly number[]): void {
    let changed = new Set(changedLeafIndices);
    let level = 0;
    while (this.layers[level]!.length > 1) {
      const current = this.layers[level]!;
      const nextLength = Math.ceil(current.length / 2);
      const next = this.layers[level + 1] ?? new Array<HashHex>(nextLength);
      next.length = nextLength;
      const changedParents = new Set<number>();
      for (const index of changed) changedParents.add(Math.floor(index / 2));
      for (const parentIndex of changedParents) {
        const left = current[parentIndex * 2]!;
        const right = current[parentIndex * 2 + 1];
        next[parentIndex] = right === undefined ? left : leanNode(left, right);
      }
      this.layers[level + 1] = next;
      changed = changedParents;
      level += 1;
    }
    this.layers.length = level + 1;
  }

  private requiredPhysicalIndex(value: bigint): number {
    const index = this.physicalIndex.get(value);
    if (index === undefined) throw new Error(`LeanIMT+ value ${value} is absent`);
    return index;
  }
}

function leanLeaf(value: bigint, nextValue: bigint): HashHex {
  return hashDomain(
    "zkid-leanimt-plus-leaf-v1",
    u64(value),
    u64(nextValue),
    byte(1),
  );
}

function leanNode(left: HashHex, right: HashHex): HashHex {
  return hashDomain(
    "zkid-leanimt-plus-node-v1",
    hexToBytes(left),
    hexToBytes(right),
  );
}

function leanSnapshot(treeRoot: HashHex, leafCount: number, epoch: number): HashHex {
  return hashDomain(
    "zkid-leanimt-plus-snapshot-v1",
    u64(epoch),
    u64(leafCount),
    hexToBytes(treeRoot),
  );
}

function parseNonSentinel(value: bigint | number | string): bigint {
  const parsed = parseU64(value);
  if (parsed === 0n) throw new RangeError("zero is reserved for the LeanIMT+ sentinel");
  return parsed;
}

function parseU64(value: bigint | number | string): bigint {
  let parsed: bigint;
  if (typeof value === "bigint") {
    parsed = value;
  } else if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new RangeError("identifier numbers must be safe integers");
    }
    parsed = BigInt(value);
  } else {
    if (!/^(0|[1-9][0-9]*)$/.test(value)) {
      throw new RangeError("identifier must be a canonical unsigned decimal integer");
    }
    parsed = BigInt(value);
  }
  if (parsed < 0n || parsed > MAX_U64) {
    throw new RangeError("identifier must fit in an unsigned 64-bit integer");
  }
  return parsed;
}

interface AvlNode {
  readonly value: bigint;
  height: number;
  left?: AvlNode;
  right?: AvlNode;
}

class AvlSet {
  private root?: AvlNode;

  add(value: bigint): void {
    this.root = insertAvl(this.root, value);
  }

  delete(value: bigint): void {
    this.root = deleteAvl(this.root, value);
  }

  predecessor(value: bigint): bigint | undefined {
    let node = this.root;
    let found: bigint | undefined;
    while (node) {
      if (node.value < value) {
        found = node.value;
        node = node.right;
      } else {
        node = node.left;
      }
    }
    return found;
  }
}

function insertAvl(node: AvlNode | undefined, value: bigint): AvlNode {
  if (!node) return { value, height: 1 };
  if (value < node.value) node.left = insertAvl(node.left, value);
  else if (value > node.value) node.right = insertAvl(node.right, value);
  else throw new Error(`AVL value ${value} already exists`);
  return balance(node);
}

function deleteAvl(node: AvlNode | undefined, value: bigint): AvlNode | undefined {
  if (!node) throw new Error(`AVL value ${value} is absent`);
  if (value < node.value) node.left = deleteAvl(node.left, value);
  else if (value > node.value) node.right = deleteAvl(node.right, value);
  else if (!node.left) return node.right;
  else if (!node.right) return node.left;
  else {
    const successor = minimum(node.right);
    const replacement: AvlNode = {
      value: successor.value,
      height: node.height,
      left: node.left,
      right: deleteAvl(node.right, successor.value),
    };
    return balance(replacement);
  }
  return balance(node);
}

function minimum(node: AvlNode): AvlNode {
  let current = node;
  while (current.left) current = current.left;
  return current;
}

function balance(node: AvlNode): AvlNode {
  updateHeight(node);
  const factor = height(node.left) - height(node.right);
  if (factor > 1) {
    if (height(node.left!.left) < height(node.left!.right)) {
      node.left = rotateLeft(node.left!);
    }
    return rotateRight(node);
  }
  if (factor < -1) {
    if (height(node.right!.right) < height(node.right!.left)) {
      node.right = rotateRight(node.right!);
    }
    return rotateLeft(node);
  }
  return node;
}

function rotateLeft(node: AvlNode): AvlNode {
  const pivot = node.right!;
  node.right = pivot.left;
  pivot.left = node;
  updateHeight(node);
  updateHeight(pivot);
  return pivot;
}

function rotateRight(node: AvlNode): AvlNode {
  const pivot = node.left!;
  node.left = pivot.right;
  pivot.right = node;
  updateHeight(node);
  updateHeight(pivot);
  return pivot;
}

function updateHeight(node: AvlNode): void {
  node.height = Math.max(height(node.left), height(node.right)) + 1;
}

function height(node: AvlNode | undefined): number {
  return node?.height ?? 0;
}

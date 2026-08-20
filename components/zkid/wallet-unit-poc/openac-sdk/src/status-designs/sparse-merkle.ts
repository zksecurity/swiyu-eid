import {
  assertEpoch,
  byte,
  hashDomain,
  hexToBytes,
  u64,
  type HashHex,
} from "./hashing.js";

export const SPARSE_STATUS_DEPTH = 64;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;

export interface SparseStatusWitness {
  readonly design: "sparse-revoked-set-v1";
  readonly identifier: string;
  readonly revoked: boolean;
  readonly epoch: number;
  readonly root: HashHex;
  /** Bottom-up siblings, one for every bit in the 64-bit identifier. */
  readonly siblings: readonly HashHex[];
}

export interface SparseStatusVerificationContext {
  readonly root: HashHex;
  readonly epoch: number;
  readonly expectedRevoked: boolean;
}

/**
 * A depth-64 sparse Merkle set of revoked identifiers.
 *
 * Missing leaves are canonically "valid". Revoking or restoring one identifier
 * touches exactly one leaf and one node per level; it never scans issued
 * credentials or other revoked entries.
 */
export class SparseStatusTree {
  readonly depth = SPARSE_STATUS_DEPTH;
  readonly epoch: number;

  private readonly nodes = new Map<string, HashHex>();
  private readonly defaultHashes: readonly HashHex[];

  private constructor(epoch: number, revokedIdentifiers: readonly bigint[]) {
    assertEpoch(epoch);
    this.epoch = epoch;
    this.defaultHashes = buildDefaultHashes();
    for (const identifier of revokedIdentifiers) {
      if (this.isRevoked(identifier)) {
        throw new Error(`duplicate revoked identifier ${identifier}`);
      }
      this.setRevoked(identifier, true);
    }
  }

  static build(
    revokedIdentifiers: readonly (bigint | number | string)[],
    epoch: number,
  ): SparseStatusTree {
    return new SparseStatusTree(
      epoch,
      revokedIdentifiers.map((identifier) => parseIdentifier(identifier)),
    );
  }

  get root(): HashHex {
    return sparseSnapshot(
      this.nodes.get(nodeKey(SPARSE_STATUS_DEPTH, 0n)) ??
        this.defaultHashes[SPARSE_STATUS_DEPTH]!,
      this.epoch,
    );
  }

  isRevoked(identifierInput: bigint | number | string): boolean {
    const identifier = parseIdentifier(identifierInput);
    return this.nodes.has(nodeKey(0, identifier));
  }

  /** Mutate this snapshot in O(depth), returning the resulting signed-root value. */
  setRevoked(
    identifierInput: bigint | number | string,
    revoked: boolean,
  ): HashHex {
    const identifier = parseIdentifier(identifierInput);
    let position = identifier;
    if (revoked) {
      this.nodes.set(nodeKey(0, position), revokedLeaf(identifier));
    } else {
      this.nodes.delete(nodeKey(0, position));
    }

    for (let level = 0; level < SPARSE_STATUS_DEPTH; level += 1) {
      const leftPosition = position % 2n === 0n ? position : position - 1n;
      const rightPosition = leftPosition + 1n;
      const left =
        this.nodes.get(nodeKey(level, leftPosition)) ?? this.defaultHashes[level]!;
      const right =
        this.nodes.get(nodeKey(level, rightPosition)) ?? this.defaultHashes[level]!;
      const parentPosition = position >> 1n;
      const parent = sparseNode(left, right);
      const parentKey = nodeKey(level + 1, parentPosition);
      if (parent === this.defaultHashes[level + 1]) {
        this.nodes.delete(parentKey);
      } else {
        this.nodes.set(parentKey, parent);
      }
      position = parentPosition;
    }
    return this.root;
  }

  witness(identifierInput: bigint | number | string): SparseStatusWitness {
    const identifier = parseIdentifier(identifierInput);
    const siblings: HashHex[] = [];
    let position = identifier;
    for (let level = 0; level < SPARSE_STATUS_DEPTH; level += 1) {
      const siblingPosition = position % 2n === 0n ? position + 1n : position - 1n;
      siblings.push(
        this.nodes.get(nodeKey(level, siblingPosition)) ?? this.defaultHashes[level]!,
      );
      position >>= 1n;
    }
    return {
      design: "sparse-revoked-set-v1",
      identifier: identifier.toString(10),
      revoked: this.isRevoked(identifier),
      epoch: this.epoch,
      root: this.root,
      siblings,
    };
  }

  static verify(
    witness: SparseStatusWitness,
    context: SparseStatusVerificationContext,
  ): boolean {
    try {
      assertEpoch(witness.epoch);
      assertEpoch(context.epoch);
      if (
        witness.design !== "sparse-revoked-set-v1" ||
        typeof witness.revoked !== "boolean" ||
        typeof context.expectedRevoked !== "boolean" ||
        witness.epoch !== context.epoch ||
        witness.root !== context.root ||
        witness.revoked !== context.expectedRevoked ||
        witness.siblings.length !== SPARSE_STATUS_DEPTH
      ) {
        return false;
      }
      const identifier = parseIdentifier(witness.identifier);
      let hash = witness.revoked ? revokedLeaf(identifier) : emptyLeaf();
      let position = identifier;
      for (const sibling of witness.siblings) {
        // hexToBytes performs strict 32-byte hash validation before hashing.
        hexToBytes(sibling);
        hash =
          position % 2n === 0n
            ? sparseNode(hash, sibling)
            : sparseNode(sibling, hash);
        position >>= 1n;
      }
      return sparseSnapshot(hash, witness.epoch) === context.root;
    } catch {
      return false;
    }
  }
}

function buildDefaultHashes(): HashHex[] {
  const defaults = [emptyLeaf()];
  for (let level = 0; level < SPARSE_STATUS_DEPTH; level += 1) {
    defaults.push(sparseNode(defaults[level]!, defaults[level]!));
  }
  return defaults;
}

function emptyLeaf(): HashHex {
  return hashDomain("swiyu-sparse-status-empty-v1", byte(0));
}

function revokedLeaf(identifier: bigint): HashHex {
  return hashDomain("swiyu-sparse-status-revoked-v1", u64(identifier), byte(1));
}

function sparseNode(left: HashHex, right: HashHex): HashHex {
  return hashDomain(
    "swiyu-sparse-status-node-v1",
    hexToBytes(left),
    hexToBytes(right),
  );
}

function sparseSnapshot(treeRoot: HashHex, epoch: number): HashHex {
  return hashDomain(
    "swiyu-sparse-status-snapshot-v1",
    u64(epoch),
    hexToBytes(treeRoot),
  );
}

function nodeKey(level: number, position: bigint): string {
  return `${level}:${position}`;
}

function parseIdentifier(value: bigint | number | string): bigint {
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

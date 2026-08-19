import {
  assertEpoch,
  hashDomain,
  hexToBytes,
  u32,
  u64,
  type HashHex,
} from "./hashing.js";
import type { StatusBit } from "./fixed-index-merkle.js";

export const SWIYU_PACKED_STATUS_CHUNK_BYTES = 64;
export const SWIYU_PACKED_STATUS_CHUNK_ENTRIES =
  SWIYU_PACKED_STATUS_CHUNK_BYTES * 4;
export const SWIYU_PACKED_STATUS_TERNARY_DEPTH = 6;
export const SWIYU_PACKED_STATUS_MAX_ENTRIES = 131_072;

export interface PackedStatusChunkWitness {
  readonly design: "packed-status-chunk-ternary-merkle-v2";
  readonly index: number;
  readonly status: StatusBit;
  readonly entryCount: number;
  readonly epoch: number;
  readonly root: HashHex;
  /** Authenticated 64-byte packed leaf. Tail bytes in the final chunk are zero. */
  readonly chunk: readonly number[];
  /** Two siblings per level, ordered after omitting the selected child. */
  readonly siblings: readonly (readonly [HashHex, HashHex])[];
}

export interface PackedStatusChunkVerificationContext {
  readonly root: HashHex;
  readonly epoch: number;
  readonly expectedStatus: StatusBit;
}

interface PackedNode {
  readonly hash: HashHex;
  readonly children?: readonly [PackedNode, PackedNode, PackedNode];
  readonly chunk?: Uint8Array;
}

/**
 * Versioned status tree over the authenticated Token Status List byte array.
 *
 * Four LSB-first 2-bit statuses live in each byte, matching the IETF Status
 * List representation. A 64-byte leaf therefore authenticates 256 statuses.
 */
export class PackedStatusChunkTree {
  readonly entryCount: number;
  readonly epoch: number;
  readonly root: HashHex;
  readonly depth = SWIYU_PACKED_STATUS_TERNARY_DEPTH;

  private constructor(
    private readonly treeRoot: PackedNode,
    private readonly packed: Uint8Array,
    epoch: number,
  ) {
    this.entryCount = packed.length * 4;
    this.epoch = epoch;
    this.root = packedStatusSnapshotRootV2(
      treeRoot.hash,
      this.entryCount,
      epoch,
    );
  }

  static buildSwiyuProfile(
    packedStatuses: Uint8Array,
    epoch: number,
  ): PackedStatusChunkTree {
    assertEpoch(epoch);
    if (!(packedStatuses instanceof Uint8Array)) {
      throw new TypeError("packed status list must be a Uint8Array");
    }
    if (packedStatuses.length < 1) {
      throw new RangeError("packed status list needs at least one byte");
    }
    if (packedStatuses.length * 4 > SWIYU_PACKED_STATUS_MAX_ENTRIES) {
      throw new RangeError(
        `packed status list exceeds ${SWIYU_PACKED_STATUS_MAX_ENTRIES} entries`,
      );
    }
    const copied = Uint8Array.from(packedStatuses);
    return new PackedStatusChunkTree(buildTree(copied), copied, epoch);
  }

  witness(index: number): PackedStatusChunkWitness {
    assertIndex(index, this.entryCount);
    const chunkIndex = Math.floor(index / SWIYU_PACKED_STATUS_CHUNK_ENTRIES);
    const topDownSiblings: Array<[HashHex, HashHex]> = [];
    let node = this.treeRoot;
    for (let remaining = this.depth; remaining > 0; remaining -= 1) {
      const children = node.children;
      if (!children) throw new Error("malformed packed status Merkle node");
      const stride = 3 ** (remaining - 1);
      const position = Math.floor(chunkIndex / stride) % 3;
      topDownSiblings.push(children
        .filter((_, child) => child !== position)
        .map((child) => child.hash) as [HashHex, HashHex]);
      node = children[position]!;
    }
    if (!node.chunk) throw new Error("selected a packed status padding leaf");
    const byte = this.packed[Math.floor(index / 4)]!;
    const status = ((byte >> ((index % 4) * 2)) & 0x03) as StatusBit;
    return Object.freeze({
      design: "packed-status-chunk-ternary-merkle-v2" as const,
      index,
      status,
      entryCount: this.entryCount,
      epoch: this.epoch,
      root: this.root,
      chunk: Object.freeze(Array.from(node.chunk)),
      siblings: Object.freeze(topDownSiblings.reverse().map((pair) =>
        Object.freeze(pair) as readonly [HashHex, HashHex])),
    });
  }

  static verify(
    witness: PackedStatusChunkWitness,
    context: PackedStatusChunkVerificationContext,
  ): boolean {
    try {
      assertEpoch(context.epoch);
      assertEpoch(witness.epoch);
      assertStatus(context.expectedStatus, "expected status");
      assertStatus(witness.status, "witness status");
      if (
        witness.design !== "packed-status-chunk-ternary-merkle-v2"
        || witness.epoch !== context.epoch
        || witness.root !== context.root
        || witness.status !== context.expectedStatus
        || witness.entryCount % 4 !== 0
        || witness.entryCount > SWIYU_PACKED_STATUS_MAX_ENTRIES
        || witness.chunk.length !== SWIYU_PACKED_STATUS_CHUNK_BYTES
        || witness.siblings.length !== SWIYU_PACKED_STATUS_TERNARY_DEPTH
      ) return false;
      assertIndex(witness.index, witness.entryCount);
      const chunk = Uint8Array.from(witness.chunk, (value) => {
        if (!Number.isInteger(value) || value < 0 || value > 255) {
          throw new RangeError("packed status chunk contains a non-byte value");
        }
        return value;
      });
      const byteOffset = Math.floor(witness.index / 4)
        % SWIYU_PACKED_STATUS_CHUNK_BYTES;
      const slot = witness.index % 4;
      if (((chunk[byteOffset]! >> (slot * 2)) & 0x03) !== witness.status) {
        return false;
      }
      const chunkIndex = Math.floor(
        witness.index / SWIYU_PACKED_STATUS_CHUNK_ENTRIES,
      );
      const packedByteLength = witness.entryCount / 4;
      const firstPaddingByte = Math.max(
        0,
        packedByteLength - chunkIndex * SWIYU_PACKED_STATUS_CHUNK_BYTES,
      );
      for (
        let offset = firstPaddingByte;
        offset < SWIYU_PACKED_STATUS_CHUNK_BYTES;
        offset += 1
      ) {
        if (chunk[offset] !== 0) return false;
      }

      let hash = packedStatusChunkLeafV2(chunkIndex, chunk);
      let position = chunkIndex;
      for (const siblings of witness.siblings) {
        if (siblings.length !== 2) return false;
        const trit = position % 3;
        const children = trit === 0
          ? [hash, siblings[0], siblings[1]]
          : trit === 1
            ? [siblings[0], hash, siblings[1]]
            : [siblings[0], siblings[1], hash];
        hash = packedStatusNodeV2(children[0]!, children[1]!, children[2]!);
        position = Math.floor(position / 3);
      }
      return position === 0
        && packedStatusSnapshotRootV2(
          hash,
          witness.entryCount,
          witness.epoch,
        ) === context.root;
    } catch {
      return false;
    }
  }
}

export function packedStatusChunkLeafV2(
  chunkIndex: number,
  chunk: Uint8Array,
): HashHex {
  if (
    !Number.isSafeInteger(chunkIndex)
    || chunkIndex < 0
    || chunkIndex >= 3 ** SWIYU_PACKED_STATUS_TERNARY_DEPTH
  ) throw new RangeError("packed status chunk index is out of range");
  if (chunk.length !== SWIYU_PACKED_STATUS_CHUNK_BYTES) {
    throw new RangeError(
      `packed status chunk must contain ${SWIYU_PACKED_STATUS_CHUNK_BYTES} bytes`,
    );
  }
  return hashDomain("swiyu-status-chunk-v2", u32(chunkIndex), chunk);
}

export function packedStatusPaddingLeafV2(chunkIndex: number): HashHex {
  return hashDomain("swiyu-status-chunk-padding-v2", u32(chunkIndex));
}

export function packedStatusNodeV2(
  first: HashHex,
  second: HashHex,
  third: HashHex,
): HashHex {
  return hashDomain(
    "swiyu-status-node3-v2",
    hexToBytes(first),
    hexToBytes(second),
    hexToBytes(third),
  );
}

export function packedStatusSnapshotRootV2(
  treeRoot: HashHex,
  entryCount: number,
  epoch: number,
): HashHex {
  return hashDomain(
    "swiyu-status-snapshot-v2",
    u32(entryCount),
    u64(epoch),
    hexToBytes(treeRoot),
  );
}

function buildTree(packed: Uint8Array): PackedNode {
  const chunkCount = Math.ceil(packed.length / SWIYU_PACKED_STATUS_CHUNK_BYTES);
  let current: PackedNode[] = Array.from(
    { length: 3 ** SWIYU_PACKED_STATUS_TERNARY_DEPTH },
    (_, chunkIndex) => {
      if (chunkIndex >= chunkCount) {
        return { hash: packedStatusPaddingLeafV2(chunkIndex) };
      }
      const chunk = new Uint8Array(SWIYU_PACKED_STATUS_CHUNK_BYTES);
      chunk.set(packed.subarray(
        chunkIndex * SWIYU_PACKED_STATUS_CHUNK_BYTES,
        (chunkIndex + 1) * SWIYU_PACKED_STATUS_CHUNK_BYTES,
      ));
      return {
        hash: packedStatusChunkLeafV2(chunkIndex, chunk),
        chunk,
      };
    },
  );
  while (current.length > 1) {
    const next: PackedNode[] = [];
    for (let index = 0; index < current.length; index += 3) {
      const children = [
        current[index]!,
        current[index + 1]!,
        current[index + 2]!,
      ] as const;
      next.push({
        hash: packedStatusNodeV2(
          children[0].hash,
          children[1].hash,
          children[2].hash,
        ),
        children,
      });
    }
    current = next;
  }
  return current[0]!;
}

function assertStatus(status: number, label: string): asserts status is StatusBit {
  if (status !== 0 && status !== 1 && status !== 2 && status !== 3) {
    throw new RangeError(`${label} must be a 2-bit status value`);
  }
}

function assertIndex(index: number, entryCount: number): void {
  if (!Number.isSafeInteger(entryCount) || entryCount < 4 || entryCount % 4 !== 0) {
    throw new RangeError("entry count must be a positive multiple of four");
  }
  if (!Number.isSafeInteger(index) || index < 0 || index >= entryCount) {
    throw new RangeError(`status index ${index} is outside 0..${entryCount - 1}`);
  }
}

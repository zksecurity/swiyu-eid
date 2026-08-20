import { FixedIndexStatusTree } from "../status-designs/fixed-index-merkle.js";
import { hexToBytes } from "../status-designs/hashing.js";
import { SWIYU_STATUS_DEPTH } from "./constants.js";
import type {
  SwiyuDenseStatusWitness,
  SwiyuPrivateStatusSnapshot,
} from "./types.js";

/** Recompute the exact fixed-index Merkle path used by the Circom relation. */
export function verifySwiyuDenseStatusWitness(
  witness: SwiyuDenseStatusWitness,
  snapshot: SwiyuPrivateStatusSnapshot,
): void {
  if (witness.status !== 0) {
    throw new Error(`credential status is not valid (value ${witness.status})`);
  }
  if (witness.siblings.length !== SWIYU_STATUS_DEPTH) {
    throw new Error(`status witness must have exactly ${SWIYU_STATUS_DEPTH} siblings`);
  }
  if (
    witness.index < 0 ||
    witness.index >= snapshot.listLength ||
    witness.entryCount !== snapshot.listLength ||
    witness.epoch !== snapshot.epoch ||
    witness.root !== snapshot.root
  ) {
    throw new Error("status witness metadata does not match the resolved snapshot");
  }
  for (const [level, sibling] of witness.siblings.entries()) {
    try {
      hexToBytes(sibling);
    } catch (error) {
      throw new Error(`status sibling ${level} is not a 32-byte SHA digest`, { cause: error });
    }
  }
  if (!FixedIndexStatusTree.verify(witness, {
    root: snapshot.root,
    epoch: snapshot.epoch,
    expectedStatus: 0,
    fixedDepth: SWIYU_STATUS_DEPTH,
  })) {
    throw new Error("status witness does not authenticate the expected snapshot root");
  }
}

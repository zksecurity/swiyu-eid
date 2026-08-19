import { p256 } from "@noble/curves/p256";

export const TS13_LEFT_SENTINEL = 0n;
export const TS13_RIGHT_SENTINEL = 0xffff_ffff_ffff_ffffn;

export interface Ts13AdjacentPairWitness {
  readonly design: "eudi-ts13-adjacent-pair-v1";
  readonly identifier: string;
  readonly left: string;
  readonly right: string;
  readonly epoch: number;
  /** 64-byte IEEE P1363 / JOSE ES256 signature: r || s. */
  readonly rawSignature: string;
}

export interface Ts13VerificationContext {
  readonly epoch: number;
  readonly revokerPublicKey: Uint8Array;
}

/**
 * Executable TS13-style registry.
 *
 * The two reserved uint64 boundary values close the intervals omitted by the
 * draft's revoked-only example. Every issued hidden identifier must therefore
 * be in 1..2^64-2. Changing issuance to bind that identifier is a prerequisite,
 * not something this adapter can retrofit into an existing credential.
 */
export class Ts13AdjacentPairRegistry {
  readonly epoch: number;
  readonly revokedIdentifiers: readonly string[];

  private readonly revoked: readonly bigint[];
  private readonly signatures = new Map<string, string>();

  private constructor(
    revoked: readonly bigint[],
    epoch: number,
    privateKey: Uint8Array,
  ) {
    assertEpoch32(epoch);
    this.epoch = epoch;
    this.revoked = revoked;
    this.revokedIdentifiers = revoked.map((value) => value.toString(10));

    const endpoints = [TS13_LEFT_SENTINEL, ...revoked, TS13_RIGHT_SENTINEL];
    for (let index = 0; index + 1 < endpoints.length; index += 1) {
      const left = endpoints[index]!;
      const right = endpoints[index + 1]!;
      const signature = p256
        .sign(encodeTs13PairMessage(left, right, epoch), privateKey, {
          prehash: true,
          lowS: true,
        })
        .toCompactRawBytes();
      this.signatures.set(pairKey(left, right), bytesToHex(signature));
    }
  }

  static build(
    revokedIdentifiers: readonly (bigint | number | string)[],
    epoch: number,
    privateKey: Uint8Array,
  ): Ts13AdjacentPairRegistry {
    const revoked = revokedIdentifiers
      .map((identifier) => parseIssuedIdentifier(identifier))
      .sort(compareBigInt);
    for (let index = 1; index < revoked.length; index += 1) {
      if (revoked[index - 1] === revoked[index]) {
        throw new Error(`duplicate revoked identifier ${revoked[index]}`);
      }
    }
    return new Ts13AdjacentPairRegistry(revoked, epoch, privateKey);
  }

  /** Reissue the epoch's pair list after adding one revoked identifier. */
  revoke(
    identifierInput: bigint | number | string,
    nextEpoch: number,
    privateKey: Uint8Array,
  ): Ts13AdjacentPairRegistry {
    const identifier = parseIssuedIdentifier(identifierInput);
    if (this.revoked.includes(identifier)) {
      throw new Error(`identifier ${identifier} is already revoked`);
    }
    return Ts13AdjacentPairRegistry.build(
      [...this.revoked, identifier],
      nextEpoch,
      privateKey,
    );
  }

  /** Reissue the epoch's pair list after restoring one identifier. */
  restore(
    identifierInput: bigint | number | string,
    nextEpoch: number,
    privateKey: Uint8Array,
  ): Ts13AdjacentPairRegistry {
    const identifier = parseIssuedIdentifier(identifierInput);
    if (!this.revoked.includes(identifier)) {
      throw new Error(`identifier ${identifier} is not revoked`);
    }
    return Ts13AdjacentPairRegistry.build(
      this.revoked.filter((value) => value !== identifier),
      nextEpoch,
      privateKey,
    );
  }

  witness(identifierInput: bigint | number | string): Ts13AdjacentPairWitness {
    const identifier = parseIssuedIdentifier(identifierInput);
    const insertionIndex = lowerBound(this.revoked, identifier);
    if (this.revoked[insertionIndex] === identifier) {
      throw new Error(`revoked identifier ${identifier} has no valid adjacent-pair witness`);
    }
    const left =
      insertionIndex === 0
        ? TS13_LEFT_SENTINEL
        : this.revoked[insertionIndex - 1]!;
    const right =
      insertionIndex === this.revoked.length
        ? TS13_RIGHT_SENTINEL
        : this.revoked[insertionIndex]!;
    const rawSignature = this.signatures.get(pairKey(left, right));
    if (!rawSignature) throw new Error("adjacent pair is missing its revoker signature");
    return {
      design: "eudi-ts13-adjacent-pair-v1",
      identifier: identifier.toString(10),
      left: left.toString(10),
      right: right.toString(10),
      epoch: this.epoch,
      rawSignature,
    };
  }

  static verify(
    witness: Ts13AdjacentPairWitness,
    context: Ts13VerificationContext,
  ): boolean {
    try {
      assertEpoch32(witness.epoch);
      assertEpoch32(context.epoch);
      if (
        witness.design !== "eudi-ts13-adjacent-pair-v1" ||
        witness.epoch !== context.epoch
      ) {
        return false;
      }
      const identifier = parseIssuedIdentifier(witness.identifier);
      const left = parseU64(witness.left);
      const right = parseU64(witness.right);
      if (!(left < identifier && identifier < right)) return false;
      const signature = strictHexToBytes(witness.rawSignature, 64);
      return p256.verify(
        signature,
        encodeTs13PairMessage(left, right, witness.epoch),
        context.revokerPublicKey,
        { prehash: true, lowS: true },
      );
    } catch {
      return false;
    }
  }
}

/** Exact TS13 encoding: uint64 left || uint64 right || uint32 epoch, all LE. */
export function encodeTs13PairMessage(
  leftInput: bigint | number | string,
  rightInput: bigint | number | string,
  epoch: number,
): Uint8Array {
  const left = parseU64(leftInput);
  const right = parseU64(rightInput);
  assertEpoch32(epoch);
  const message = new Uint8Array(20);
  const view = new DataView(message.buffer);
  view.setBigUint64(0, left, true);
  view.setBigUint64(8, right, true);
  view.setUint32(16, epoch, true);
  return message;
}

function parseIssuedIdentifier(value: bigint | number | string): bigint {
  const parsed = parseU64(value);
  if (parsed === TS13_LEFT_SENTINEL || parsed === TS13_RIGHT_SENTINEL) {
    throw new RangeError("TS13 boundary sentinels are reserved and cannot be issued");
  }
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
  if (parsed < 0n || parsed > TS13_RIGHT_SENTINEL) {
    throw new RangeError("identifier must fit in an unsigned 64-bit integer");
  }
  return parsed;
}

function assertEpoch32(epoch: number): void {
  if (!Number.isSafeInteger(epoch) || epoch < 0 || epoch > 0xffff_ffff) {
    throw new RangeError("TS13 epoch must fit in an unsigned 32-bit integer");
  }
}

function lowerBound(sorted: readonly bigint[], value: bigint): number {
  let low = 0;
  let high = sorted.length;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if (sorted[middle]! < value) low = middle + 1;
    else high = middle;
  }
  return low;
}

function compareBigInt(left: bigint, right: bigint): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function pairKey(left: bigint, right: bigint): string {
  return `${left}:${right}`;
}

function strictHexToBytes(value: string, length: number): Uint8Array {
  if (!new RegExp(`^[0-9a-f]{${length * 2}}$`, "i").test(value)) {
    throw new Error(`expected exactly ${length} bytes of hexadecimal data`);
  }
  return Uint8Array.from(value.match(/../g)!, (octet) => Number.parseInt(octet, 16));
}

function bytesToHex(value: Uint8Array): string {
  return Array.from(value, (octet) => octet.toString(16).padStart(2, "0")).join("");
}

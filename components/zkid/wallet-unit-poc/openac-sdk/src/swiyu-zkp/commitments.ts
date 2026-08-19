import { sha256 } from "@noble/hashes/sha2";
import type {
  SwiyuAuthoritativeStatusSnapshot,
  SwiyuLookupHints,
  SwiyuPrivateStatusSnapshot,
  SwiyuStatusCommitment,
} from "./types.js";
import {
  assertFieldElement,
  bigEndianBytesToBigInt,
} from "./encoding.js";
import { hexToBytes } from "../status-designs/hashing.js";
import {
  SWIYU_MAX_STATUS_LIST_LENGTH,
  SWIYU_P256_SCALAR_ORDER,
  SWIYU_STRING_SLOT_BYTES,
} from "./constants.js";

const encoder = new TextEncoder();

export type SwiyuHashLimbs = SwiyuStatusCommitment;

/** Stable credential lookup digest carried privately from Prepare to Show. */
export function computeSwiyuPreparedLookupCommitment(
  hints: Pick<SwiyuLookupHints, "issuer" | "kid" | "vct">,
): SwiyuHashLimbs {
  const record = concat(
    domain("swiyu-lookup-v1"),
    lengthPrefixedSlot(hints.issuer, SWIYU_STRING_SLOT_BYTES, "issuer"),
    lengthPrefixedSlot(hints.kid, SWIYU_STRING_SLOT_BYTES, "kid"),
    lengthPrefixedSlot(hints.vct, SWIYU_STRING_SLOT_BYTES, "vct"),
  );
  return digestLimbs(record);
}

/** Stable private status-list URI digest carried from Prepare to Show. */
export function computeSwiyuPreparedStatusUriCommitment(
  uri: string,
): SwiyuHashLimbs {
  return digestLimbs(
    concat(domain("swiyu-status-uri-v1"), lengthPrefixedSlot(uri, 160, "status URI")),
  );
}

/** Fresh verifier-session binding derived from Prepare's lookup digest. */
export function computeSwiyuPreparedSessionCommitment(
  challengeHash: bigint,
  lookup: SwiyuHashLimbs,
): SwiyuHashLimbs {
  if (challengeHash < 0n || challengeHash >= SWIYU_P256_SCALAR_ORDER) {
    throw new Error("challenge hash must be a canonical P-256 scalar");
  }
  return digestLimbs(
    concat(
      domain("swiyu-session-v1"),
      bigEndian32(challengeHash),
      bigEndian16(lookup.hashHi),
      bigEndian16(lookup.hashLo),
    ),
  );
}

/** Fresh status binding derived from Prepare's URI digest and a snapshot root. */
export function computeSwiyuPreparedStatusCommitment(
  uri: SwiyuHashLimbs,
  snapshotRoot: string,
): SwiyuHashLimbs {
  if (!/^[0-9a-f]{64}$/.test(snapshotRoot)) {
    throw new Error("status root must be a lowercase 32-byte hexadecimal SHA-256 digest");
  }
  return digestLimbs(
    concat(
      domain("swiyu-status-bind-v1"),
      bigEndian16(uri.hashHi),
      bigEndian16(uri.hashLo),
      hexToBytes(snapshotRoot),
    ),
  );
}

/**
 * Exact 448-byte SHA preimage used by `SwiyuMetadataCommitment`.
 * The challenge scalar makes otherwise-identical credential metadata unique
 * to the verifier session. Bytes 393..447 are reserved zeros.
 */
export function computeSwiyuMetadataCommitment(
  hints: Pick<SwiyuLookupHints, "issuer" | "kid" | "vct">,
  challengeHash: bigint,
): SwiyuHashLimbs {
  if (challengeHash < 0n || challengeHash >= SWIYU_P256_SCALAR_ORDER) {
    throw new Error("challenge hash must be a canonical P-256 scalar");
  }
  const record = new Uint8Array(448);
  let cursor = writeAscii(record, 0, "swiyu-age18-status-v1\0", 22, "metadata domain");
  writeBigEndian32(record, cursor, challengeHash);
  cursor += 32;
  cursor = writeLengthPrefixedSlot(
    record,
    cursor,
    hints.issuer,
    SWIYU_STRING_SLOT_BYTES,
    "issuer",
  );
  cursor = writeLengthPrefixedSlot(
    record,
    cursor,
    hints.kid,
    SWIYU_STRING_SLOT_BYTES,
    "kid",
  );
  writeLengthPrefixedSlot(
    record,
    cursor,
    hints.vct,
    SWIYU_STRING_SLOT_BYTES,
    "vct",
  );

  const digest = sha256(record);
  return {
    hashHi: bigEndianBytesToBigInt(digest.slice(0, 16)),
    hashLo: bigEndianBytesToBigInt(digest.slice(16, 32)),
  };
}

/** Exact SHA-256 record used by `SwiyuStatusProfileCommitment`. */
export function computeSwiyuStatusProfileCommitment(
  snapshot: SwiyuPrivateStatusSnapshot,
): SwiyuHashLimbs {
  validatePrivateStatusSnapshot(snapshot);
  const record = new Uint8Array(256);
  record[0] = 0;
  record[1] = 23;
  writeAscii(record, 2, "swiyu-status-profile-v0", 23, "status profile domain");
  record[25] = snapshot.uri.length;
  writeAscii(record, 26, snapshot.uri, snapshot.uri.length, "status URI");
  record.set(hexToBytes(snapshot.root), 186);
  const digest = sha256(record);
  return {
    hashHi: bigEndianBytesToBigInt(digest.slice(0, 16)),
    hashLo: bigEndianBytesToBigInt(digest.slice(16, 32)),
  };
}

export function validatePrivateStatusSnapshot(
  snapshot: SwiyuPrivateStatusSnapshot,
): void {
  validateStatusSnapshotIdentity(snapshot.id);
  validateStatusCoordinates(snapshot.epoch, snapshot.listLength);
  assertAsciiValue(snapshot.uri, "status URI");
  if (snapshot.uri.length === 0 || snapshot.uri.length > 160) {
    throw new Error("status URI length must be in 1..160");
  }
  if (!/^[0-9a-f]{64}$/.test(snapshot.root)) {
    throw new Error("status root must be a lowercase 32-byte hexadecimal SHA-256 digest");
  }
}

export function validateAuthoritativeStatusSnapshot(
  snapshot: SwiyuAuthoritativeStatusSnapshot,
): void {
  validateStatusSnapshotIdentity(snapshot.id);
  assertBoundedAscii(snapshot.issuer, "status snapshot issuer", SWIYU_STRING_SLOT_BYTES);
  assertBoundedAscii(snapshot.kid, "status snapshot kid", SWIYU_STRING_SLOT_BYTES);
  assertBoundedAscii(snapshot.subject, "status snapshot subject", 160);
  validateStatusCoordinates(snapshot.epoch, snapshot.listLength);
  if (typeof snapshot.validBefore !== "bigint" || snapshot.validBefore < 0n) {
    throw new Error("status snapshot validBefore must be a non-negative bigint");
  }
  if (snapshot.validBefore >= 1n << 64n) {
    throw new Error("status snapshot validBefore must fit an unsigned 64-bit integer");
  }
  if (
    typeof snapshot.provenance !== "string" ||
    snapshot.provenance.length === 0 ||
    snapshot.provenance.length > 512
  ) {
    throw new Error("status snapshot provenance length must be in 1..512");
  }
  assertAsciiValue(snapshot.provenance, "status snapshot provenance");
  if (
    typeof snapshot.commitment !== "object" ||
    snapshot.commitment === null
  ) {
    throw new Error("status snapshot commitment is required");
  }
  assertFieldElement(snapshot.commitment.hashHi, "status snapshot commitment high limb");
  assertFieldElement(snapshot.commitment.hashLo, "status snapshot commitment low limb");
}

function validateStatusSnapshotIdentity(id: string): void {
  if (typeof id !== "string") {
    throw new Error("status snapshot id must be a string");
  }
  if (id.length === 0 || id.length > 256) {
    throw new Error("status snapshot id length must be in 1..256");
  }
  assertAsciiValue(id, "status snapshot id");
}

function validateStatusCoordinates(epoch: number, listLength: number): void {
  if (!Number.isSafeInteger(epoch) || epoch < 0) {
    throw new Error("status epoch must be a non-negative safe integer");
  }
  if (
    !Number.isInteger(listLength) ||
    listLength < 1 ||
    listLength > SWIYU_MAX_STATUS_LIST_LENGTH
  ) {
    throw new Error(
      `status list length must be in 1..${SWIYU_MAX_STATUS_LIST_LENGTH} for the fixed 17-level circuit`,
    );
  }
}

function writeBigEndian32(
  target: Uint8Array,
  offset: number,
  value: bigint,
): void {
  let remaining = value;
  for (let index = 31; index >= 0; index -= 1) {
    target[offset + index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
}

function writeLengthPrefixedSlot(
  target: Uint8Array,
  offset: number,
  value: string,
  slotLength: number,
  label: string,
): number {
  assertAsciiValue(value, label);
  if (value.length === 0 || value.length > slotLength) {
    throw new Error(`${label} length must be in 1..${slotLength}`);
  }
  target[offset] = value.length;
  writeAscii(target, offset + 1, value, value.length, label);
  return offset + 1 + slotLength;
}

function writeAscii(
  target: Uint8Array,
  offset: number,
  value: string,
  expectedLength: number,
  label: string,
): number {
  const encoded = encoder.encode(value);
  if (encoded.length !== expectedLength) {
    throw new Error(`${label} must contain exactly ${expectedLength} ASCII bytes`);
  }
  target.set(encoded, offset);
  return offset + expectedLength;
}

function assertAsciiValue(value: string, label: string): void {
  if (encoder.encode(value).length !== value.length) {
    throw new Error(`${label} must contain ASCII bytes only`);
  }
}

function assertBoundedAscii(
  value: string,
  label: string,
  maximumLength: number,
): void {
  if (typeof value !== "string" || value.length === 0 || value.length > maximumLength) {
    throw new Error(`${label} length must be in 1..${maximumLength}`);
  }
  assertAsciiValue(value, label);
}

function domain(value: string): Uint8Array {
  const encoded = encoder.encode(value);
  if (encoded.length > 0xffff) throw new Error("commitment domain is too long");
  return concat(
    new Uint8Array([(encoded.length >>> 8) & 0xff, encoded.length & 0xff]),
    encoded,
  );
}

function lengthPrefixedSlot(
  value: string,
  slotLength: number,
  label: string,
): Uint8Array {
  assertAsciiValue(value, label);
  if (value.length === 0 || value.length > slotLength || slotLength > 255) {
    throw new Error(`${label} length must be in 1..${slotLength}`);
  }
  const result = new Uint8Array(1 + slotLength);
  result[0] = value.length;
  result.set(encoder.encode(value), 1);
  return result;
}

function bigEndian32(value: bigint): Uint8Array {
  return bigEndianFixed(value, 32);
}

function bigEndian16(value: bigint): Uint8Array {
  return bigEndianFixed(value, 16);
}

function bigEndianFixed(value: bigint, length: number): Uint8Array {
  if (value < 0n || value >= 1n << BigInt(length * 8)) {
    throw new Error(`value does not fit ${length} bytes`);
  }
  const result = new Uint8Array(length);
  let remaining = value;
  for (let index = length - 1; index >= 0; index -= 1) {
    result[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return result;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function digestLimbs(record: Uint8Array): SwiyuHashLimbs {
  const digest = sha256(record);
  return {
    hashHi: bigEndianBytesToBigInt(digest.slice(0, 16)),
    hashLo: bigEndianBytesToBigInt(digest.slice(16, 32)),
  };
}

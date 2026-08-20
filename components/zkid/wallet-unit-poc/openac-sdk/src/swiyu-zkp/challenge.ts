import { sha256 } from "@noble/hashes/sha2";
import {
  SWIYU_AGE18_STATUS_PROFILE,
  SWIYU_P256_SCALAR_ORDER,
} from "./constants.js";
import { parseSwiyuIsoDate } from "./date.js";
import {
  bigEndianBytesToBigInt,
  concatBytes,
} from "./encoding.js";
import type { SwiyuChallenge } from "./types.js";

const CHALLENGE_DOMAIN = new TextEncoder().encode("swiyu-show-v0\0");
const encoder = new TextEncoder();

/**
 * Canonical, collision-free encoding of the verifier session tuple.
 * Every value is prefixed with a four-byte big-endian UTF-8 length.
 */
export function encodeSwiyuChallenge(challenge: SwiyuChallenge): Uint8Array {
  validateSwiyuChallenge(challenge);
  const fields = [
    challenge.nonce,
    challenge.clientId,
    challenge.responseUri,
    challenge.state,
    challenge.queryId,
    challenge.profile,
    challenge.cutoffDate,
    challenge.currentTime.toString(10),
    challenge.statusListSnapshot,
  ];
  const encoded = fields.map((field) => lengthPrefix(encoder.encode(field)));
  return concatBytes([CHALLENGE_DOMAIN, ...encoded]);
}

export function hashSwiyuChallenge(challenge: SwiyuChallenge): {
  digest: Uint8Array;
  scalar: bigint;
} {
  const digest = sha256(encodeSwiyuChallenge(challenge));
  return {
    digest,
    scalar: bigEndianBytesToBigInt(digest) % SWIYU_P256_SCALAR_ORDER,
  };
}

export function validateSwiyuChallenge(challenge: SwiyuChallenge): void {
  if (typeof challenge.profile !== "string") {
    throw new Error("profile must be a string");
  }
  if (challenge.profile !== SWIYU_AGE18_STATUS_PROFILE) {
    throw new Error(`Unsupported profile ${JSON.stringify(challenge.profile)}`);
  }
  const stringFields: Array<[string, unknown]> = [
    ["nonce", challenge.nonce],
    ["client_id", challenge.clientId],
    ["response_uri", challenge.responseUri],
    ["state", challenge.state],
    ["query_id", challenge.queryId],
    ["status_list_snapshot", challenge.statusListSnapshot],
  ];
  for (const [label, value] of stringFields) {
    if (typeof value !== "string") {
      throw new Error(`${label} must be a string`);
    }
    const length = encoder.encode(value).length;
    if (length < 1 || length > 4096) {
      throw new Error(`${label} UTF-8 length must be in 1..4096`);
    }
  }
  if (typeof challenge.cutoffDate !== "string") {
    throw new Error("cutoff_date must be a string");
  }
  parseSwiyuIsoDate(challenge.cutoffDate, "cutoff_date");
  if (typeof challenge.currentTime !== "bigint") {
    throw new Error("current_time must be a bigint Unix-seconds value");
  }
  if (challenge.currentTime < 0n || challenge.currentTime >= 1n << 64n) {
    throw new Error("current_time must fit an unsigned 64-bit integer");
  }
}

function lengthPrefix(value: Uint8Array): Uint8Array {
  const output = new Uint8Array(4 + value.length);
  const view = new DataView(output.buffer, output.byteOffset, output.byteLength);
  view.setUint32(0, value.length, false);
  output.set(value, 4);
  return output;
}

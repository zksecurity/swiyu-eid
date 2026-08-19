import { base64Decode, base64urlEncode, bytesToBigInt } from "../utils.js";
import { SWIYU_CIRCUIT_FIELD } from "./constants.js";

const BASE64URL = /^[A-Za-z0-9_-]+$/;

export function decodeBase64urlStrict(
  value: string,
  label: string,
  exactBytes?: number,
): Uint8Array {
  if (value.length === 0 || !BASE64URL.test(value)) {
    throw new Error(`${label} is not unpadded base64url`);
  }
  // An unpadded base64url string can never have a remainder of one.
  if (value.length % 4 === 1) {
    throw new Error(`${label} has an impossible base64url length`);
  }
  const bytes = base64Decode(value);
  if (base64urlEncode(bytes) !== value) {
    throw new Error(`${label} is not canonically encoded`);
  }
  if (exactBytes !== undefined && bytes.length !== exactBytes) {
    throw new Error(`${label} must decode to exactly ${exactBytes} bytes`);
  }
  return bytes;
}

export function decodeUtf8Strict(bytes: Uint8Array, label: string): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    throw new Error(
      `${label} is not valid UTF-8: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

export function asciiPadded(
  value: string,
  length: number,
  label: string,
): bigint[] {
  if (value.length === 0 || value.length > length) {
    throw new Error(`${label} length must be between 1 and ${length}`);
  }
  const output = Array<bigint>(length).fill(0n);
  for (let index = 0; index < value.length; index++) {
    const byte = value.charCodeAt(index);
    if (byte > 0x7f) throw new Error(`${label} must contain ASCII bytes only`);
    output[index] = BigInt(byte);
  }
  return output;
}

export function bytesAsBigints(bytes: Uint8Array): bigint[] {
  return Array.from(bytes, (byte) => BigInt(byte));
}

export function bigEndianBytesToBigInt(bytes: Uint8Array): bigint {
  return bytesToBigInt(bytes);
}

export function bigintToLittleEndian32(value: bigint): Uint8Array {
  assertFieldElement(value, "public scalar");
  const output = new Uint8Array(32);
  let remaining = value;
  for (let index = 0; index < output.length; index++) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

export function littleEndian32ToBigint(bytes: Uint8Array): bigint {
  if (bytes.length !== 32) {
    throw new Error(`Expected a 32-byte scalar, got ${bytes.length}`);
  }
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index--) {
    value = (value << 8n) | BigInt(bytes[index]!);
  }
  assertFieldElement(value, "public scalar");
  return value;
}

export function assertFieldElement(value: bigint, label: string): void {
  if (value < 0n || value >= SWIYU_CIRCUIT_FIELD) {
    throw new Error(`${label} is outside the secq256r1 circuit field`);
  }
}

export function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

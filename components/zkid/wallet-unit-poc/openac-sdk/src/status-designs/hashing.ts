import { sha256 } from "@noble/hashes/sha2";

const encoder = new TextEncoder();

export type HashHex = string;

export function hashDomain(domain: string, ...parts: Uint8Array[]): HashHex {
  const domainBytes = encoder.encode(domain);
  const input = new Uint8Array(
    2 + domainBytes.length + parts.reduce((total, part) => total + part.length, 0),
  );
  const view = new DataView(input.buffer);
  view.setUint16(0, domainBytes.length, false);
  input.set(domainBytes, 2);
  let offset = 2 + domainBytes.length;
  for (const part of parts) {
    input.set(part, offset);
    offset += part.length;
  }
  return bytesToHex(sha256(input));
}

export function utf8(value: string): Uint8Array {
  return encoder.encode(value);
}

export function byte(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 255) {
    throw new RangeError("byte value must be an integer between 0 and 255");
  }
  return Uint8Array.of(value);
}

export function u32(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new RangeError("u32 value is out of range");
  }
  const result = new Uint8Array(4);
  new DataView(result.buffer).setUint32(0, value, false);
  return result;
}

export function u64(value: number | bigint): Uint8Array {
  const bigintValue = typeof value === "number" ? BigInt(value) : value;
  if (bigintValue < 0n || bigintValue > 0xffff_ffff_ffff_ffffn) {
    throw new RangeError("u64 value is out of range");
  }
  const result = new Uint8Array(8);
  new DataView(result.buffer).setBigUint64(0, bigintValue, false);
  return result;
}

export function hexToBytes(value: HashHex): Uint8Array {
  if (!/^[0-9a-f]{64}$/i.test(value)) {
    throw new Error("expected a 32-byte hexadecimal hash");
  }
  return Uint8Array.from(value.match(/../g)!, (octet) => Number.parseInt(octet, 16));
}

export function bytesToHex(value: Uint8Array): string {
  return Array.from(value, (octet) => octet.toString(16).padStart(2, "0")).join("");
}

export function assertEpoch(epoch: number): void {
  if (!Number.isSafeInteger(epoch) || epoch < 0) {
    throw new RangeError("epoch must be a non-negative safe integer");
  }
}

export function nextPowerOfTwo(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError("value must be a positive safe integer");
  }
  return 2 ** Math.ceil(Math.log2(value));
}

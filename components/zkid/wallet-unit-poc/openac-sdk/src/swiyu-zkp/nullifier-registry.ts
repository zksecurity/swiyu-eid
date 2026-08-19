export interface SwiyuSpentNullifier {
  scopeDigest: Uint8Array;
  nullifier: Uint8Array;
  proofDigest: Uint8Array;
  acceptedAt: Date;
}

export interface SwiyuNullifierRegistry {
  /**
   * Atomically insert a verified nullifier. Returns false when the same
   * `(scopeDigest, nullifier)` is already present.
   *
   * A production implementation must couple this operation to the claim or a
   * transactional outbox. A read followed by a write is not sufficient.
   */
  insertVerifiedClaim(claim: Readonly<SwiyuSpentNullifier>): Promise<boolean>;
}

/** Deterministic test implementation; production uses a database unique key. */
export class InMemorySwiyuNullifierRegistry implements SwiyuNullifierRegistry {
  readonly #spent = new Map<string, SwiyuSpentNullifier>();

  insertVerifiedClaim(claim: Readonly<SwiyuSpentNullifier>): Promise<boolean> {
    const normalized = normalizeClaim(claim);
    const key = `${hex(normalized.scopeDigest)}:${hex(normalized.nullifier)}`;
    // There is no await between the test and insertion, so this operation is
    // atomic with respect to JavaScript jobs, including Promise.all callers.
    if (this.#spent.has(key)) return Promise.resolve(false);
    this.#spent.set(key, normalized);
    return Promise.resolve(true);
  }

  get size(): number {
    return this.#spent.size;
  }
}

function normalizeClaim(claim: Readonly<SwiyuSpentNullifier>): SwiyuSpentNullifier {
  if (!(claim.acceptedAt instanceof Date) || !Number.isFinite(claim.acceptedAt.valueOf())) {
    throw new Error("acceptedAt must be a valid Date");
  }
  return Object.freeze({
    scopeDigest: copy32(claim.scopeDigest, "scope digest"),
    nullifier: copy32(claim.nullifier, "nullifier"),
    proofDigest: copy32(claim.proofDigest, "proof digest"),
    acceptedAt: new Date(claim.acceptedAt),
  });
}

function copy32(value: Uint8Array, label: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new Error(`${label} must contain exactly 32 bytes`);
  }
  return value.slice();
}

function hex(value: Uint8Array): string {
  let output = "";
  for (const byte of value) output += byte.toString(16).padStart(2, "0");
  return output;
}

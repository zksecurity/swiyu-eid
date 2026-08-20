import { describe, expect, it } from "vitest";
import {
  buildSwiyuNullifierIssuerRecord,
  buildSwiyuNullifierPrepareWitness,
  buildSwiyuNullifierShowWitness,
  computeSwiyuNullifierCredentialSeed,
  computeSwiyuNullifierChallengeHash,
  computeSwiyuNullifierScopeDigest,
  computeSwiyuNullifierSecretCommitment,
  computeSwiyuScopedNullifier,
  generateSwiyuNullifierHolderSecret,
  hashSwiyuNullifierIdentifier,
  swiyuNullifierDigestLimbs,
} from "../../src/swiyu-zkp/nullifier.js";
import { InMemorySwiyuNullifierRegistry } from "../../src/swiyu-zkp/nullifier-registry.js";

const bytes = (value: number): Uint8Array => new Uint8Array(32).fill(value);
const credentialBindingHash = swiyuNullifierDigestLimbs(bytes(0x55));
const material = {
  holderSecret: bytes(0x11),
  credentialUid: bytes(0x22),
  credentialBindingHash,
};
const scope = {
  registryNamespaceId: bytes(0x31),
  verifierOriginHash: bytes(0x32),
  programId: bytes(0x33),
  claimTypeId: bytes(0x34),
  epoch: 42n,
  eligibilityPolicyDigest: bytes(0x35),
};

describe("credential-scoped swiyu nullifiers", () => {
  it("is deterministic for one credential and one exact scope", () => {
    const seed = computeSwiyuNullifierCredentialSeed(material);
    const scopeDigest = computeSwiyuNullifierScopeDigest(scope);
    expect(computeSwiyuScopedNullifier(seed, scopeDigest)).toEqual(
      computeSwiyuScopedNullifier(seed, scopeDigest),
    );
  });

  it("separates every verifier-controlled scope dimension", () => {
    const original = computeSwiyuNullifierScopeDigest(scope);
    const variations = [
      { ...scope, registryNamespaceId: bytes(0x41) },
      { ...scope, verifierOriginHash: bytes(0x42) },
      { ...scope, programId: bytes(0x43) },
      { ...scope, claimTypeId: bytes(0x44) },
      { ...scope, epoch: 43n },
      { ...scope, eligibilityPolicyDigest: bytes(0x45) },
    ];
    for (const changed of variations) {
      expect(computeSwiyuNullifierScopeDigest(changed)).not.toEqual(original);
    }
  });

  it("binds the canonical scope into the holder-authorized challenge", () => {
    const firstScope = computeSwiyuNullifierScopeDigest(scope);
    const secondScope = computeSwiyuNullifierScopeDigest({ ...scope, epoch: 43n });
    const first = computeSwiyuNullifierChallengeHash(7n, firstScope);
    expect(first.scalar).toBeGreaterThanOrEqual(0n);
    expect(first.digest).not.toEqual(
      computeSwiyuNullifierChallengeHash(7n, secondScope).digest,
    );
    expect(first.digest).not.toEqual(
      computeSwiyuNullifierChallengeHash(8n, firstScope).digest,
    );
  });

  it("separates credentials even when the holder secret is reused", () => {
    const first = computeSwiyuNullifierCredentialSeed(material);
    const second = computeSwiyuNullifierCredentialSeed({
      ...material,
      credentialUid: bytes(0x23),
    });
    expect(second).not.toEqual(first);
  });

  it("binds the wallet secret through the issuer-signed commitment", () => {
    expect(computeSwiyuNullifierSecretCommitment(bytes(0x11))).not.toEqual(
      computeSwiyuNullifierSecretCommitment(bytes(0x12)),
    );
    const witness = buildSwiyuNullifierPrepareWitness({
      material,
      issuerSigR: 3n,
      issuerSigSInverse: 4n,
    });
    expect(witness.secretCommitment.map(Number)).toEqual([
      ...computeSwiyuNullifierSecretCommitment(material.holderSecret),
    ]);
  });

  it("uses the exact fixed issuer record and two-limb Show context", () => {
    const secretCommitment = computeSwiyuNullifierSecretCommitment(material.holderSecret);
    const record = buildSwiyuNullifierIssuerRecord({
      credentialUid: material.credentialUid,
      secretCommitment,
      credentialBindingHash,
    });
    expect(record).toHaveLength(112);
    expect([...record.slice(0, 16)]).toEqual([
      0, 14, ...new TextEncoder().encode("swy-nf-attr-v1"),
    ]);

    const credentialSeed = computeSwiyuNullifierCredentialSeed(material);
    const scopeDigest = computeSwiyuNullifierScopeDigest(scope);
    const show = buildSwiyuNullifierShowWitness({ credentialSeed, scopeDigest });
    expect(show.expectedNullifierHi).toBeGreaterThanOrEqual(0n);
    expect(show.expectedNullifierLo).toBeGreaterThanOrEqual(0n);
    expect(show.expectedNullifierHi).toBeLessThan(1n << 128n);
    expect(show.expectedNullifierLo).toBeLessThan(1n << 128n);
  });

  it("prevents mixing a nullifier attestation with different age credential rows", () => {
    const secretCommitment = computeSwiyuNullifierSecretCommitment(material.holderSecret);
    const changedBinding = swiyuNullifierDigestLimbs(bytes(0x56));
    const originalRecord = buildSwiyuNullifierIssuerRecord({
      credentialUid: material.credentialUid,
      secretCommitment,
      credentialBindingHash,
    });
    const changedRecord = buildSwiyuNullifierIssuerRecord({
      credentialUid: material.credentialUid,
      secretCommitment,
      credentialBindingHash: changedBinding,
    });
    expect(changedRecord).not.toEqual(originalRecord);
    expect(computeSwiyuNullifierCredentialSeed({
      ...material,
      credentialBindingHash: changedBinding,
    })).not.toEqual(computeSwiyuNullifierCredentialSeed(material));
  });

  it("rejects malformed lengths, limb aliases, and epochs", () => {
    expect(() => computeSwiyuNullifierSecretCommitment(new Uint8Array(31))).toThrow(
      "exactly 32 bytes",
    );
    expect(() => computeSwiyuNullifierCredentialSeed({
      ...material,
      credentialBindingHash: { hashHi: 1n << 128n, hashLo: 0n },
    })).toThrow("128-bit");
    expect(() => computeSwiyuNullifierScopeDigest({ ...scope, epoch: -1n })).toThrow(
      "unsigned 64-bit",
    );
    expect(() => computeSwiyuNullifierScopeDigest({ ...scope, epoch: 1n << 64n })).toThrow(
      "unsigned 64-bit",
    );
    expect(() => computeSwiyuNullifierSecretCommitment(new Uint8Array(32))).toThrow(
      "must not be all zero",
    );
  });

  it("generates a non-zero 32-byte holder secret from a CSPRNG source", () => {
    const generated = generateSwiyuNullifierHolderSecret({
      getRandomValues(array) {
        (array as Uint8Array).fill(0x5a);
        return array;
      },
    });
    expect(generated).toEqual(new Uint8Array(32).fill(0x5a));
  });

  it("hashes configured identifiers with labels and canonical length prefixes", () => {
    expect(hashSwiyuNullifierIdentifier("benefit-2026", "program")).toHaveLength(32);
    expect(hashSwiyuNullifierIdentifier("benefit-2026", "program")).toEqual(
      hashSwiyuNullifierIdentifier("benefit-2026", "program"),
    );
    expect(() => hashSwiyuNullifierIdentifier("", "program")).toThrow("non-empty");
  });
});

describe("spent-nullifier registry semantics", () => {
  it("accepts exactly one of concurrent claims for the same scope", async () => {
    const registry = new InMemorySwiyuNullifierRegistry();
    const scopeDigest = computeSwiyuNullifierScopeDigest(scope);
    const credentialSeed = computeSwiyuNullifierCredentialSeed(material);
    const nullifier = computeSwiyuScopedNullifier(credentialSeed, scopeDigest);
    const claim = {
      scopeDigest,
      nullifier,
      proofDigest: bytes(0x77),
      acceptedAt: new Date("2026-08-17T00:00:00Z"),
    };
    const outcomes = await Promise.all(
      Array.from({ length: 32 }, () => registry.insertVerifiedClaim(claim)),
    );
    expect(outcomes.filter(Boolean)).toHaveLength(1);
    expect(registry.size).toBe(1);
  });

  it("allows the same credential in a genuinely different scope", async () => {
    const registry = new InMemorySwiyuNullifierRegistry();
    const seed = computeSwiyuNullifierCredentialSeed(material);
    const firstScope = computeSwiyuNullifierScopeDigest(scope);
    const secondScope = computeSwiyuNullifierScopeDigest({ ...scope, epoch: 43n });
    const base = { proofDigest: bytes(0x70), acceptedAt: new Date() };
    await expect(registry.insertVerifiedClaim({
      ...base,
      scopeDigest: firstScope,
      nullifier: computeSwiyuScopedNullifier(seed, firstScope),
    })).resolves.toBe(true);
    await expect(registry.insertVerifiedClaim({
      ...base,
      scopeDigest: secondScope,
      nullifier: computeSwiyuScopedNullifier(seed, secondScope),
    })).resolves.toBe(true);
  });
});

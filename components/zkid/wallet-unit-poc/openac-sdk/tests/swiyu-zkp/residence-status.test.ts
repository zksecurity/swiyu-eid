import { deflateSync, inflateSync } from "node:zlib";
import { describe, expect, it } from "vitest";

import {
  resolveSwiyuPackedStatusListJwt,
  resolveSwiyuTernaryStatusListJwt,
  SwiyuResidenceVerifierStatus,
} from "../../src/swiyu-zkp/residence-status.js";
import { SWIYU_BENCHMARK_RESIDENCE_STATUS } from "../../src/swiyu-zkp/residence-benchmark-manifest.js";
import { swiyuResidenceShowPublicValues } from "../../src/swiyu-zkp/residence-split.js";
import {
  computeSwiyuPreparedStatusCommitment,
  computeSwiyuPreparedStatusUriCommitment,
} from "../../src/swiyu-zkp/commitments.js";
import { littleEndian32ToBigint } from "../../src/swiyu-zkp/encoding.js";
import { base64urlEncode } from "../../src/utils.js";
import {
  CHECKED_IN_DID_TDW_KID,
  ISSUER_PRIVATE_KEY,
  publicJwk,
  signJwt,
} from "./fixture.js";

const ISSUER = "did:example:issuer";
const SUBJECT = "https://status.example.ch/lists/2026-07";
const VCT = "urn:ch:swiyu-lab:residence-eligibility:v1";
const IAT = 1_750_000_000;

describe("authenticated ternary residence status resolver", () => {
  it("derives the packed v2 root from the same authenticated bytes without expansion", () => {
    const jwt = makeStatusListJwt();
    const legacy = resolve(jwt, 0, BigInt(IAT + 30));
    const packed = resolvePacked(jwt, 0, BigInt(IAT + 30));
    expect(packed.tree.depth).toBe(6);
    expect(packed.statusWitness).toMatchObject({
      design: "packed-status-chunk-ternary-merkle-v2",
      index: 0,
      status: 0,
      entryCount: 8,
      epoch: IAT,
      root: packed.privateSnapshot.root,
    });
    expect(packed.statusWitness.chunk).toHaveLength(64);
    expect(packed.statusWitness.chunk.slice(0, 2)).toEqual([0xe4, 0x1b]);
    expect(packed.statusWitness.chunk.slice(2)).toEqual(Array(62).fill(0));
    expect(packed.statusWitness.siblings).toHaveLength(6);
    expect(packed.privateSnapshot.root).not.toBe(legacy.privateSnapshot.root);
    expect(packed.verifierStatus.treeProfile)
      .toBe("packed-status-chunk-ternary-merkle-v2");
    expect(() => resolvePacked(jwt, 1, BigInt(IAT + 30))).toThrow("not valid");
  });

  it("derives the ternary root directly and exposes only a prepared commitment", () => {
    const resolved = resolve(makeStatusListJwt(), 0, BigInt(IAT + 30));
    expect(resolved.tree.depth).toBe(11);
    expect(resolved.statusWitness).toMatchObject({
      design: "fixed-index-status-ternary-merkle-v1",
      index: 0,
      status: 0,
      entryCount: 8,
      epoch: IAT,
      root: resolved.privateSnapshot.root,
    });
    expect(resolved.statusWitness.siblings).toHaveLength(11);
    expect(resolved.verifierStatus).toBeInstanceOf(SwiyuResidenceVerifierStatus);
    expect(resolved.verifierStatus.preparedStatusCommitment).toEqual(
      computeSwiyuPreparedStatusCommitment(
        computeSwiyuPreparedStatusUriCommitment(SUBJECT),
        resolved.privateSnapshot.root,
      ),
    );
    expect(resolved.verifierStatus).not.toHaveProperty("uri");
    expect(resolved.verifierStatus).not.toHaveProperty("root");
    expect(resolved.verifierStatus).not.toHaveProperty("statusIndex");
    expect(Object.isFrozen(resolved.statusWitness.siblings)).toBe(true);
  });

  it("feeds the residence adapter without accepting caller-supplied URI/root", () => {
    const resolved = resolvePacked(makeStatusListJwt(), 0, BigInt(IAT + 30));
    const values = swiyuResidenceShowPublicValues({
      baseChallengeHash: 7n,
      currentTime: BigInt(IAT + 30),
      acceptedLookup: {
        issuer: ISSUER,
        kid: CHECKED_IN_DID_TDW_KID,
        vct: VCT,
      },
      trustedStatus: resolved.verifierStatus,
      allowedMunicipalityBfs: [261, 351],
      minimumResidenceDays: 365,
      municipalityDirectoryAsOf: "2025-01-01",
      municipalityDirectorySha256: "11".repeat(32),
    }).map(littleEndian32ToBigint);
    expect(values.slice(-2)).toEqual([
      resolved.verifierStatus.preparedStatusCommitment.hashHi,
      resolved.verifierStatus.preparedStatusCommitment.hashLo,
    ]);
  });

  it("rejects signature tampering and both freshness boundaries", () => {
    const jwt = makeStatusListJwt();
    const parts = jwt.split(".") as [string, string, string];
    const replacement = parts[2][0] === "A" ? "B" : "A";
    expect(() => resolve(
      `${parts[0]}.${parts[1]}.${replacement}${parts[2].slice(1)}`,
      0,
      BigInt(IAT + 1),
    )).toThrow("signature");
    expect(() => resolve(jwt, 0, BigInt(IAT - 1))).toThrow("not yet valid");
    expect(() => resolve(jwt, 0, BigInt(IAT + 60))).toThrow("stale");
  });

  it("binds the authenticated credential index and requires VALID status", () => {
    const jwt = makeStatusListJwt();
    expect(() => resolve(jwt, 8, BigInt(IAT + 1))).toThrow("outside");
    expect(() => resolve(jwt, 1, BigInt(IAT + 1))).toThrow("not valid");
    expect(() => resolve(jwt, 4, BigInt(IAT + 1))).toThrow("not valid");
    expect(() => resolve(jwt, 7, BigInt(IAT + 1))).not.toThrow();
  });

  it("matches the native residence benchmark's authenticated 65,536-entry root", () => {
    const status = SWIYU_BENCHMARK_RESIDENCE_STATUS;
    const resolved = resolve(
      makeStatusListJwt({
        packed: new Uint8Array(status.listLength / 4),
        iat: status.epoch,
        exp: status.epoch + 600,
        ttl: 300,
      }),
      42,
      BigInt(status.epoch + 30),
    );
    expect(resolved.verifierStatus).toMatchObject({
      epoch: status.epoch,
      listLength: status.listLength,
    });
    expect(resolved.privateSnapshot.root).toBe(status.snapshotRoot);
    const packed = resolvePacked(
      makeStatusListJwt({
        packed: new Uint8Array(status.listLength / 4),
        iat: status.epoch,
        exp: status.epoch + 600,
        ttl: 300,
      }),
      42,
      BigInt(status.epoch + 30),
    );
    expect(packed.privateSnapshot.root).toBe(status.packedV2.snapshotRoot);
  }, 30_000);

  it("rejects objects forged through the erased TypeScript class boundary", () => {
    const forged = Object.assign(
      Object.create(SwiyuResidenceVerifierStatus.prototype),
      {
        preparedStatusCommitment: { hashHi: 1n, hashLo: 2n },
        issuer: ISSUER,
        epoch: IAT,
        validBefore: BigInt(IAT + 60),
        listLength: 8,
      },
    ) as SwiyuResidenceVerifierStatus;
    expect(() => swiyuResidenceShowPublicValues({
      baseChallengeHash: 7n,
      currentTime: BigInt(IAT + 30),
      acceptedLookup: { issuer: ISSUER, kid: CHECKED_IN_DID_TDW_KID, vct: VCT },
      trustedStatus: forged,
      allowedMunicipalityBfs: [261, 351],
      minimumResidenceDays: 365,
      municipalityDirectoryAsOf: "2025-01-01",
      municipalityDirectorySha256: "11".repeat(32),
    })).toThrow("authenticated ternary status-list");
    expect(() => Reflect.construct(SwiyuResidenceVerifierStatus, [
      Symbol("forged"), { hashHi: 1n, hashLo: 2n }, "id", ISSUER,
      CHECKED_IN_DID_TDW_KID, IAT, 8, BigInt(IAT + 60), "forged",
    ])).toThrow("authenticated resolver");
  });
});

function resolve(compactJwt: string, credentialStatusIndex: number, currentTime: bigint) {
  return resolveSwiyuTernaryStatusListJwt({
    compactJwt,
    issuerPublicKey: publicJwk(ISSUER_PRIVATE_KEY, CHECKED_IN_DID_TDW_KID),
    expectedIssuer: ISSUER,
    expectedSubject: SUBJECT,
    credentialStatusIndex,
    currentTime,
    inflateZlib(compressed, maxOutputBytes) {
      return new Uint8Array(inflateSync(compressed, { maxOutputLength: maxOutputBytes }));
    },
  });
}

function resolvePacked(
  compactJwt: string,
  credentialStatusIndex: number,
  currentTime: bigint,
) {
  return resolveSwiyuPackedStatusListJwt({
    compactJwt,
    issuerPublicKey: publicJwk(ISSUER_PRIVATE_KEY, CHECKED_IN_DID_TDW_KID),
    expectedIssuer: ISSUER,
    expectedSubject: SUBJECT,
    credentialStatusIndex,
    currentTime,
    inflateZlib(compressed, maxOutputBytes) {
      return new Uint8Array(inflateSync(compressed, { maxOutputLength: maxOutputBytes }));
    },
  });
}

function makeStatusListJwt(options: Readonly<{
  packed?: Uint8Array;
  iat?: number;
  exp?: number;
  ttl?: number;
}> = {}): string {
  const iat = options.iat ?? IAT;
  const header = {
    alg: "ES256",
    kid: CHECKED_IN_DID_TDW_KID,
    typ: "statuslist+jwt",
    profile_version: "swiss-profile-vc:1.0.0",
  };
  // LSB-first statuses: [VALID, 1, 2, 3, 3, 2, 1, VALID].
  const packed = options.packed ?? new Uint8Array([0xe4, 0x1b]);
  const payload = {
    ttl: options.ttl ?? 60,
    exp: options.exp ?? iat + 1_000,
    sub: SUBJECT,
    iss: ISSUER,
    iat,
    status_list: {
      bits: 2,
      lst: base64urlEncode(new Uint8Array(deflateSync(packed, { level: 9 }))),
    },
  };
  return signJwt(JSON.stringify(header), JSON.stringify(payload));
}

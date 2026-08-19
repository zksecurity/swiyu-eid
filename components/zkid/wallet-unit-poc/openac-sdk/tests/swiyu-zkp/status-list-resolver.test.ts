import { deflateSync, inflateSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import {
  computeSwiyuStatusProfileCommitment,
  prepareSwiyuCredential,
  provisionSwiyuCredentialStatus,
  resolveSwiyuStatusListJwt,
} from "../../src/index.js";
import { base64urlEncode } from "../../src/utils.js";
import {
  CHECKED_IN_DID_TDW_KID,
  ISSUER_PRIVATE_KEY,
  buildCredentialFixture,
  publicJwk,
  signJwt,
} from "./fixture.js";

const ISSUER = "did:example:issuer";
const SUBJECT = "https://status.example.ch/lists/2026-07";
const IAT = 1_750_000_000;

describe("Swiss statuslist+jwt resolver", () => {
  it("verifies a golden issuer-shaped token and derives its fixed-depth tree", () => {
    const compactJwt = makeStatusListJwt();
    const resolved = resolve(compactJwt, BigInt(IAT + 30));

    expect(resolved.privateSnapshot).toEqual({
      id: expect.stringMatching(/^statuslist-jwt:[A-Za-z0-9_-]{43}$/),
      uri: SUBJECT,
      root: resolved.tree.root,
      epoch: IAT,
      listLength: 8,
    });
    expect(resolved.authoritativeSnapshot).toEqual({
      id: resolved.privateSnapshot.id,
      issuer: ISSUER,
      kid: CHECKED_IN_DID_TDW_KID,
      subject: SUBJECT,
      commitment: computeSwiyuStatusProfileCommitment(resolved.privateSnapshot),
      epoch: IAT,
      listLength: 8,
      validBefore: BigInt(IAT + 60),
      provenance: expect.stringMatching(
        /^statuslist\+jwt#sha256:[A-Za-z0-9_-]{43}$/,
      ),
    });
    expect(resolved.authoritativeSnapshot).not.toHaveProperty("uri");
    expect(resolved.authoritativeSnapshot).not.toHaveProperty("root");
    expect(resolved.tree.depth).toBe(17);
    expect(
      Array.from({ length: 8 }, (_, index) => resolved.tree.witness(index).status),
    ).toEqual([0, 1, 2, 3, 3, 2, 1, 0]);
  });

  it("provisions the exact private witness selected by the signed credential index", () => {
    const credential = buildCredentialFixture({ statusIndex: 7 });
    const prepared = prepareSwiyuCredential({
      compactSdJwt: credential.compactSdJwt,
      issuerPublicKey: credential.issuerPublicKey,
    });
    const provisioned = provisionSwiyuCredentialStatus({
      prepared,
      compactStatusListJwt: makeStatusListJwt(),
      statusListIssuerPublicKey: publicJwk(
        ISSUER_PRIVATE_KEY,
        CHECKED_IN_DID_TDW_KID,
      ),
      currentTime: BigInt(IAT + 30),
      inflateZlib(compressed, maxOutputBytes) {
        return new Uint8Array(
          inflateSync(compressed, { maxOutputLength: maxOutputBytes }),
        );
      },
    });

    expect(provisioned.statusSnapshot.uri).toBe(credential.statusUri);
    expect(provisioned.statusWitness).toMatchObject({
      index: 7,
      status: 0,
      entryCount: 8,
      epoch: IAT,
      root: provisioned.statusSnapshot.root,
    });
    expect(provisioned.statusWitness.siblings).toHaveLength(17);
    expect(Object.isFrozen(provisioned.statusWitness.siblings)).toBe(true);
  });

  it("treats both signed exp and iat + ttl as exclusive freshness boundaries", () => {
    const ttlBound = makeStatusListJwt({ ttl: 60, exp: IAT + 1_000 });
    expect(() => resolve(ttlBound, BigInt(IAT + 60))).toThrow(/stale/);

    const expBound = makeStatusListJwt({ ttl: 1_000, exp: IAT + 45 });
    expect(() => resolve(expBound, BigInt(IAT + 45))).toThrow(/stale/);
    expect(() => resolve(expBound, BigInt(IAT + 44))).not.toThrow();
  });

  it("rejects non-2-bit lists before deriving a root", () => {
    expect(() =>
      resolve(makeStatusListJwt({ bits: 1 }), BigInt(IAT + 1)),
    ).toThrow(/bits must equal 2/);
  });

  it("rejects a tampered issuer signature", () => {
    const compactJwt = makeStatusListJwt();
    const parts = compactJwt.split(".") as [string, string, string];
    const replacement = parts[2][0] === "A" ? "B" : "A";
    const tampered = `${parts[0]}.${parts[1]}.${replacement}${parts[2].slice(1)}`;
    expect(() => resolve(tampered, BigInt(IAT + 1))).toThrow(/signature/);
  });

  it("enforces protected alg, typ, kid, and profile_version", () => {
    for (const [field, value, expected] of [
      ["alg", "ES384", /alg must equal ES256/],
      ["typ", "JWT", /typ must equal statuslist\+jwt/],
      ["kid", `${CHECKED_IN_DID_TDW_KID}x`, /exact protected kid/],
      ["profile_version", "swiss-profile-vc:9.9.9", /profile_version must equal/],
    ] as const) {
      const compactJwt = makeStatusListJwt({ headerOverride: { [field]: value } });
      expect(() => resolve(compactJwt, BigInt(IAT + 1))).toThrow(expected);
    }
  });

  it("rejects decompression output beyond the fixed depth-17 capacity", () => {
    const compactJwt = makeStatusListJwt();
    expect(() =>
      resolveSwiyuStatusListJwt({
        compactJwt,
        issuerPublicKey: publicJwk(ISSUER_PRIVATE_KEY, CHECKED_IN_DID_TDW_KID),
        expectedIssuer: ISSUER,
        expectedSubject: SUBJECT,
        currentTime: BigInt(IAT + 1),
        inflateZlib() {
          return new Uint8Array(32_769);
        },
      }),
    ).toThrow(/1\.\.32768 bytes/);
  });
});

function resolve(compactJwt: string, currentTime: bigint) {
  return resolveSwiyuStatusListJwt({
    compactJwt,
    issuerPublicKey: publicJwk(ISSUER_PRIVATE_KEY, CHECKED_IN_DID_TDW_KID),
    expectedIssuer: ISSUER,
    expectedSubject: SUBJECT,
    currentTime,
    inflateZlib(compressed, maxOutputBytes) {
      return new Uint8Array(
        inflateSync(compressed, { maxOutputLength: maxOutputBytes }),
      );
    },
  });
}

interface StatusListFixtureOptions {
  bits?: number;
  ttl?: number;
  exp?: number;
  headerOverride?: Record<string, string>;
}

function makeStatusListJwt(options: StatusListFixtureOptions = {}): string {
  const header = {
    alg: "ES256",
    kid: CHECKED_IN_DID_TDW_KID,
    typ: "statuslist+jwt",
    profile_version: "swiss-profile-vc:1.0.0",
    ...options.headerOverride,
  };
  // LSB-first 2-bit entries: [0,1,2,3] and [3,2,1,0].
  const packed = new Uint8Array([0xe4, 0x1b]);
  const payload = {
    ttl: options.ttl ?? 60,
    exp: options.exp ?? IAT + 1_000,
    sub: SUBJECT,
    iss: ISSUER,
    iat: IAT,
    status_list: {
      bits: options.bits ?? 2,
      lst: base64urlEncode(new Uint8Array(deflateSync(packed, { level: 9 }))),
    },
  };
  return signJwt(JSON.stringify(header), JSON.stringify(payload));
}

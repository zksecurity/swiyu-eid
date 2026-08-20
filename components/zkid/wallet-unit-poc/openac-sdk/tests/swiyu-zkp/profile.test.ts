import { describe, expect, it } from "vitest";
import { sha256 } from "@noble/hashes/sha2";
import {
  Credential,
  SWIYU_AGE18_STATUS_CIRCUIT,
  SWIYU_AGE18_STATUS_PROFILE,
  SWIYU_MAX_B64_HEADER_BYTES,
  SWIYU_MAX_B64_PAYLOAD_BYTES,
  SWIYU_MAX_STATUS_LIST_LENGTH,
  SWIYU_MESSAGE_BYTES,
  SWIYU_CIRCUIT_FIELD,
  SWIYU_P256_BASE_FIELD,
  SWIYU_P256_SCALAR_ORDER,
  SWIYU_PROFILE_VERSION,
  SWIYU_STRING_SLOT_BYTES,
  SWIYU_STATUS_DEPTH,
  SwiyuZkpVerifier,
  SwiyuZkpWallet,
  computeSwiyuMetadataCommitment,
  computeSwiyuStatusProfileCommitment,
  encodeSwiyuChallenge,
  hashSwiyuChallenge,
  parseSwiyuCompactSdJwt,
  parseSwiyuIsoDate,
  validatePrivateStatusSnapshot,
  base64Decode,
} from "../../src/index.js";
import { base64urlEncode } from "../../src/utils.js";
import { assertFieldElement } from "../../src/swiyu-zkp/encoding.js";
import {
  BindingTestBackend,
  CHECKED_IN_DID_TDW_KID,
  HOLDER_PRIVATE_KEY,
  RecordingWitnessGenerator,
  buildCredentialFixture,
  holderSigner,
  makeChallenge,
  makeStatus,
  signJwt,
} from "./fixture.js";
describe("swiyu-age18-status-2k-v0 wallet profile", () => {
  function setup() {
    const witnessGenerator = new RecordingWitnessGenerator();
    const backend = new BindingTestBackend(witnessGenerator);
    return {
      witnessGenerator,
      backend,
      wallet: new SwiyuZkpWallet({ witnessGenerator, proofBackend: backend }),
      verifier: new SwiyuZkpVerifier(backend),
    };
  }

  it("prepares once and emits one challenge-bound proof with no raw private fields", async () => {
    expect(SWIYU_AGE18_STATUS_PROFILE).toBe("swiyu-age18-status-2k-v0");
    expect(SWIYU_AGE18_STATUS_CIRCUIT).toBe("swiyu_age18_status_2k");
    expect(SWIYU_STATUS_DEPTH).toBe(17);
    const fixture = buildCredentialFixture();
    const { snapshot, authoritativeSnapshot, witness } = makeStatus();
    const challenge = makeChallenge(snapshot.id);
    const { wallet, verifier, witnessGenerator } = setup();
    const prepared = wallet.prepare({
      compactSdJwt: fixture.compactSdJwt,
      issuerPublicKey: fixture.issuerPublicKey,
    });
    expect(prepared.profile).toBe(SWIYU_AGE18_STATUS_PROFILE);
    expect(prepared.circuitId).toBe(SWIYU_AGE18_STATUS_CIRCUIT);

    const envelope = await wallet.show({
      prepared,
      challenge,
      holderSigner: holderSigner(),
      statusSnapshot: snapshot,
      statusWitness: witness,
      provingKey: new Uint8Array([1]),
    });
    expect(base64Decode(envelope.proof)).toHaveLength(10 * 32);
    expect(witnessGenerator.inputs?.statusSiblings).toHaveLength(
      SWIYU_STATUS_DEPTH,
    );
    expect(witnessGenerator.inputs?.statusValue).toBe(0);

    const serialized = JSON.stringify(envelope);
    for (const privateValue of [
      "2000-02-29",
      fixture.disclosure,
      fixture.holderPublicKey.x,
      fixture.holderPublicKey.y,
      fixture.statusUri,
    ]) {
      expect(serialized).not.toContain(privateValue);
    }
    expect(serialized).not.toContain("statusIndex");
    expect(serialized).not.toContain("statusSiblings");
    expect(envelope.lookup).not.toHaveProperty("statusListSnapshot");
    expect(envelope.lookup).not.toHaveProperty("nbf");
    expect(envelope.lookup).not.toHaveProperty("exp");
    expect(authoritativeSnapshot).not.toHaveProperty("uri");
    expect(authoritativeSnapshot).not.toHaveProperty("root");

    await expect(
      verifier.verify({
        envelope,
        challenge,
        issuerPublicKey: fixture.issuerPublicKey,
        statusSnapshot: authoritativeSnapshot,
        verifyingKey: new Uint8Array([2]),
      }),
    ).resolves.toEqual({ valid: true });

    await expect(
      verifier.verify({
        envelope,
        challenge,
        issuerPublicKey: fixture.issuerPublicKey,
        statusSnapshot: {
          ...authoritativeSnapshot,
          validBefore: challenge.currentTime,
        },
        verifyingKey: new Uint8Array([2]),
      }),
    ).resolves.toEqual({
      valid: false,
      error: "authoritative status snapshot is stale at current_time",
    });
  });

  it("rejects the same proof under a different fresh challenge", async () => {
    const fixture = buildCredentialFixture();
    const { snapshot, authoritativeSnapshot, witness } = makeStatus();
    const challenge = makeChallenge(snapshot.id);
    const { wallet, verifier } = setup();
    const envelope = await wallet.show({
      prepared: wallet.prepare({
        compactSdJwt: fixture.compactSdJwt,
        issuerPublicKey: fixture.issuerPublicKey,
      }),
      challenge,
      holderSigner: holderSigner(),
      statusSnapshot: snapshot,
      statusWitness: witness,
      provingKey: new Uint8Array([1]),
    });
    const wrongChallenge = { ...challenge, nonce: "different-nonce" };
    const result = await verifier.verify({
      envelope,
      challenge: wrongChallenge,
      issuerPublicKey: fixture.issuerPublicKey,
      statusSnapshot: authoritativeSnapshot,
      verifyingKey: new Uint8Array([2]),
    });
    expect(result.valid).toBe(false);
    expect(result.error).toContain("context mismatch");
  });

  it("rejects runtime challenge type coercions before hashing", () => {
    const challenge = makeChallenge();
    expect(() =>
      encodeSwiyuChallenge({ ...challenge, nonce: 7 as never }),
    ).toThrow(/nonce must be a string/);
    expect(() =>
      encodeSwiyuChallenge({ ...challenge, currentTime: 1 as never }),
    ).toThrow(/current_time must be a bigint/);
  });

  it("fails closed on malformed proof transport and proof-bound lookup tampering", async () => {
    const fixture = buildCredentialFixture();
    const { snapshot, authoritativeSnapshot, witness } = makeStatus();
    const challenge = makeChallenge(snapshot.id);
    const { wallet, verifier } = setup();
    const envelope = await wallet.show({
      prepared: wallet.prepare({
        compactSdJwt: fixture.compactSdJwt,
        issuerPublicKey: fixture.issuerPublicKey,
      }),
      challenge,
      holderSigner: holderSigner(),
      statusSnapshot: snapshot,
      statusWitness: witness,
      provingKey: new Uint8Array([1]),
    });

    const malformed = await verifier.verify({
      envelope: { ...envelope, proof: "not+base64url" },
      challenge,
      issuerPublicKey: fixture.issuerPublicKey,
      statusSnapshot: authoritativeSnapshot,
      verifyingKey: new Uint8Array([2]),
    });
    expect(malformed.valid).toBe(false);
    expect(malformed.error).toContain("base64url");

    const tampered = await verifier.verify({
      envelope: {
        ...envelope,
        lookup: { ...envelope.lookup, issuer: "did:example:attacker" },
      },
      challenge,
      issuerPublicKey: fixture.issuerPublicKey,
      statusSnapshot: authoritativeSnapshot,
      verifyingKey: new Uint8Array([2]),
    });
    expect(tampered.valid).toBe(false);
    expect(tampered.error).toContain("context mismatch");
  });

  it("rejects swapped or conflated semantic profile and artifact ids", async () => {
    const fixture = buildCredentialFixture();
    const { snapshot, authoritativeSnapshot, witness } = makeStatus();
    const challenge = makeChallenge(snapshot.id);
    const { wallet, verifier } = setup();
    const envelope = await wallet.show({
      prepared: wallet.prepare({
        compactSdJwt: fixture.compactSdJwt,
        issuerPublicKey: fixture.issuerPublicKey,
      }),
      challenge,
      holderSigner: holderSigner(),
      statusSnapshot: snapshot,
      statusWitness: witness,
      provingKey: new Uint8Array([1]),
    });

    for (const wrongEnvelope of [
      {
        ...envelope,
        profile: SWIYU_AGE18_STATUS_CIRCUIT,
      },
      {
        ...envelope,
        circuitId: SWIYU_AGE18_STATUS_PROFILE,
      },
    ]) {
      await expect(
        verifier.verify({
          envelope: wrongEnvelope as never,
          challenge,
          issuerPublicKey: fixture.issuerPublicKey,
          statusSnapshot: authoritativeSnapshot,
          verifyingKey: new Uint8Array([2]),
        }),
      ).resolves.toEqual({
        valid: false,
        error: "proof envelope profile, circuit, or version is unsupported",
      });
    }
  });

  it("rejects an issuer signature changed after issuance", () => {
    const fixture = buildCredentialFixture();
    const parts = fixture.jwt.split(".");
    const signature = parts[2]!;
    const replacement = signature.endsWith("A") ? "B" : "A";
    const tampered = `${parts[0]}.${parts[1]}.${signature.slice(0, -1)}${replacement}~${fixture.disclosure}~`;
    expect(() =>
      parseSwiyuCompactSdJwt(tampered, fixture.issuerPublicKey),
    ).toThrow(/signature/i);
  });

  it("rejects duplicate security fields even when the malformed token is correctly signed", () => {
    const fixture = buildCredentialFixture({
      payloadJson(canonical) {
        return canonical.replace(
          '{"iss":"did:example:issuer",',
          '{"iss":"did:example:issuer","iss":"did:example:attacker",',
        );
      },
    });
    expect(() =>
      parseSwiyuCompactSdJwt(fixture.compactSdJwt, fixture.issuerPublicKey),
    ).toThrow(/Duplicate JSON key "iss"/);
  });

  it("requires the exact unique Swiss profile version and accepts the checked-in 99-byte did:tdw kid", () => {
    expect(CHECKED_IN_DID_TDW_KID).toHaveLength(99);
    expect(SWIYU_STRING_SLOT_BYTES).toBe(112);
    expect(SWIYU_PROFILE_VERSION).toBe("swiss-profile-vc:1.0.0");
    const fixture = buildCredentialFixture();
    const parsed = parseSwiyuCompactSdJwt(
      fixture.compactSdJwt,
      fixture.issuerPublicKey,
    );
    expect(parsed.lookup.kid).toBe(CHECKED_IN_DID_TDW_KID);
    expect(parsed.baseInputs.kid).toHaveLength(SWIYU_STRING_SLOT_BYTES);

    const missing = buildCredentialFixture({
      headerJson(canonical) {
        return canonical.replace(
          `,"profile_version":"${SWIYU_PROFILE_VERSION}"`,
          "",
        );
      },
    });
    expect(() =>
      parseSwiyuCompactSdJwt(missing.compactSdJwt, missing.issuerPublicKey),
    ).toThrow(/profile_version.*required/);

    const wrong = buildCredentialFixture({
      headerJson(canonical) {
        return canonical.replace(SWIYU_PROFILE_VERSION, "swiss-profile-vc:9.9.9");
      },
    });
    expect(() =>
      parseSwiyuCompactSdJwt(wrong.compactSdJwt, wrong.issuerPublicKey),
    ).toThrow(/profile_version must equal/);

    const duplicate = buildCredentialFixture({
      issuerKid: "did:example:issuer#key-1",
      headerJson(canonical) {
        return canonical.replace(
          '"profile_version":',
          `"profile_version":"${SWIYU_PROFILE_VERSION}","profile_version":`,
        );
      },
    });
    expect(() =>
      parseSwiyuCompactSdJwt(duplicate.compactSdJwt, duplicate.issuerPublicKey),
    ).toThrow(/Duplicate JSON key "profile_version"/);
  });

  it("separates the P-256 base field from its scalar order at both boundaries", () => {
    expect(SWIYU_P256_SCALAR_ORDER).toBeLessThan(SWIYU_P256_BASE_FIELD);
    expect(SWIYU_CIRCUIT_FIELD).toBe(SWIYU_P256_BASE_FIELD);
    expect(() => assertFieldElement(SWIYU_P256_SCALAR_ORDER, "q")).not.toThrow();
    expect(() => assertFieldElement(SWIYU_P256_BASE_FIELD - 1n, "p-1")).not.toThrow();
    expect(() => assertFieldElement(SWIYU_P256_BASE_FIELD, "p")).toThrow(
      /outside.*circuit field/,
    );
    expect(() => assertFieldElement(-1n, "negative")).toThrow(
      /outside.*circuit field/,
    );
  });

  it("uses the full 112-byte issuer and credential-type slots", () => {
    const issuer = "i".repeat(SWIYU_STRING_SLOT_BYTES);
    const vct = "v".repeat(SWIYU_STRING_SLOT_BYTES);
    const fixture = buildCredentialFixture({
      payloadJson(canonical) {
        return canonical
          .replace("did:example:issuer", issuer)
          .replace("https://example.ch/vct/person", vct);
      },
    });
    const parsed = parseSwiyuCompactSdJwt(
      fixture.compactSdJwt,
      fixture.issuerPublicKey,
    );
    expect(parsed.lookup.issuer).toBe(issuer);
    expect(parsed.lookup.vct).toBe(vct);
    expect(parsed.baseInputs.iss).toHaveLength(SWIYU_STRING_SLOT_BYTES);
    expect(parsed.baseInputs.vct).toHaveLength(SWIYU_STRING_SLOT_BYTES);

    const overflow = buildCredentialFixture({
      payloadJson(canonical) {
        return canonical.replace(
          "did:example:issuer",
          "i".repeat(SWIYU_STRING_SLOT_BYTES + 1),
        );
      },
    });
    expect(() =>
      parseSwiyuCompactSdJwt(overflow.compactSdJwt, overflow.issuerPublicKey),
    ).toThrow(/payload\.iss length must be in 1\.\.112/);
  });

  it("rejects unsupported unencoded-payload signaling even when correctly signed", () => {
    const fixture = buildCredentialFixture({
      issuerKid: "did:example:issuer#key-1",
      headerJson(canonical) {
        return canonical.replace('{"alg":"ES256",', '{"alg":"ES256","b64":false,');
      },
    });
    expect(() =>
      parseSwiyuCompactSdJwt(fixture.compactSdJwt, fixture.issuerPublicKey),
    ).toThrow(/header\.b64 is forbidden/);
  });

  it("rejects a correctly signed cleartext birthdate beside the selective disclosure", () => {
    const fixture = buildCredentialFixture({
      payloadJson(canonical) {
        return canonical.replace(
          '{"iss":"did:example:issuer",',
          '{"birthdate":"2012-01-01","iss":"did:example:issuer",',
        );
      },
    });
    expect(() =>
      parseSwiyuCompactSdJwt(fixture.compactSdJwt, fixture.issuerPublicKey),
    ).toThrow(/payload\.birthdate is forbidden/);
  });

  it("rejects JSON escapes even in unrelated fixed-profile payload values", () => {
    const fixture = buildCredentialFixture({
      payloadJson(canonical) {
        return canonical.replace(
          '{"iss":',
          '{"display_extension":"Zo\\u00eb","iss":',
        );
      },
    });
    expect(() =>
      parseSwiyuCompactSdJwt(fixture.compactSdJwt, fixture.issuerPublicKey),
    ).toThrow(/JSON strings must not use escapes/);
  });

  it("requires the resolved issuer key to carry the exact protected kid", async () => {
    const fixture = buildCredentialFixture();
    const { kid: _kid, ...issuerWithoutKid } = fixture.issuerPublicKey;
    expect(() =>
      parseSwiyuCompactSdJwt(fixture.compactSdJwt, issuerWithoutKid),
    ).toThrow(/exact protected header kid/);

    const { snapshot, authoritativeSnapshot, witness } = makeStatus();
    const challenge = makeChallenge(snapshot.id);
    const { wallet, verifier } = setup();
    const envelope = await wallet.show({
      prepared: wallet.prepare({
        compactSdJwt: fixture.compactSdJwt,
        issuerPublicKey: fixture.issuerPublicKey,
      }),
      challenge,
      holderSigner: holderSigner(),
      statusSnapshot: snapshot,
      statusWitness: witness,
      provingKey: new Uint8Array([1]),
    });
    await expect(
      verifier.verify({
        envelope,
        challenge,
        issuerPublicKey: issuerWithoutKid,
        statusSnapshot: authoritativeSnapshot,
        verifyingKey: new Uint8Array([2]),
      }),
    ).resolves.toEqual({
      valid: false,
      error: "resolved issuer key must carry the exact proof lookup kid",
    });

    const one = new Uint8Array(32);
    one[31] = 1;
    await expect(
      verifier.verify({
        envelope,
        challenge,
        issuerPublicKey: {
          ...fixture.issuerPublicKey,
          x: base64urlEncode(one),
          y: base64urlEncode(one),
        },
        statusSnapshot: authoritativeSnapshot,
        verifyingKey: new Uint8Array([2]),
      }),
    ).resolves.toEqual({
      valid: false,
      error: "resolved issuer key is not a valid P-256 point",
    });
  });

  it("rejects a disclosure with the wrong claim name even when its digest is signed", () => {
    const fixture = buildCredentialFixture({ disclosureName: "birthdayx" });
    expect(() =>
      parseSwiyuCompactSdJwt(fixture.compactSdJwt, fixture.issuerPublicKey),
    ).toThrow(/exactly one supplied disclosure must have claim name birthdate/);
  });

  it("rejects disclosure substitution when the signed digest is for another value", () => {
    const fixture = buildCredentialFixture();
    const replacement = buildCredentialFixture({ birthdate: "2001-02-28" }).disclosure;
    const substituted = `${fixture.jwt}~${replacement}~`;
    expect(() =>
      parseSwiyuCompactSdJwt(substituted, fixture.issuerPublicKey),
    ).toThrow(/digest must occur exactly once/);
  });

  it("prepares an issuer-shaped credential with unrelated selective disclosures", () => {
    const fixture = buildCredentialFixture({
      swiyuIssuerShape: true,
      additionalDisclosures: [
        {
          salt: "qrstuvwxyzABCDEF",
          name: "given_name",
          value: "Zoë",
        },
      ],
    });
    const parsed = parseSwiyuCompactSdJwt(
      fixture.compactSdJwt,
      fixture.issuerPublicKey,
    );
    const [headerSegment, payloadSegment] = fixture.jwt.split(".") as [
      string,
      string,
      string,
    ];
    const signingInputLength = headerSegment.length + 1 + payloadSegment.length;
    const paddedSigningInputLength =
      Math.ceil((signingInputLength + 9) / 64) * 64;
    expect({
      headerB64: headerSegment.length,
      payloadB64: payloadSegment.length,
      paddedSigningInput: paddedSigningInputLength,
    }).toEqual({
      headerB64: 246,
      payloadB64: 616,
      paddedSigningInput: 896,
    });
    expect(headerSegment.length).toBeLessThanOrEqual(
      SWIYU_MAX_B64_HEADER_BYTES,
    );
    expect(payloadSegment.length).toBeLessThanOrEqual(
      SWIYU_MAX_B64_PAYLOAD_BYTES,
    );
    expect(paddedSigningInputLength).toBeLessThanOrEqual(SWIYU_MESSAGE_BYTES);
    const { wallet } = setup();
    const prepared = wallet.prepare({
      compactSdJwt: fixture.compactSdJwt,
      issuerPublicKey: fixture.issuerPublicKey,
    });
    expect(prepared.profile).toBe(SWIYU_AGE18_STATUS_PROFILE);
    expect(parsed.birthdate).toBe("2000-02-29");
    expect(parsed.baseInputs.disclosureLength).toBe(fixture.disclosure.length);
  });

  it("accepts a correctly signed payload above the obsolete 1k ceiling", () => {
    const fixture = buildCredentialFixture({
      swiyuIssuerShape: true,
      payloadJson(canonical) {
        return canonical.replace(
          '{"iss":',
          `{"issuer_extension":"${"a".repeat(400)}","iss":`,
        );
      },
    });
    const payloadLength = fixture.jwt.split(".")[1]!.length;
    expect(payloadLength).toBeGreaterThan(1024);
    expect(payloadLength).toBeLessThanOrEqual(SWIYU_MAX_B64_PAYLOAD_BYTES);
    expect(() =>
      parseSwiyuCompactSdJwt(fixture.compactSdJwt, fixture.issuerPublicKey),
    ).not.toThrow();
  });

  it("authenticates nested object and array disclosures through their parent", () => {
    const encodeDisclosure = (tuple: unknown[]) =>
      base64urlEncode(new TextEncoder().encode(JSON.stringify(tuple)));
    const digest = (encoded: string) =>
      base64urlEncode(sha256(new TextEncoder().encode(encoded)));

    const objectChild = encodeDisclosure([
      "qrstuvwxyzABCDEF",
      "family_name",
      "Müller",
    ]);
    const arrayChild = encodeDisclosure(["GHIJKLMNOPQRSTUV", "blue"]);
    const parent = encodeDisclosure([
      "WXYZabcdefghijkl",
      "profile",
      {
        _sd: [digest(objectChild)],
        tags: [{ "...": digest(arrayChild) }],
      },
    ]);
    const parentDigest = digest(parent);
    const fixture = buildCredentialFixture({
      swiyuIssuerShape: true,
      payloadJson(canonical) {
        return canonical.replace('"_sd":[', `"_sd":["${parentDigest}",`);
      },
    });
    // swiyu's issuer may serialize child disclosures before their parent.
    const compact = `${fixture.jwt}~${fixture.disclosure}~${objectChild}~${arrayChild}~${parent}~`;
    expect(() =>
      parseSwiyuCompactSdJwt(compact, fixture.issuerPublicKey),
    ).not.toThrow();
  });

  it("authenticates disclosures rooted in clear nested payload objects", () => {
    const child = base64urlEncode(
      new TextEncoder().encode(
        JSON.stringify(["qrstuvwxyzABCDEF", "street", "Bundesgasse 3"]),
      ),
    );
    const childDigest = base64urlEncode(
      sha256(new TextEncoder().encode(child)),
    );
    const fixture = buildCredentialFixture({
      payloadJson(canonical) {
        return canonical.replace(
          '{"iss":',
          `{"address":{"_sd":["${childDigest}"]},"iss":`,
        );
      },
    });
    expect(() =>
      parseSwiyuCompactSdJwt(
        `${fixture.compactSdJwt}${child}~`,
        fixture.issuerPublicKey,
      ),
    ).not.toThrow();
  });

  it("authenticates array disclosures rooted directly in the signed payload", () => {
    const child = base64urlEncode(
      new TextEncoder().encode(
        JSON.stringify(["qrstuvwxyzABCDEF", "public-transport"]),
      ),
    );
    const childDigest = base64urlEncode(
      sha256(new TextEncoder().encode(child)),
    );
    const fixture = buildCredentialFixture({
      payloadJson(canonical) {
        return canonical.replace(
          '{"iss":',
          `{"mobility":[{"...":"${childDigest}"}],"iss":`,
        );
      },
    });
    expect(() =>
      parseSwiyuCompactSdJwt(
        `${fixture.compactSdJwt}${child}~`,
        fixture.issuerPublicKey,
      ),
    ).not.toThrow();
  });

  it("rejects a well-formed auxiliary disclosure outside the signed graph", () => {
    const fixture = buildCredentialFixture();
    const injected = base64urlEncode(
      new TextEncoder().encode(
        JSON.stringify(["qrstuvwxyzABCDEF", "given_name", "Mallory"]),
      ),
    );
    expect(() =>
      parseSwiyuCompactSdJwt(
        `${fixture.compactSdJwt}${injected}~`,
        fixture.issuerPublicKey,
      ),
    ).toThrow(/not authenticated by the signed disclosure graph/);
  });

  it("rejects ambiguous duplicate birthdate disclosures", () => {
    const fixture = buildCredentialFixture({
      additionalDisclosures: [
        {
          salt: "qrstuvwxyzABCDEF",
          name: "birthdate",
          value: "2001-01-01",
        },
      ],
    });
    expect(() =>
      parseSwiyuCompactSdJwt(fixture.compactSdJwt, fixture.issuerPublicKey),
    ).toThrow(/exactly one supplied disclosure must have claim name birthdate/);
  });

  it("rejects a second birthdate tuple even when it is not top-level-signed", () => {
    const fixture = buildCredentialFixture();
    const nestedBirthdate = base64urlEncode(
      new TextEncoder().encode(
        JSON.stringify(["qrstuvwxyzABCDEF", "birthdate", "2001-01-01"]),
      ),
    );
    const withNestedBirthdate = `${fixture.compactSdJwt}${nestedBirthdate}~`;
    expect(() =>
      parseSwiyuCompactSdJwt(withNestedBirthdate, fixture.issuerPublicKey),
    ).toThrow(/exactly one supplied disclosure must have claim name birthdate/);
  });

  it("rejects a three-element disclosure with a non-string claim name", () => {
    const fixture = buildCredentialFixture();
    const malformed = base64urlEncode(
      new TextEncoder().encode(
        JSON.stringify(["qrstuvwxyzABCDEF", 7, "not-a-valid-object-disclosure"]),
      ),
    );
    const withMalformedDisclosure = `${fixture.compactSdJwt}${malformed}~`;
    expect(() =>
      parseSwiyuCompactSdJwt(withMalformedDisclosure, fixture.issuerPublicKey),
    ).toThrow(/two- or three-element SD-JWT tuple/);
  });

  it("matches the circuit's Gregorian leap-year domain", () => {
    expect(parseSwiyuIsoDate("2000-02-29", "date")).toBe(20000229n);
    expect(parseSwiyuIsoDate("2004-02-29", "date")).toBe(20040229n);
    for (const invalid of ["1900-02-29", "2001-02-29", "2100-02-29", "2000-04-31"] as const) {
      expect(() => parseSwiyuIsoDate(invalid, "date")).toThrow(/invalid day/);
      const fixture = buildCredentialFixture({ birthdate: invalid });
      expect(() =>
        parseSwiyuCompactSdJwt(fixture.compactSdJwt, fixture.issuerPublicKey),
      ).toThrow(/invalid day/);
    }
  });

  it("accepts the full depth-17 status range and rejects overflow", () => {
    const maximum = buildCredentialFixture({
      statusIndex: SWIYU_MAX_STATUS_LIST_LENGTH - 1,
    });
    expect(
      parseSwiyuCompactSdJwt(
        maximum.compactSdJwt,
        maximum.issuerPublicKey,
      ).statusIndex,
    ).toBe(SWIYU_MAX_STATUS_LIST_LENGTH - 1);

    const overflow = buildCredentialFixture({
      statusIndex: SWIYU_MAX_STATUS_LIST_LENGTH,
    });
    expect(() =>
      parseSwiyuCompactSdJwt(
        overflow.compactSdJwt,
        overflow.issuerPublicKey,
      ),
    ).toThrow(/17-level profile/);

    const { snapshot } = makeStatus();
    for (const listLength of [1, SWIYU_MAX_STATUS_LIST_LENGTH]) {
      expect(() =>
        validatePrivateStatusSnapshot({ ...snapshot, listLength }),
      ).not.toThrow();
    }
    for (const listLength of [0, SWIYU_MAX_STATUS_LIST_LENGTH + 1]) {
      expect(() =>
        validatePrivateStatusSnapshot({ ...snapshot, listLength }),
      ).toThrow(/status list length/);
    }
  });

  it("rejects stale credentials before witness generation", async () => {
    const fixture = buildCredentialFixture({ exp: 1_740_000_000 });
    const { snapshot, witness } = makeStatus();
    const { wallet, witnessGenerator } = setup();
    const prepared = wallet.prepare({
      compactSdJwt: fixture.compactSdJwt,
      issuerPublicKey: fixture.issuerPublicKey,
    });
    await expect(
      wallet.show({
        prepared,
        challenge: makeChallenge(snapshot.id),
        holderSigner: holderSigner(),
        statusSnapshot: snapshot,
        statusWitness: witness,
        provingKey: new Uint8Array([1]),
      }),
    ).rejects.toThrow(/not valid at.*current_time/);
    expect(witnessGenerator.inputs).toBeUndefined();
  });

  it("treats JWT exp as an exclusive validity boundary", async () => {
    const challenge = makeChallenge();
    const fixture = buildCredentialFixture({ exp: Number(challenge.currentTime) });
    const { snapshot, witness } = makeStatus();
    const { wallet, witnessGenerator } = setup();
    await expect(
      wallet.show({
        prepared: wallet.prepare({
          compactSdJwt: fixture.compactSdJwt,
          issuerPublicKey: fixture.issuerPublicKey,
        }),
        challenge,
        holderSigner: holderSigner(),
        statusSnapshot: snapshot,
        statusWitness: witness,
        provingKey: new Uint8Array([1]),
      }),
    ).rejects.toThrow(/not valid at.*current_time/);
    expect(witnessGenerator.inputs).toBeUndefined();
  });

  it("rejects revoked/suspended, wrong-index, wrong-path and wrong-root status evidence", async () => {
    const fixture = buildCredentialFixture();
    const { snapshot, witness } = makeStatus();
    const { wallet } = setup();
    const prepared = wallet.prepare({
      compactSdJwt: fixture.compactSdJwt,
      issuerPublicKey: fixture.issuerPublicKey,
    });
    const base = {
      prepared,
      challenge: makeChallenge(snapshot.id),
      holderSigner: holderSigner(),
      statusSnapshot: snapshot,
      provingKey: new Uint8Array([1]),
    };
    await expect(
      wallet.show({ ...base, statusWitness: { ...witness, status: 1 } }),
    ).rejects.toThrow(/not valid/);
    await expect(
      wallet.show({ ...base, statusWitness: { ...witness, status: 2 } }),
    ).rejects.toThrow(/not valid.*value 2/);
    await expect(
      wallet.show({ ...base, statusWitness: { ...witness, index: 43 } }),
    ).rejects.toThrow(/signed credential index/);
    const wrongPath = [...witness.siblings];
    wrongPath[4] = `${wrongPath[4]![0] === "0" ? "1" : "0"}${wrongPath[4]!.slice(1)}`;
    await expect(
      wallet.show({ ...base, statusWitness: { ...witness, siblings: wrongPath } }),
    ).rejects.toThrow(/authenticate.*root/);
    await expect(
      wallet.show({
        ...base,
        statusSnapshot: {
          ...snapshot,
          root: `${snapshot.root[0] === "0" ? "1" : "0"}${snapshot.root.slice(1)}`,
        },
        statusWitness: witness,
      }),
    ).rejects.toThrow(/authenticate.*root|resolved snapshot/);
  });

  it("rejects holder signatures from a key other than the signed cnf key", async () => {
    const fixture = buildCredentialFixture();
    const { snapshot, witness } = makeStatus();
    const { wallet } = setup();
    const wrongKey = new Uint8Array(32);
    wrongKey[31] = 99;
    await expect(
      wallet.show({
        prepared: wallet.prepare({
          compactSdJwt: fixture.compactSdJwt,
          issuerPublicKey: fixture.issuerPublicKey,
        }),
        challenge: makeChallenge(snapshot.id),
        holderSigner: holderSigner(wrongKey),
        statusSnapshot: snapshot,
        statusWitness: witness,
        provingKey: new Uint8Array([1]),
      }),
    ).rejects.toThrow(/holder signature does not match/);
  });

  it("has stable metadata/snapshot commitment and challenge vectors", () => {
    const fixture = buildCredentialFixture();
    const { snapshot } = makeStatus();
    const parsed = parseSwiyuCompactSdJwt(
      fixture.compactSdJwt,
      fixture.issuerPublicKey,
    );
    const metadata = computeSwiyuMetadataCommitment(
      parsed.lookup,
      hashSwiyuChallenge(makeChallenge(snapshot.id)).scalar,
    );
    expect(metadata).toEqual({
      hashHi: 58705223853647882008150526974811453905n,
      hashLo: 138904321590673713067390515217485040407n,
    });
    expect(
      computeSwiyuMetadataCommitment(
        parsed.lookup,
        hashSwiyuChallenge({
          ...makeChallenge(snapshot.id),
          nonce: "different-session",
        }).scalar,
      ),
    ).not.toEqual(metadata);
    expect(computeSwiyuStatusProfileCommitment(snapshot)).toEqual({
      hashHi: 109475111538640229597713363934214969033n,
      hashLo: 170725460803801889247438623623142364604n,
    });
    expect(Buffer.from(encodeSwiyuChallenge(makeChallenge(snapshot.id))).toString("hex")).toBe(
      "73776979752d73686f772d763000000000126e2d3766336637373864306265343437346500000020783530395f73616e5f646e733a76657269666965722e6578616d706c652e63680000002b68747470733a2f2f76657269666965722e6578616d706c652e63682f6f69643476702f63616c6c6261636b0000000e73746174652d61616632346335640000001c6167652d6f7665722d31382d616e642d76616c69642d7374617475730000001873776979752d61676531382d7374617475732d326b2d76300000000a323030372d30362d31350000000a313735303030303030300000001863682d74736c2d323032362d30372d65706f63682d313732",
    );
  });

  it("leaves the ordinary Credential parser and generic OpenAC surface intact", () => {
    const header = base64urlEncode(new TextEncoder().encode('{"alg":"ES256"}'));
    const payload = base64urlEncode(new TextEncoder().encode('{"sub":"ordinary"}'));
    const signature = base64urlEncode(new Uint8Array(64));
    const ordinary = Credential.parse(`${header}.${payload}.${signature}`, []);
    expect(ordinary.payload.sub).toBe("ordinary");
  });
});

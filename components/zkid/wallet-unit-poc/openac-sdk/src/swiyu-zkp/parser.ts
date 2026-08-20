import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2";
import { InputError, OpenACError } from "../errors.js";
import type { EcdsaPublicKey } from "../types.js";
import {
  base64urlEncode,
  modInverse,
  P256_SCALAR_ORDER,
  sha256Pad,
} from "../utils.js";
import {
  SWIYU_AGE18_STATUS_PROFILE,
  SWIYU_DISCLOSURE_PADDED_BYTES,
  SWIYU_MAX_AUX_DISCLOSURE_B64_BYTES,
  SWIYU_MAX_B64_HEADER_BYTES,
  SWIYU_MAX_B64_PAYLOAD_BYTES,
  SWIYU_MAX_DISCLOSURES,
  SWIYU_MAX_STATUS_LIST_LENGTH,
  SWIYU_MESSAGE_BYTES,
  SWIYU_PROFILE_VERSION,
  SWIYU_STRING_SLOT_BYTES,
} from "./constants.js";
import { parseSwiyuIsoDate } from "./date.js";
import {
  asciiPadded,
  bigEndianBytesToBigInt,
  bytesAsBigints,
  decodeBase64urlStrict,
  decodeUtf8Strict,
  assertFieldElement,
} from "./encoding.js";
import {
  forbidProperty,
  parseJsonWithUniqueKeys,
  parseStrictCompactJson,
  requireArray,
  requireObject,
  requireProperty,
  requireString,
  requireUnsignedDecimal,
  type StrictJsonObject,
  type StrictJsonNode,
  type StrictJsonProperty,
  type StrictJsonString,
} from "./strict-json.js";
import type { SwiyuCircuitInputs, SwiyuLookupHints } from "./types.js";

export interface ParsedSwiyuCredential {
  issuerPublicKey: EcdsaPublicKey;
  lookup: SwiyuLookupHints;
  birthdate: string;
  birthdateNumeric: bigint;
  statusUri: string;
  statusIndex: number;
  nbf: bigint;
  exp: bigint;
  holderPublicKey: EcdsaPublicKey;
  baseInputs: Omit<
    SwiyuCircuitInputs,
    | "challengeHash"
    | "cutoffDate"
    | "currentTime"
    | "expectedMetadataHashHi"
    | "expectedMetadataHashLo"
    | "expectedStatusSnapshotHashHi"
    | "expectedStatusSnapshotHashLo"
    | "holderSigR"
    | "holderSigSInverse"
    | "statusValue"
    | "statusSiblings"
    | "statusEpoch"
    | "statusListLength"
  >;
}

export function parseSwiyuCompactSdJwt(
  compactSdJwt: string,
  issuerPublicKey: EcdsaPublicKey,
): ParsedSwiyuCredential {
  try {
    return parseUnchecked(compactSdJwt, issuerPublicKey);
  } catch (error) {
    if (error instanceof OpenACError) throw error;
    throw new InputError(
      "INVALID_JWT",
      `Invalid ${SWIYU_AGE18_STATUS_PROFILE} credential: ${error instanceof Error ? error.message : String(error)}`,
      error,
    );
  }
}

function parseUnchecked(
  compactSdJwt: string,
  issuerPublicKey: EcdsaPublicKey,
): ParsedSwiyuCredential {
  const sdParts = compactSdJwt.split("~");
  if (sdParts.at(-1) === "") sdParts.pop();
  if (
    sdParts.length < 2 ||
    sdParts.length > SWIYU_MAX_DISCLOSURES + 1 ||
    sdParts.some((part) => part.length === 0)
  ) {
    throw new Error(
      `expected one issuer JWS and between one and ${SWIYU_MAX_DISCLOSURES} disclosures`,
    );
  }
  const [jwt, ...disclosures] = sdParts as [string, ...string[]];
  const jwtParts = jwt.split(".");
  if (jwtParts.length !== 3 || jwtParts.some((part) => part.length === 0)) {
    throw new Error("issuer JWS must contain exactly three non-empty parts");
  }
  const [b64Header, b64Payload, b64Signature] = jwtParts as [string, string, string];
  if (b64Header.length > SWIYU_MAX_B64_HEADER_BYTES) {
    throw new Error(`protected header exceeds ${SWIYU_MAX_B64_HEADER_BYTES} base64url bytes`);
  }
  if (b64Payload.length > SWIYU_MAX_B64_PAYLOAD_BYTES) {
    throw new Error(`payload exceeds ${SWIYU_MAX_B64_PAYLOAD_BYTES} base64url bytes`);
  }

  const headerBytes = decodeBase64urlStrict(b64Header, "protected header");
  const payloadBytes = decodeBase64urlStrict(b64Payload, "payload");
  const headerJson = decodeUtf8Strict(headerBytes, "protected header");
  const payloadJson = decodeUtf8Strict(payloadBytes, "payload");
  const header = requireObject(parseStrictCompactJson(headerJson), "header");
  const payload = requireObject(parseStrictCompactJson(payloadJson), "payload");

  // This profile proves exactly one selectively disclosed birthdate. Allowing a
  // second, cleartext claim with the same semantic name would make the signed
  // credential ambiguous and let host and circuit select different values.
  forbidProperty(payload, "birthdate", "payload");

  const alg = stringProperty(header, "alg", "header", 5);
  if (alg.value !== "ES256") throw new Error("header.alg must equal ES256");
  const typ = stringProperty(header, "typ", "header", 9);
  if (typ.value !== "dc+sd-jwt") throw new Error("header.typ must equal dc+sd-jwt");
  const profileVersion = stringProperty(
    header,
    "profile_version",
    "header",
    SWIYU_PROFILE_VERSION.length,
  );
  if (profileVersion.value !== SWIYU_PROFILE_VERSION) {
    throw new Error(`header.profile_version must equal ${SWIYU_PROFILE_VERSION}`);
  }
  const kid = stringProperty(header, "kid", "header", SWIYU_STRING_SLOT_BYTES);
  forbidProperty(header, "crit", "header");
  forbidProperty(header, "b64", "header");

  const iss = stringProperty(payload, "iss", "payload", SWIYU_STRING_SLOT_BYTES);
  const vct = stringProperty(payload, "vct", "payload", SWIYU_STRING_SLOT_BYTES);
  const nbfProperty = requireProperty(payload, "nbf", "payload");
  const nbf = requireUnsignedDecimal(nbfProperty.value, "payload.nbf");
  const expProperty = requireProperty(payload, "exp", "payload");
  const exp = requireUnsignedDecimal(expProperty.value, "payload.exp");
  if (nbf.value >= exp.value) {
    throw new Error("payload.nbf must be strictly earlier than payload.exp");
  }

  const cnfProperty = requireProperty(payload, "cnf", "payload");
  const cnf = requireObject(cnfProperty.value, "payload.cnf");
  const jwkProperty = requireProperty(cnf, "jwk", "payload.cnf");
  const jwk = requireObject(jwkProperty.value, "payload.cnf.jwk");
  const kty = stringProperty(jwk, "kty", "payload.cnf.jwk", 2);
  const crv = stringProperty(jwk, "crv", "payload.cnf.jwk", 5);
  if (kty.value !== "EC" || crv.value !== "P-256") {
    throw new Error("payload.cnf.jwk must be an EC P-256 key");
  }
  const holderX = stringProperty(jwk, "x", "payload.cnf.jwk", 43);
  const holderY = stringProperty(jwk, "y", "payload.cnf.jwk", 43);
  if (holderX.value.length !== 43 || holderY.value.length !== 43) {
    throw new Error("holder JWK coordinates must be 43-character base64url values");
  }
  const holderPublicKey: EcdsaPublicKey = {
    kty: "EC",
    crv: "P-256",
    x: holderX.value,
    y: holderY.value,
  };
  validateP256Point(holderPublicKey, "holder public key");

  const statusProperty = requireProperty(payload, "status", "payload");
  const status = requireObject(statusProperty.value, "payload.status");
  const statusListProperty = requireProperty(status, "status_list", "payload.status");
  const statusList = requireObject(statusListProperty.value, "payload.status.status_list");
  const statusUri = stringProperty(statusList, "uri", "payload.status.status_list", 160);
  const statusIndexProperty = requireProperty(statusList, "idx", "payload.status.status_list");
  const statusIndex = requireUnsignedDecimal(
    statusIndexProperty.value,
    "payload.status.status_list.idx",
  );
  if (statusIndex.value >= BigInt(SWIYU_MAX_STATUS_LIST_LENGTH)) {
    throw new Error("payload.status.status_list.idx must fit the 17-level profile");
  }

  const sdAlg = stringProperty(payload, "_sd_alg", "payload", 7);
  if (sdAlg.value !== "sha-256") throw new Error("payload._sd_alg must equal sha-256");
  const sdProperty = requireProperty(payload, "_sd", "payload");
  const sd = requireArray(sdProperty.value, "payload._sd");
  if (sd.items.length === 0) throw new Error("payload._sd must not be empty");

  const suppliedDisclosures = disclosures.map(parseSuppliedDisclosure);
  const signedDigestNodes = new Map<
    string,
    { count: number; node: StrictJsonString }
  >();
  for (let index = 0; index < sd.items.length; index++) {
    const member = requireString(sd.items[index]!, `payload._sd[${index}]`);
    decodeBase64urlStrict(member.value, `payload._sd[${index}]`, 32);
    if (member.value.length !== 43) {
      throw new Error(`payload._sd[${index}] must contain a 43-character digest`);
    }
    const previous = signedDigestNodes.get(member.value);
    signedDigestNodes.set(member.value, {
      count: (previous?.count ?? 0) + 1,
      node: previous?.node ?? member,
    });
  }

  // A swiyu bundle may also contain nested or array disclosures whose digests
  // are reachable through parent disclosures rather than the JWT's top-level
  // `_sd`. They are accepted, but a second birthdate tuple would make selection
  // ambiguous even if that tuple were nested.
  const birthdateDisclosures = suppliedDisclosures.filter(
    (supplied) => supplied.claimName === "birthdate",
  );
  if (birthdateDisclosures.length !== 1) {
    throw new Error(
      "exactly one supplied disclosure must have claim name birthdate",
    );
  }
  const disclosure = birthdateDisclosures[0]!.encoded;
  const parsedDisclosure = parseDisclosure(disclosure);
  const digest = birthdateDisclosures[0]!.digest;
  const signedBirthdate = signedDigestNodes.get(digest);
  if (signedBirthdate?.count !== 1) {
    throw new Error("birthdate disclosure digest must occur exactly once in payload._sd");
  }
  const digestNode = signedBirthdate.node;
  for (const [signedDigest, entry] of signedDigestNodes) {
    if (entry.count !== 1) {
      throw new Error(`payload._sd repeats disclosure digest ${signedDigest}`);
    }
  }
  authenticateSuppliedDisclosures(
    suppliedDisclosures,
    collectDisclosureReferences(payload, "payload", "value"),
  );

  validateP256Point(issuerPublicKey, "issuer public key");
  if (issuerPublicKey.kid !== kid.value) {
    throw new InputError(
      "INVALID_KEY",
      "issuer public key must carry the exact protected header kid",
    );
  }
  const signatureBytes = decodeBase64urlStrict(b64Signature, "issuer signature", 64);
  const issuerSignature = parseP256Signature(signatureBytes, "issuer signature");
  const signingInput = `${b64Header}.${b64Payload}`;
  const signingInputBytes = new TextEncoder().encode(signingInput);
  const issuerPoint = publicPoint(issuerPublicKey);
  if (!p256.verify(
    issuerSignature.toDERRawBytes(),
    sha256(signingInputBytes),
    issuerPoint.toRawBytes(),
  )) {
    throw new InputError("INVALID_SIGNATURE", "issuer JWS signature verification failed");
  }
  const [messagePadded, messageLength] = sha256Pad(signingInputBytes, SWIYU_MESSAGE_BYTES);
  const disclosureBytes = new TextEncoder().encode(disclosure);
  const [disclosurePadded] = sha256Pad(
    disclosureBytes,
    SWIYU_DISCLOSURE_PADDED_BYTES,
  );
  const issuerCoordinates = jwkCoordinates(issuerPublicKey);
  assertFieldElement(issuerCoordinates.x, "issuer public key x");
  assertFieldElement(issuerCoordinates.y, "issuer public key y");
  const holderCoordinates = jwkCoordinates(holderPublicKey);
  assertFieldElement(holderCoordinates.x, "holder public key x");
  assertFieldElement(holderCoordinates.y, "holder public key y");

  const lookup = {
    issuer: iss.value,
    kid: kid.value,
    vct: vct.value,
  } as const;

  const baseInputs: ParsedSwiyuCredential["baseInputs"] = {
    issuerPubKeyX: issuerCoordinates.x,
    issuerPubKeyY: issuerCoordinates.y,
    message: bytesAsBigints(messagePadded),
    messageLength,
    periodIndex: b64Header.length,
    headerJsonLength: headerBytes.length,
    payloadJsonLength: payloadBytes.length,
    issuerSigR: issuerSignature.r,
    issuerSigSInverse: modInverse(issuerSignature.s, P256_SCALAR_ORDER),
    disclosurePadded: bytesAsBigints(disclosurePadded),
    disclosureLength: disclosure.length,
    disclosureJsonLength: parsedDisclosure.jsonLength,
    disclosureSaltLength: parsedDisclosure.salt.length,
    iss: asciiPadded(iss.value, SWIYU_STRING_SLOT_BYTES, "issuer"),
    issLength: iss.value.length,
    kid: asciiPadded(kid.value, SWIYU_STRING_SLOT_BYTES, "kid"),
    kidLength: kid.value.length,
    vct: asciiPadded(vct.value, SWIYU_STRING_SLOT_BYTES, "vct"),
    vctLength: vct.value.length,
    holderXB64: asciiPadded(holderX.value, 44, "holder x"),
    holderYB64: asciiPadded(holderY.value, 44, "holder y"),
    statusUri: asciiPadded(statusUri.value, 160, "status URI"),
    statusUriLength: statusUri.value.length,
    nbfDigitLength: nbf.raw.length,
    expDigitLength: exp.raw.length,
    statusIndexDigitLength: statusIndex.raw.length,
    disclosureDigestB64: asciiPadded(digest, 43, "disclosure digest"),
    headerAlgKeyStart: property(header, "alg").keyStart,
    headerTypKeyStart: property(header, "typ").keyStart,
    headerProfileVersionKeyStart: property(header, "profile_version").keyStart,
    headerKidKeyStart: property(header, "kid").keyStart,
    payloadIssKeyStart: property(payload, "iss").keyStart,
    payloadVctKeyStart: property(payload, "vct").keyStart,
    payloadNbfKeyStart: nbfProperty.keyStart,
    payloadExpKeyStart: expProperty.keyStart,
    payloadCnfKeyStart: cnfProperty.keyStart,
    payloadCnfClose: cnf.end,
    payloadJwkKeyStart: jwkProperty.keyStart,
    payloadJwkClose: jwk.end,
    payloadKtyKeyStart: property(jwk, "kty").keyStart,
    payloadCrvKeyStart: property(jwk, "crv").keyStart,
    payloadXKeyStart: property(jwk, "x").keyStart,
    payloadYKeyStart: property(jwk, "y").keyStart,
    payloadStatusKeyStart: statusProperty.keyStart,
    payloadStatusClose: status.end,
    payloadStatusListKeyStart: statusListProperty.keyStart,
    payloadStatusListClose: statusList.end,
    payloadStatusUriKeyStart: property(statusList, "uri").keyStart,
    payloadStatusIdxKeyStart: statusIndexProperty.keyStart,
    payloadSdAlgKeyStart: property(payload, "_sd_alg").keyStart,
    payloadSdKeyStart: sdProperty.keyStart,
    payloadSdClose: sd.end,
    payloadDigestStart: digestNode.start,
  };

  return {
    issuerPublicKey: { ...issuerPublicKey },
    lookup,
    birthdate: parsedDisclosure.birthdate,
    birthdateNumeric: parsedDisclosure.birthdateNumeric,
    statusUri: statusUri.value,
    statusIndex: Number(statusIndex.value),
    nbf: nbf.value,
    exp: exp.value,
    holderPublicKey,
    baseInputs,
  };
}

interface SuppliedDisclosure {
  index: number;
  encoded: string;
  digest: string;
  tupleKind: "object" | "array";
  claimName?: string;
  value: StrictJsonNode;
}

/**
 * Validate every disclosure's transport and JSON container without imposing the
 * circuit's ASCII/canonical birthdate subset on unrelated swiyu claims. Nested
 * and array disclosures may legitimately carry structured or non-ASCII values.
 */
function parseSuppliedDisclosure(
  encoded: string,
  index: number,
  all: readonly string[],
): SuppliedDisclosure {
  if (encoded.length > SWIYU_MAX_AUX_DISCLOSURE_B64_BYTES) {
    throw new Error(
      `disclosure ${index} exceeds ${SWIYU_MAX_AUX_DISCLOSURE_B64_BYTES} base64url bytes`,
    );
  }
  if (all.indexOf(encoded) !== index) {
    throw new Error(`disclosure ${index} duplicates an earlier disclosure`);
  }
  const bytes = decodeBase64urlStrict(encoded, `disclosure ${index}`);
  const json = decodeUtf8Strict(bytes, `disclosure ${index}`);
  let tuple;
  try {
    tuple = requireArray(
      parseJsonWithUniqueKeys(json),
      `disclosure ${index}`,
    );
  } catch (error) {
    throw new Error(
      `disclosure ${index} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  const salt = tuple.items[0];
  const name = tuple.items[1];
  if (
    (tuple.items.length !== 2 && tuple.items.length !== 3) ||
    salt?.kind !== "string" ||
    (tuple.items.length === 3 && name?.kind !== "string") ||
    !/^[A-Za-z0-9_-]{16,128}$/.test(salt.value)
  ) {
    throw new Error(
      `disclosure ${index} must be a two- or three-element SD-JWT tuple with a base64url salt`,
    );
  }
  return {
    index,
    encoded,
    digest: base64urlEncode(sha256(new TextEncoder().encode(encoded))),
    tupleKind: tuple.items.length === 3 ? "object" : "array",
    ...(tuple.items.length === 3 && name?.kind === "string"
      ? { claimName: name.value }
      : {}),
    value: tuple.items.at(-1)!,
  };
}

interface DisclosureReference {
  digest: string;
  kind: "object" | "array";
  path: string;
}

/**
 * Authenticate each supplied disclosure through the signed top-level `_sd`
 * array or a reachable parent disclosure. Missing referenced disclosures are
 * allowed (selective disclosure); injected supplied disclosures are not.
 */
function authenticateSuppliedDisclosures(
  supplied: readonly SuppliedDisclosure[],
  rootReferences: readonly DisclosureReference[],
): void {
  const byDigest = new Map<string, SuppliedDisclosure>();
  for (const disclosure of supplied) {
    if (byDigest.has(disclosure.digest)) {
      throw new Error(`disclosure ${disclosure.index} duplicates a disclosure digest`);
    }
    byDigest.set(disclosure.digest, disclosure);
  }

  const queue: DisclosureReference[] = [...rootReferences];
  const seenReferences = new Map<string, string>();
  const authenticated = new Set<string>();

  for (let cursor = 0; cursor < queue.length; cursor++) {
    const reference = queue[cursor]!;
    const firstPath = seenReferences.get(reference.digest);
    if (firstPath !== undefined) {
      throw new Error(
        `disclosure digest is referenced more than once (${firstPath} and ${reference.path})`,
      );
    }
    seenReferences.set(reference.digest, reference.path);

    const disclosure = byDigest.get(reference.digest);
    if (!disclosure) continue;
    if (disclosure.tupleKind !== reference.kind) {
      throw new Error(
        `disclosure ${disclosure.index} tuple kind does not match ${reference.path}`,
      );
    }
    authenticated.add(disclosure.digest);
    queue.push(
      ...collectDisclosureReferences(
        disclosure.value,
        `disclosure ${disclosure.index} value`,
        "value",
      ),
    );
  }

  for (const disclosure of supplied) {
    if (!authenticated.has(disclosure.digest)) {
      throw new Error(
        `disclosure ${disclosure.index} is not authenticated by the signed disclosure graph`,
      );
    }
  }
}

function collectDisclosureReferences(
  node: StrictJsonNode,
  path: string,
  placement: "value" | "array-element",
): DisclosureReference[] {
  if (node.kind === "array") {
    return node.items.flatMap((item, index) =>
      collectDisclosureReferences(item, `${path}[${index}]`, "array-element"),
    );
  }
  if (node.kind !== "object") return [];

  const arrayDigest = node.properties.get("...");
  if (arrayDigest) {
    if (
      placement !== "array-element" ||
      node.properties.size !== 1 ||
      arrayDigest.value.kind !== "string"
    ) {
      throw new Error(`${path} has an invalid SD-JWT array disclosure placeholder`);
    }
    return [{
      digest: validateNestedDigest(arrayDigest.value.value, `${path}.…`),
      kind: "array",
      path: `${path}.…`,
    }];
  }

  const references: DisclosureReference[] = [];
  for (const property of node.properties.values()) {
    if (property.key === "_sd") {
      if (property.value.kind !== "array") {
        throw new Error(`${path}._sd must be an array`);
      }
      for (let index = 0; index < property.value.items.length; index++) {
        const member = property.value.items[index]!;
        if (member.kind !== "string") {
          throw new Error(`${path}._sd[${index}] must be a digest string`);
        }
        references.push({
          digest: validateNestedDigest(member.value, `${path}._sd[${index}]`),
          kind: "object",
          path: `${path}._sd[${index}]`,
        });
      }
    } else {
      references.push(
        ...collectDisclosureReferences(
          property.value,
          `${path}.${property.key}`,
          "value",
        ),
      );
    }
  }
  return references;
}

function validateNestedDigest(value: string, path: string): string {
  decodeBase64urlStrict(value, path, 32);
  if (value.length !== 43) {
    throw new Error(`${path} must contain a 43-character disclosure digest`);
  }
  return value;
}

function parseDisclosure(disclosure: string): {
  salt: string;
  birthdate: string;
  birthdateNumeric: bigint;
  jsonLength: number;
} {
  if (disclosure.length < 56 || disclosure.length > 119) {
    throw new Error("birthdate disclosure encoded length must be in 56..119");
  }
  const bytes = decodeBase64urlStrict(disclosure, "birthdate disclosure");
  const json = decodeUtf8Strict(bytes, "birthdate disclosure");
  const tuple = requireArray(parseStrictCompactJson(json), "birthdate disclosure");
  if (tuple.items.length !== 3) {
    throw new Error('birthdate disclosure must be exactly [salt,"birthdate","YYYY-MM-DD"]');
  }
  const salt = requireString(tuple.items[0]!, "birthdate disclosure salt").value;
  const name = requireString(tuple.items[1]!, "birthdate disclosure name").value;
  const birthdate = requireString(tuple.items[2]!, "birthdate disclosure value").value;
  if (!/^[A-Za-z0-9_-]{16,48}$/.test(salt)) {
    throw new Error("birthdate disclosure salt must be 16..48 base64url characters");
  }
  if (name !== "birthdate") {
    throw new Error("birthdate disclosure name must equal birthdate");
  }
  const canonical = JSON.stringify([salt, "birthdate", birthdate]);
  if (json !== canonical || bytes.length !== salt.length + 29) {
    throw new Error("birthdate disclosure must use the canonical compact tuple encoding");
  }
  return {
    salt,
    birthdate,
    birthdateNumeric: parseSwiyuIsoDate(birthdate, "birthdate disclosure value"),
    jsonLength: bytes.length,
  };
}

function stringProperty(
  object: StrictJsonObject,
  key: string,
  path: string,
  maxLength: number,
): StrictJsonString {
  const value = requireString(requireProperty(object, key, path).value, `${path}.${key}`);
  if (value.value.length < 1 || value.value.length > maxLength) {
    throw new Error(`${path}.${key} length must be in 1..${maxLength}`);
  }
  return value;
}

function property(object: StrictJsonObject, key: string): StrictJsonProperty {
  return object.properties.get(key)!;
}

function validateP256Point(jwk: EcdsaPublicKey, label: string): void {
  if (jwk.kty !== "EC" || jwk.crv !== "P-256") {
    throw new InputError("INVALID_KEY", `${label} must be an EC P-256 JWK`);
  }
  try {
    publicPoint(jwk);
  } catch (error) {
    if (error instanceof OpenACError) throw error;
    throw new InputError("INVALID_KEY", `${label} is not a valid P-256 point`, error);
  }
}

function publicPoint(jwk: EcdsaPublicKey): InstanceType<typeof p256.ProjectivePoint> {
  const coordinates = jwkCoordinates(jwk);
  const point = p256.ProjectivePoint.fromAffine(coordinates);
  point.assertValidity();
  return point;
}

function jwkCoordinates(jwk: EcdsaPublicKey): { x: bigint; y: bigint } {
  return {
    x: bigEndianBytesToBigInt(decodeBase64urlStrict(jwk.x, "JWK x", 32)),
    y: bigEndianBytesToBigInt(decodeBase64urlStrict(jwk.y, "JWK y", 32)),
  };
}

function parseP256Signature(bytes: Uint8Array, label: string) {
  try {
    return p256.Signature.fromCompact(
      Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(""),
    );
  } catch (error) {
    throw new InputError("INVALID_SIGNATURE", `${label} is not a valid compact P-256 signature`, error);
  }
}

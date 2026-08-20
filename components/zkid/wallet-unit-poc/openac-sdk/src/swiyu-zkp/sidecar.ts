import { p256 } from "@noble/curves/nist.js";
import type { EcdsaPublicKey } from "../types.js";
import {
  SWIYU_AGE18_STATUS_CIRCUIT,
  SWIYU_AGE18_STATUS_PROFILE,
  SWIYU_PROOF_ENVELOPE_VERSION,
  SWIYU_STRING_SLOT_BYTES,
} from "./constants.js";
import { decodeBase64urlStrict } from "./encoding.js";
import {
  parseJsonWithUniqueKeys,
  requireArray,
  requireObject,
  requireProperty,
  requireString,
  requireUnsignedDecimal,
  type StrictJsonArray,
  type StrictJsonNode,
  type StrictJsonObject,
} from "./strict-json.js";
import type {
  SwiyuAuthoritativeStatusSnapshot,
  SwiyuChallenge,
  SwiyuKeyMaterial,
  SwiyuProofEnvelope,
  SwiyuVerificationResult,
  SwiyuVerifyRequest,
} from "./types.js";

export const SWIYU_SIDECAR_MAX_PROOF_ENVELOPE_BYTES = 2_097_152;
export const SWIYU_SIDECAR_MAX_REQUEST_BYTES = 2_162_688;

const encoder = new TextEncoder();

export interface SwiyuSidecarTrustAnchor {
  did: string;
  trustRegistryUri: string;
}

/**
 * A key and its already-authenticated policy relationships, provisioned by a
 * background ingestion job. Presentation verification performs no discovery.
 */
export interface SwiyuSidecarIssuerRecord {
  issuer: string;
  kid: string;
  publicKey: EcdsaPublicKey;
  vctValues: readonly string[];
  trustAnchors: readonly SwiyuSidecarTrustAnchor[];
}

export interface SwiyuSidecarExpectedContext {
  nonce: string;
  clientId: string;
  responseUri: string;
  state: string;
  queryId: string;
  profile: typeof SWIYU_AGE18_STATUS_PROFILE;
  circuitId: typeof SWIYU_AGE18_STATUS_CIRCUIT;
  cutoffDate: string;
  currentTime: bigint;
  statusListSnapshot: string;
  vctValues: readonly string[];
  acceptedIssuerDids: readonly string[];
  trustAnchors: readonly SwiyuSidecarTrustAnchor[];
}

export interface SwiyuSidecarRequest {
  proofEnvelope: SwiyuProofEnvelope;
  expected: SwiyuSidecarExpectedContext;
}

export interface SwiyuSidecarSuccessResponse {
  verified: true;
  profile: typeof SWIYU_AGE18_STATUS_PROFILE;
  circuit_id: typeof SWIYU_AGE18_STATUS_CIRCUIT;
  predicate_satisfied: true;
  status_valid: true;
  status_list_snapshot: string;
}

export interface SwiyuVerifierSidecarDependencies {
  /** The production instance invokes the real fixed-profile verifier. */
  verifier: {
    verify(request: SwiyuVerifyRequest): Promise<SwiyuVerificationResult>;
  };
  /** Profile verification key pinned at process start, never supplied by a request. */
  verifyingKey: SwiyuKeyMaterial;
  issuers: readonly SwiyuSidecarIssuerRecord[];
  statusSnapshots: readonly SwiyuAuthoritativeStatusSnapshot[];
}

/** A deliberately non-diagnostic rejection suitable for an HTTP trust boundary. */
export class SwiyuSidecarRejection extends Error {
  constructor() {
    super("presentation rejected");
    this.name = "SwiyuSidecarRejection";
  }
}

/**
 * Pure verifier-side policy service. It accepts Java's exact JSON contract,
 * resolves every authority input from immutable local registries, and invokes
 * one pinned fixed-profile verifier.
 */
export class SwiyuVerifierSidecarService {
  private readonly verifier: SwiyuVerifierSidecarDependencies["verifier"];
  private readonly verifyingKey: SwiyuKeyMaterial;
  private readonly issuers: ReadonlyMap<string, SwiyuSidecarIssuerRecord>;
  private readonly statusSnapshots: ReadonlyMap<
    string,
    SwiyuAuthoritativeStatusSnapshot
  >;

  constructor(dependencies: SwiyuVerifierSidecarDependencies) {
    if (
      !dependencies.verifier ||
      typeof dependencies.verifier.verify !== "function"
    ) {
      throw new Error("a swiyu proof verifier is required");
    }
    const verifyingKey = copyKeyMaterial(dependencies.verifyingKey);
    this.verifier = dependencies.verifier;
    this.verifyingKey = verifyingKey;
    this.issuers = buildIssuerRegistry(dependencies.issuers);
    this.statusSnapshots = buildStatusRegistry(dependencies.statusSnapshots);
  }

  async verifyJson(
    requestJson: string,
  ): Promise<SwiyuSidecarSuccessResponse> {
    try {
      if (typeof requestJson !== "string") throw new Error("invalid request");
      const byteLength = encoder.encode(requestJson).length;
      if (byteLength === 0 || byteLength > SWIYU_SIDECAR_MAX_REQUEST_BYTES) {
        throw new Error("invalid request size");
      }
      return await this.verifyParsed(parseSwiyuSidecarRequest(requestJson));
    } catch (error) {
      if (error instanceof SwiyuSidecarRejection) throw error;
      throw new SwiyuSidecarRejection();
    }
  }

  async verifyParsed(
    request: Readonly<SwiyuSidecarRequest>,
  ): Promise<SwiyuSidecarSuccessResponse> {
    try {
      const { proofEnvelope: envelope, expected } = request;
      if (
        expected.profile !== SWIYU_AGE18_STATUS_PROFILE ||
        expected.circuitId !== SWIYU_AGE18_STATUS_CIRCUIT ||
        envelope.version !== SWIYU_PROOF_ENVELOPE_VERSION ||
        envelope.profile !== SWIYU_AGE18_STATUS_PROFILE ||
        envelope.circuitId !== SWIYU_AGE18_STATUS_CIRCUIT
      ) {
        throw new Error("unsupported profile");
      }

      // Hints select a locally provisioned record. They never grant policy.
      const issuer = this.issuers.get(issuerRegistryKey(
        envelope.lookup.issuer,
        envelope.lookup.kid,
      ));
      if (!issuer) throw new Error("unprovisioned issuer key");
      if (
        !expected.vctValues.includes(envelope.lookup.vct) ||
        !issuer.vctValues.includes(envelope.lookup.vct)
      ) {
        throw new Error("credential type not accepted");
      }
      if (!issuerSatisfiesPolicy(issuer, expected)) {
        throw new Error("issuer policy not satisfied");
      }

      // Snapshot selection comes only from the signed expected context.
      const statusSnapshot = this.statusSnapshots.get(
        expected.statusListSnapshot,
      );
      if (!statusSnapshot) throw new Error("unprovisioned status snapshot");
      if (statusSnapshot.issuer !== issuer.issuer) {
        throw new Error("status snapshot issuer is not bound to the credential issuer");
      }

      const challenge: SwiyuChallenge = Object.freeze({
        nonce: expected.nonce,
        clientId: expected.clientId,
        responseUri: expected.responseUri,
        state: expected.state,
        queryId: expected.queryId,
        profile: expected.profile,
        cutoffDate: expected.cutoffDate,
        currentTime: expected.currentTime,
        statusListSnapshot: expected.statusListSnapshot,
      });
      const verification: SwiyuVerifyRequest = {
        envelope,
        challenge,
        issuerPublicKey: issuer.publicKey,
        statusSnapshot,
        verifyingKey: copyKeyMaterial(this.verifyingKey),
      };
      const result = await this.verifier.verify(verification);
      if (!result.valid) throw new Error("invalid proof");

      return Object.freeze({
        verified: true,
        profile: SWIYU_AGE18_STATUS_PROFILE,
        circuit_id: SWIYU_AGE18_STATUS_CIRCUIT,
        predicate_satisfied: true,
        status_valid: true,
        status_list_snapshot: expected.statusListSnapshot,
      });
    } catch (error) {
      if (error instanceof SwiyuSidecarRejection) throw error;
      throw new SwiyuSidecarRejection();
    }
  }
}

export function parseSwiyuSidecarRequest(source: string): SwiyuSidecarRequest {
  const root = exactObject(
    parseJsonWithUniqueKeys(source),
    "request",
    ["proof_envelope", "expected"],
  );
  const proofEnvelopeJson = boundedString(
    property(root, "proof_envelope"),
    "request.proof_envelope",
    1,
    SWIYU_SIDECAR_MAX_PROOF_ENVELOPE_BYTES,
  );
  const expected = parseExpected(property(root, "expected"));
  return {
    proofEnvelope: parseProofEnvelope(proofEnvelopeJson),
    expected,
  };
}

function parseExpected(node: StrictJsonNode): SwiyuSidecarExpectedContext {
  const expected = exactObject(node, "request.expected", [
    "nonce",
    "client_id",
    "response_uri",
    "state",
    "query_id",
    "profile",
    "circuit_id",
    "cutoff_date",
    "current_time",
    "status_list_snapshot",
    "vct_values",
    "accepted_issuer_dids",
    "trust_anchors",
  ]);
  const profile = boundedString(
    property(expected, "profile"),
    "request.expected.profile",
    1,
    64,
  );
  const circuitId = boundedString(
    property(expected, "circuit_id"),
    "request.expected.circuit_id",
    1,
    64,
  );
  if (profile !== SWIYU_AGE18_STATUS_PROFILE) {
    throw new Error("request.expected.profile is unsupported");
  }
  if (circuitId !== SWIYU_AGE18_STATUS_CIRCUIT) {
    throw new Error("request.expected.circuit_id is unsupported");
  }
  const currentTime = requireUnsignedDecimal(
    property(expected, "current_time"),
    "request.expected.current_time",
    20,
  ).value;
  if (currentTime >= 1n << 64n) {
    throw new Error("request.expected.current_time exceeds uint64");
  }
  const statusListSnapshot = asciiString(
    property(expected, "status_list_snapshot"),
    "request.expected.status_list_snapshot",
    1,
    256,
  );
  if (!/^[A-Za-z0-9._~:-]+$/.test(statusListSnapshot)) {
    throw new Error("request.expected.status_list_snapshot is not opaque");
  }
  const vctValues = uniqueAsciiStringArray(
    property(expected, "vct_values"),
    "request.expected.vct_values",
    1,
    64,
    SWIYU_STRING_SLOT_BYTES,
  );
  const acceptedIssuerDids = uniqueAsciiStringArray(
    property(expected, "accepted_issuer_dids"),
    "request.expected.accepted_issuer_dids",
    0,
    64,
    SWIYU_STRING_SLOT_BYTES,
  );
  const trustAnchors = parseTrustAnchors(
    property(expected, "trust_anchors"),
    "request.expected.trust_anchors",
  );
  if (acceptedIssuerDids.length === 0 && trustAnchors.length === 0) {
    throw new Error("request expected context has no issuer policy");
  }
  return Object.freeze({
    nonce: boundedString(property(expected, "nonce"), "request.expected.nonce", 1, 4096),
    clientId: boundedString(property(expected, "client_id"), "request.expected.client_id", 1, 4096),
    responseUri: boundedString(property(expected, "response_uri"), "request.expected.response_uri", 1, 4096),
    state: boundedString(property(expected, "state"), "request.expected.state", 1, 4096),
    queryId: boundedString(property(expected, "query_id"), "request.expected.query_id", 1, 4096),
    profile: SWIYU_AGE18_STATUS_PROFILE,
    circuitId: SWIYU_AGE18_STATUS_CIRCUIT,
    cutoffDate: asciiString(property(expected, "cutoff_date"), "request.expected.cutoff_date", 10, 10),
    currentTime,
    statusListSnapshot,
    vctValues,
    acceptedIssuerDids,
    trustAnchors,
  });
}

function parseProofEnvelope(source: string): SwiyuProofEnvelope {
  if (encoder.encode(source).length > SWIYU_SIDECAR_MAX_PROOF_ENVELOPE_BYTES) {
    throw new Error("proof envelope is too large");
  }
  const envelope = exactObject(parseJsonWithUniqueKeys(source), "proof_envelope", [
    "version",
    "profile",
    "circuitId",
    "proof",
    "lookup",
  ]);
  const version = asciiString(property(envelope, "version"), "proof_envelope.version", 1, 64);
  const profile = asciiString(property(envelope, "profile"), "proof_envelope.profile", 1, 64);
  const circuitId = asciiString(property(envelope, "circuitId"), "proof_envelope.circuitId", 1, 64);
  if (
    version !== SWIYU_PROOF_ENVELOPE_VERSION ||
    profile !== SWIYU_AGE18_STATUS_PROFILE ||
    circuitId !== SWIYU_AGE18_STATUS_CIRCUIT
  ) {
    throw new Error("proof envelope profile is unsupported");
  }
  const lookupNode = exactObject(property(envelope, "lookup"), "proof_envelope.lookup", [
    "issuer",
    "kid",
    "vct",
  ]);
  return Object.freeze({
    version: SWIYU_PROOF_ENVELOPE_VERSION,
    profile: SWIYU_AGE18_STATUS_PROFILE,
    circuitId: SWIYU_AGE18_STATUS_CIRCUIT,
    proof: asciiString(
      property(envelope, "proof"),
      "proof_envelope.proof",
      1,
      SWIYU_SIDECAR_MAX_PROOF_ENVELOPE_BYTES,
    ),
    lookup: Object.freeze({
      issuer: asciiString(property(lookupNode, "issuer"), "proof_envelope.lookup.issuer", 1, SWIYU_STRING_SLOT_BYTES),
      kid: asciiString(property(lookupNode, "kid"), "proof_envelope.lookup.kid", 1, SWIYU_STRING_SLOT_BYTES),
      vct: asciiString(property(lookupNode, "vct"), "proof_envelope.lookup.vct", 1, SWIYU_STRING_SLOT_BYTES),
    }),
  });
}

function buildIssuerRegistry(
  records: readonly SwiyuSidecarIssuerRecord[],
): ReadonlyMap<string, SwiyuSidecarIssuerRecord> {
  if (!Array.isArray(records) || records.length === 0 || records.length > 4_096) {
    throw new Error("issuer registry must contain 1..4096 records");
  }
  const registry = new Map<string, SwiyuSidecarIssuerRecord>();
  for (const [index, record] of records.entries()) {
    const label = `issuer record ${index}`;
    const issuer = validateAscii(record.issuer, `${label} issuer`, 1, SWIYU_STRING_SLOT_BYTES);
    const kid = validateAscii(record.kid, `${label} kid`, 1, SWIYU_STRING_SLOT_BYTES);
    const publicKey = validateIssuerPublicKey(record.publicKey, kid, label);
    const vctValues = validateUniqueAsciiValues(record.vctValues, `${label} vctValues`, 1, 64, SWIYU_STRING_SLOT_BYTES);
    const trustAnchors = validateTrustAnchorRecords(record.trustAnchors, `${label} trustAnchors`);
    const key = issuerRegistryKey(issuer, kid);
    if (registry.has(key)) throw new Error(`${label} duplicates issuer and kid`);
    registry.set(key, Object.freeze({ issuer, kid, publicKey, vctValues, trustAnchors }));
  }
  return registry;
}

function buildStatusRegistry(
  snapshots: readonly SwiyuAuthoritativeStatusSnapshot[],
): ReadonlyMap<string, SwiyuAuthoritativeStatusSnapshot> {
  if (!Array.isArray(snapshots) || snapshots.length === 0 || snapshots.length > 4_096) {
    throw new Error("status registry must contain 1..4096 snapshots");
  }
  const registry = new Map<string, SwiyuAuthoritativeStatusSnapshot>();
  for (const snapshot of snapshots) {
    if (!snapshot || typeof snapshot !== "object") {
      throw new Error("status registry contains an invalid snapshot");
    }
    if (registry.has(snapshot.id)) throw new Error("status registry contains a duplicate id");
    const copy: SwiyuAuthoritativeStatusSnapshot = Object.freeze({
      id: snapshot.id,
      issuer: snapshot.issuer,
      kid: snapshot.kid,
      subject: snapshot.subject,
      commitment: Object.freeze({
        hashHi: snapshot.commitment.hashHi,
        hashLo: snapshot.commitment.hashLo,
      }),
      epoch: snapshot.epoch,
      listLength: snapshot.listLength,
      validBefore: snapshot.validBefore,
      provenance: snapshot.provenance,
    });
    // The fixed verifier performs the definitive snapshot validation before
    // proof verification. Basic identity checks here make registry keys safe.
    validateAscii(copy.id, "status snapshot id", 1, 256);
    if (!/^[A-Za-z0-9._~:-]+$/.test(copy.id)) {
      throw new Error("status snapshot id is not an opaque policy identifier");
    }
    registry.set(copy.id, copy);
  }
  return registry;
}

function issuerSatisfiesPolicy(
  issuer: SwiyuSidecarIssuerRecord,
  expected: SwiyuSidecarExpectedContext,
): boolean {
  if (expected.acceptedIssuerDids.includes(issuer.issuer)) return true;
  return expected.trustAnchors.some((requested) =>
    issuer.trustAnchors.some(
      (provisioned) =>
        provisioned.did === requested.did &&
        provisioned.trustRegistryUri === requested.trustRegistryUri,
    ),
  );
}

function issuerRegistryKey(issuer: string, kid: string): string {
  return `${issuer.length}:${issuer}${kid}`;
}

function validateIssuerPublicKey(
  key: EcdsaPublicKey,
  expectedKid: string,
  label: string,
): EcdsaPublicKey {
  if (!key || key.kty !== "EC" || key.crv !== "P-256" || key.kid !== expectedKid) {
    throw new Error(`${label} public key must be a P-256 JWK with the exact kid`);
  }
  const xBytes = decodeBase64urlStrict(key.x, `${label} public key x`, 32);
  const yBytes = decodeBase64urlStrict(key.y, `${label} public key y`, 32);
  const x = bytesToBigInt(xBytes);
  const y = bytesToBigInt(yBytes);
  p256.ProjectivePoint.fromAffine({ x, y }).assertValidity();
  return Object.freeze({ kty: "EC", crv: "P-256", x: key.x, y: key.y, kid: expectedKid });
}

function parseTrustAnchors(
  node: StrictJsonNode,
  path: string,
): readonly SwiyuSidecarTrustAnchor[] {
  const array = requireArray(node, path);
  if (array.items.length > 64) throw new Error(`${path} exceeds 64 entries`);
  const anchors = array.items.map((item, index) => {
    const object = exactObject(item, `${path}[${index}]`, ["did", "trustRegistryUri"]);
    return Object.freeze({
      did: asciiString(property(object, "did"), `${path}[${index}].did`, 1, 512),
      trustRegistryUri: absoluteHttpUri(
        asciiString(property(object, "trustRegistryUri"), `${path}[${index}].trustRegistryUri`, 1, 2048),
        `${path}[${index}].trustRegistryUri`,
      ),
    });
  });
  rejectDuplicateAnchors(anchors, path);
  return Object.freeze(anchors);
}

function validateTrustAnchorRecords(
  anchors: readonly SwiyuSidecarTrustAnchor[],
  path: string,
): readonly SwiyuSidecarTrustAnchor[] {
  if (!Array.isArray(anchors) || anchors.length > 64) {
    throw new Error(`${path} must contain at most 64 entries`);
  }
  const copy = anchors.map((anchor, index) => Object.freeze({
    did: validateAscii(anchor.did, `${path}[${index}].did`, 1, 512),
    trustRegistryUri: absoluteHttpUri(
      validateAscii(anchor.trustRegistryUri, `${path}[${index}].trustRegistryUri`, 1, 2048),
      `${path}[${index}].trustRegistryUri`,
    ),
  }));
  rejectDuplicateAnchors(copy, path);
  return Object.freeze(copy);
}

function rejectDuplicateAnchors(
  anchors: readonly SwiyuSidecarTrustAnchor[],
  path: string,
): void {
  const seen = new Set<string>();
  for (const anchor of anchors) {
    const key = JSON.stringify([anchor.did, anchor.trustRegistryUri]);
    if (seen.has(key)) throw new Error(`${path} contains a duplicate anchor`);
    seen.add(key);
  }
}

function exactObject(
  node: StrictJsonNode,
  path: string,
  keys: readonly string[],
): StrictJsonObject {
  const object = requireObject(node, path);
  if (object.properties.size !== keys.length) {
    throw new Error(`${path} must contain exactly the supported fields`);
  }
  for (const key of keys) requireProperty(object, key, path);
  return object;
}

function property(object: StrictJsonObject, key: string): StrictJsonNode {
  return requireProperty(object, key, "object").value;
}

function boundedString(
  node: StrictJsonNode,
  path: string,
  minimumBytes: number,
  maximumBytes: number,
): string {
  const value = requireStringAllowEscapes(node, path);
  assertWellFormedUnicode(value, path);
  const length = encoder.encode(value).length;
  if (length < minimumBytes || length > maximumBytes) {
    throw new Error(`${path} UTF-8 length must be in ${minimumBytes}..${maximumBytes}`);
  }
  return value;
}

function asciiString(
  node: StrictJsonNode,
  path: string,
  minimumBytes: number,
  maximumBytes: number,
): string {
  return validateAscii(
    boundedString(node, path, minimumBytes, maximumBytes),
    path,
    minimumBytes,
    maximumBytes,
  );
}

function requireStringAllowEscapes(node: StrictJsonNode, path: string): string {
  if (node.kind !== "string") throw new Error(`${path} must be a string`);
  return node.value;
}

function uniqueAsciiStringArray(
  node: StrictJsonNode,
  path: string,
  minimumItems: number,
  maximumItems: number,
  maximumStringBytes: number,
): readonly string[] {
  const array = requireArray(node, path);
  if (array.items.length < minimumItems || array.items.length > maximumItems) {
    throw new Error(`${path} length must be in ${minimumItems}..${maximumItems}`);
  }
  const values = array.items.map((item, index) =>
    asciiString(item, `${path}[${index}]`, 1, maximumStringBytes),
  );
  if (new Set(values).size !== values.length) throw new Error(`${path} contains duplicates`);
  return Object.freeze(values);
}

function validateUniqueAsciiValues(
  values: readonly string[],
  path: string,
  minimumItems: number,
  maximumItems: number,
  maximumStringBytes: number,
): readonly string[] {
  if (!Array.isArray(values) || values.length < minimumItems || values.length > maximumItems) {
    throw new Error(`${path} length must be in ${minimumItems}..${maximumItems}`);
  }
  const copy = values.map((value, index) =>
    validateAscii(value, `${path}[${index}]`, 1, maximumStringBytes),
  );
  if (new Set(copy).size !== copy.length) throw new Error(`${path} contains duplicates`);
  return Object.freeze(copy);
}

function validateAscii(
  value: string,
  path: string,
  minimumBytes: number,
  maximumBytes: number,
): string {
  if (typeof value !== "string" || !/^[\x20-\x7e]*$/.test(value)) {
    throw new Error(`${path} must contain printable ASCII only`);
  }
  if (value.length < minimumBytes || value.length > maximumBytes) {
    throw new Error(`${path} length must be in ${minimumBytes}..${maximumBytes}`);
  }
  return value;
}

function absoluteHttpUri(value: string, path: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch (error) {
    throw new Error(`${path} must be an absolute HTTP(S) URI`, { cause: error });
  }
  if ((url.protocol !== "http:" && url.protocol !== "https:") || url.username || url.password) {
    throw new Error(`${path} must be an absolute HTTP(S) URI without userinfo`);
  }
  return value;
}

function assertWellFormedUnicode(value: string, path: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) {
        throw new Error(`${path} contains an unpaired surrogate`);
      }
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new Error(`${path} contains an unpaired surrogate`);
    }
  }
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function copyKeyMaterial(material: SwiyuKeyMaterial): SwiyuKeyMaterial {
  if (material instanceof Uint8Array) {
    if (material.length === 0) {
      throw new Error("a non-empty pinned swiyu verification key is required");
    }
    return new Uint8Array(material);
  }
  if (
    !material ||
    typeof material !== "object" ||
    material.kind !== "local-file" ||
    typeof material.path !== "string" ||
    material.path.length === 0 ||
    material.path.includes("\0")
  ) {
    throw new Error("a pinned swiyu verification key is required");
  }
  return Object.freeze({ kind: "local-file", path: material.path });
}

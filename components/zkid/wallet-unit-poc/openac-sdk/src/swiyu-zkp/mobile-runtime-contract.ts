import {
  SWIYU_AGE18_STATUS_CIRCUIT,
  SWIYU_AGE18_STATUS_PROFILE,
} from "./constants.js";
import {
  SWIYU_CANTON_SPLIT_DESCRIPTOR,
} from "./canton-split.js";
import { hashSwiyuChallenge } from "./challenge.js";
import { parseSwiyuIsoDate } from "./date.js";
import {
  SWIYU_NULLIFIER_AGE18_SPLIT_DESCRIPTOR,
} from "./nullifier-age18-split.js";
import {
  SWIYU_RESIDENCE_SPLIT_DESCRIPTOR,
} from "./residence-split.js";
import {
  parseJsonWithUniqueKeys,
  requireArray,
  requireDecodedString,
  requireObject,
  requireProperty,
  requireUnsignedDecimal,
  type StrictJsonNode,
  type StrictJsonObject,
} from "./strict-json.js";
import type { SwiyuChallenge } from "./types.js";

export const SWIYU_MOBILE_RUNTIME_REQUEST_SCHEMA =
  "swiyu.mobile-runtime-request.v1" as const;
export const SWIYU_MOBILE_RUNTIME_MAX_REQUEST_BYTES = 262_144;

export const SWIYU_MOBILE_EXPERIMENTS = Object.freeze([
  Object.freeze({
    experiment: "age-over-18",
    profile: SWIYU_AGE18_STATUS_PROFILE,
    circuitIds: Object.freeze([SWIYU_AGE18_STATUS_CIRCUIT]),
  }),
  Object.freeze({
    experiment: "canton-membership",
    profile: SWIYU_CANTON_SPLIT_DESCRIPTOR.profile,
    circuitIds: Object.freeze([
      SWIYU_CANTON_SPLIT_DESCRIPTOR.prepareCircuitId,
      SWIYU_CANTON_SPLIT_DESCRIPTOR.showCircuitId,
    ]),
  }),
  Object.freeze({
    experiment: "residence-eligibility",
    profile: SWIYU_RESIDENCE_SPLIT_DESCRIPTOR.profile,
    circuitIds: Object.freeze([
      SWIYU_RESIDENCE_SPLIT_DESCRIPTOR.prepareCircuitId,
      SWIYU_RESIDENCE_SPLIT_DESCRIPTOR.showCircuitId,
    ]),
  }),
  Object.freeze({
    experiment: "one-claim-per-credential",
    profile: SWIYU_NULLIFIER_AGE18_SPLIT_DESCRIPTOR.profile,
    circuitIds: Object.freeze([
      SWIYU_NULLIFIER_AGE18_SPLIT_DESCRIPTOR.prepareCircuitId,
      SWIYU_NULLIFIER_AGE18_SPLIT_DESCRIPTOR.showCircuitId,
    ]),
  }),
]);

export type SwiyuMobileRuntimeJson =
  | string
  | bigint
  | boolean
  | null
  | readonly SwiyuMobileRuntimeJson[]
  | SwiyuMobileRuntimeJsonObject;

export interface SwiyuMobileRuntimeJsonObject {
  readonly [key: string]: SwiyuMobileRuntimeJson;
}

export interface SwiyuMobileRuntimePolicy {
  profile: string;
  circuitIds: readonly string[];
  parameters: SwiyuMobileRuntimeJsonObject;
}

export interface SwiyuMobileRuntimeRequest {
  schema: typeof SWIYU_MOBILE_RUNTIME_REQUEST_SCHEMA;
  credentialId: bigint;
  compactSdJwt: string;
  holderKeyId: string;
  challenge: Readonly<{
    nonce: string;
    clientId: string;
    responseUri: string;
    state: string;
    queryId: string;
    policy: Readonly<SwiyuMobileRuntimePolicy>;
  }>;
}

export type SwiyuMobileTrustedKeyPurpose =
  | "credential-issuer"
  | "status-list-issuer";

export interface SwiyuMobileRuntimeCallbacks {
  /** Return trust-checked, unpadded base64url P-256 affine coordinates. */
  resolveTrustedP256Key(request: Readonly<{
    issuer: string;
    keyId: string;
    purpose: SwiyuMobileTrustedKeyPurpose;
  }>): Promise<Readonly<{ x: string; y: string }>>;
  fetchStatusListJwt(uri: string): Promise<string>;
  /** Return a compact 64-byte P-256 signature (r || s) over the digest. */
  signHolderDigest(holderKeyId: string, digest: Uint8Array): Promise<Uint8Array>;
}

export function parseSwiyuMobileRuntimeRequestJson(
  source: string,
): SwiyuMobileRuntimeRequest {
  if (
    typeof source !== "string"
    || source.length === 0
    || new TextEncoder().encode(source).length > SWIYU_MOBILE_RUNTIME_MAX_REQUEST_BYTES
  ) {
    throw new Error("mobile runtime request size is invalid");
  }
  const root = exactObject(parseJsonWithUniqueKeys(source), "request", [
    "schema",
    "credential_id",
    "compact_sd_jwt",
    "holder_key_id",
    "challenge",
  ]);
  const schema = boundedString(root, "schema", "request", 64);
  if (schema !== SWIYU_MOBILE_RUNTIME_REQUEST_SCHEMA) {
    throw new Error("mobile runtime request schema is unsupported");
  }
  const credentialId = requireUnsignedDecimal(
    property(root, "credential_id"),
    "request.credential_id",
    19,
  ).value;
  if (credentialId > 9_223_372_036_854_775_807n) {
    throw new Error("request.credential_id exceeds a signed 64-bit integer");
  }

  const challengeObject = exactObject(property(root, "challenge"), "request.challenge", [
    "nonce",
    "client_id",
    "response_uri",
    "state",
    "query_id",
    "policy",
  ]);
  const policyObject = exactObject(
    property(challengeObject, "policy"),
    "request.challenge.policy",
    ["profile", "circuit_ids", "parameters"],
  );
  const profile = boundedString(policyObject, "profile", "request.challenge.policy", 128);
  const circuitIds = requireArray(
    property(policyObject, "circuit_ids"),
    "request.challenge.policy.circuit_ids",
  ).items.map((item, index) => boundedNodeString(
    item,
    `request.challenge.policy.circuit_ids[${index}]`,
    128,
  ));
  if (circuitIds.length < 1 || circuitIds.length > 2) {
    throw new Error("request.challenge.policy.circuit_ids length must be in 1..2");
  }
  requireExecutableDescriptor(profile, circuitIds);
  const parametersNode = exactObject(
    property(policyObject, "parameters"),
    "request.challenge.policy.parameters",
    ["cutoff_date", "current_time", "status_list_snapshot"],
  );
  validateExecutableAgeParameters(parametersNode);

  return Object.freeze({
    schema: SWIYU_MOBILE_RUNTIME_REQUEST_SCHEMA,
    credentialId,
    compactSdJwt: boundedString(root, "compact_sd_jwt", "request", 131_072),
    holderKeyId: boundedString(root, "holder_key_id", "request", 4096),
    challenge: Object.freeze({
      nonce: boundedString(challengeObject, "nonce", "request.challenge", 4096),
      clientId: boundedString(challengeObject, "client_id", "request.challenge", 4096),
      responseUri: boundedString(challengeObject, "response_uri", "request.challenge", 4096),
      state: boundedString(challengeObject, "state", "request.challenge", 4096),
      queryId: boundedString(challengeObject, "query_id", "request.challenge", 4096),
      policy: Object.freeze({
        profile,
        circuitIds: Object.freeze(circuitIds),
        parameters: Object.freeze(strictObjectToRecord(parametersNode)),
      }),
    }),
  });
}

export function mobileRuntimeRequestToAgeChallenge(
  request: Readonly<SwiyuMobileRuntimeRequest>,
): SwiyuChallenge {
  const { challenge } = request;
  if (
    challenge.policy.profile !== SWIYU_AGE18_STATUS_PROFILE
    || challenge.policy.circuitIds.length !== 1
    || challenge.policy.circuitIds[0] !== SWIYU_AGE18_STATUS_CIRCUIT
  ) {
    throw new Error("mobile runtime request is not the supported age profile");
  }
  const parameters = challenge.policy.parameters;
  const cutoffDate = parameterString(parameters, "cutoff_date");
  parseSwiyuIsoDate(cutoffDate, "cutoff_date");
  const currentTime = parameterBigint(parameters, "current_time");
  const statusListSnapshot = parameterString(parameters, "status_list_snapshot");
  return Object.freeze({
    nonce: challenge.nonce,
    clientId: challenge.clientId,
    responseUri: challenge.responseUri,
    state: challenge.state,
    queryId: challenge.queryId,
    profile: SWIYU_AGE18_STATUS_PROFILE,
    cutoffDate,
    currentTime,
    statusListSnapshot,
  });
}

export function hashSwiyuMobileRuntimeAgeChallenge(
  request: Readonly<SwiyuMobileRuntimeRequest>,
): Readonly<{ digest: Uint8Array; scalar: bigint }> {
  return hashSwiyuChallenge(mobileRuntimeRequestToAgeChallenge(request));
}

function requireExecutableDescriptor(profile: string, circuitIds: readonly string[]): void {
  if (
    profile !== SWIYU_AGE18_STATUS_PROFILE
    || circuitIds.length !== 1
    || circuitIds[0] !== SWIYU_AGE18_STATUS_CIRCUIT
  ) {
    throw new Error("mobile runtime profile or circuit ids are not executable by this runtime");
  }
}

function validateExecutableAgeParameters(parameters: StrictJsonObject): void {
  const path = "request.challenge.policy.parameters";
  const cutoffDate = boundedString(parameters, "cutoff_date", path, 10);
  parseSwiyuIsoDate(cutoffDate, `${path}.cutoff_date`);

  const currentTime = requireUnsignedDecimal(
    property(parameters, "current_time"),
    `${path}.current_time`,
    19,
  ).value;
  if (currentTime === 0n || currentTime > 9_223_372_036_854_775_807n) {
    throw new Error(`${path}.current_time must fit a positive signed 64-bit integer`);
  }

  const snapshot = boundedString(parameters, "status_list_snapshot", path, 256);
  if (!/^[A-Za-z0-9._~:-]+$/u.test(snapshot)) {
    throw new Error(`${path}.status_list_snapshot is invalid`);
  }
}

function exactObject(node: StrictJsonNode, path: string, keys: readonly string[]): StrictJsonObject {
  const object = requireObject(node, path);
  const expected = new Set(keys);
  for (const key of object.properties.keys()) {
    if (!expected.has(key)) throw new Error(`${path}.${key} is not allowed`);
  }
  for (const key of keys) requireProperty(object, key, path);
  return object;
}

function property(object: StrictJsonObject, key: string): StrictJsonNode {
  return requireProperty(object, key, "object").value;
}

function boundedString(
  object: StrictJsonObject,
  key: string,
  path: string,
  maximumLength: number,
): string {
  return boundedNodeString(property(object, key), `${path}.${key}`, maximumLength);
}

function boundedNodeString(node: StrictJsonNode, path: string, maximumLength: number): string {
  const value = requireDecodedString(node, path).value;
  const length = new TextEncoder().encode(value).length;
  if (length < 1 || length > maximumLength) {
    throw new Error(`${path} UTF-8 length must be in 1..${maximumLength}`);
  }
  return value;
}

function strictObjectToRecord(
  object: StrictJsonObject,
): Record<string, SwiyuMobileRuntimeJson> {
  return Object.fromEntries(
    [...object.properties.entries()].map(([key, entry]) => [key, strictNodeToValue(entry.value)]),
  );
}

function strictNodeToValue(node: StrictJsonNode): SwiyuMobileRuntimeJson {
  if (node.kind === "string") return node.value;
  if (node.kind === "number") return BigInt(node.raw);
  if (node.kind === "literal") return node.value;
  if (node.kind === "array") return Object.freeze(node.items.map(strictNodeToValue));
  return Object.freeze(strictObjectToRecord(node));
}

function parameterString(
  parameters: SwiyuMobileRuntimeJsonObject,
  key: string,
): string {
  const value = parameters[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`mobile runtime policy parameter ${key} must be a string`);
  }
  return value;
}

function parameterBigint(
  parameters: SwiyuMobileRuntimeJsonObject,
  key: string,
): bigint {
  const value = parameters[key];
  if (typeof value !== "bigint" || value < 0n || value >= 1n << 63n) {
    throw new Error(`mobile runtime policy parameter ${key} must fit a signed 64-bit integer`);
  }
  return value;
}

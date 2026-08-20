import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2";
import { FixedIndexStatusTree, type StatusBit } from "../status-designs/fixed-index-merkle.js";
import type { EcdsaPublicKey } from "../types.js";
import { base64urlEncode } from "../utils.js";
import {
  SWIYU_MAX_STATUS_LIST_LENGTH,
  SWIYU_PROFILE_VERSION,
  SWIYU_STRING_SLOT_BYTES,
} from "./constants.js";
import { computeSwiyuStatusProfileCommitment } from "./commitments.js";
import {
  bigEndianBytesToBigInt,
  decodeBase64urlStrict,
  decodeUtf8Strict,
} from "./encoding.js";
import {
  forbidProperty,
  parseStrictCompactJson,
  requireObject,
  requireProperty,
  requireString,
  requireUnsignedDecimal,
} from "./strict-json.js";
import type {
  SwiyuAuthoritativeStatusSnapshot,
  SwiyuPrivateStatusSnapshot,
} from "./types.js";

const encoder = new TextEncoder();
const MAX_STATUS_LIST_BYTES = SWIYU_MAX_STATUS_LIST_LENGTH / 4;

export interface SwiyuStatusListJwtResolutionRequest {
  compactJwt: string;
  /** Trust-checked P-256 issuer key; its kid must equal the protected kid. */
  issuerPublicKey: EcdsaPublicKey;
  expectedIssuer: string;
  /** Private URI from the credential's signed status reference. */
  expectedSubject: string;
  /** Unix seconds at which freshness is evaluated. */
  currentTime: bigint;
  /** Platform adapter that must abort before emitting more than maxOutputBytes. */
  inflateZlib: SwiyuBoundedZlibInflater;
}

export type SwiyuBoundedZlibInflater = (
  compressed: Uint8Array,
  maxOutputBytes: number,
) => Uint8Array;

export interface SwiyuResolvedStatusList {
  /** Wallet-side material. Do not pass this object to the verifier. */
  privateSnapshot: Readonly<SwiyuPrivateStatusSnapshot>;
  /** URI/root-free resolver result suitable for the verifier. */
  authoritativeSnapshot: Readonly<SwiyuAuthoritativeStatusSnapshot>;
  /** Derived fixed-depth tree used to select a private status witness. */
  tree: FixedIndexStatusTree;
}

/**
 * Verify and adapt a Swiss `statuslist+jwt` without accepting a caller-supplied
 * root. The fixed-depth root, commitment, epoch, list length, and freshness are
 * all derived from authenticated JWT bytes.
 */
export function resolveSwiyuStatusListJwt(
  request: SwiyuStatusListJwtResolutionRequest,
): SwiyuResolvedStatusList {
  const parts = request.compactJwt.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new Error("status list JWS must contain exactly three non-empty parts");
  }
  const [b64Header, b64Payload, b64Signature] = parts as [string, string, string];
  const header = requireObject(
    parseStrictCompactJson(
      decodeUtf8Strict(
        decodeBase64urlStrict(b64Header, "status list protected header"),
        "status list protected header",
      ),
    ),
    "status list header",
  );
  const payload = requireObject(
    parseStrictCompactJson(
      decodeUtf8Strict(
        decodeBase64urlStrict(b64Payload, "status list payload"),
        "status list payload",
      ),
    ),
    "status list payload",
  );

  requireExactString(header, "alg", "status list header", "ES256", 5);
  requireExactString(
    header,
    "typ",
    "status list header",
    "statuslist+jwt",
    14,
  );
  requireExactString(
    header,
    "profile_version",
    "status list header",
    SWIYU_PROFILE_VERSION,
    SWIYU_PROFILE_VERSION.length,
  );
  const kid = requireBoundedString(
    header,
    "kid",
    "status list header",
    SWIYU_STRING_SLOT_BYTES,
  );
  forbidProperty(header, "crit", "status list header");
  forbidProperty(header, "b64", "status list header");

  if (
    request.issuerPublicKey.kty !== "EC" ||
    request.issuerPublicKey.crv !== "P-256"
  ) {
    throw new Error("status list issuer key must be a P-256 JWK");
  }
  if (request.issuerPublicKey.kid !== kid) {
    throw new Error("status list issuer key must carry the exact protected kid");
  }
  const issuerPoint = publicPoint(request.issuerPublicKey);
  const signatureBytes = decodeBase64urlStrict(
    b64Signature,
    "status list signature",
    64,
  );
  let signature: ReturnType<typeof p256.Signature.fromCompact>;
  try {
    signature = p256.Signature.fromCompact(signatureBytes);
  } catch (error) {
    throw new Error("status list signature is not a compact P-256 signature", {
      cause: error,
    });
  }
  const signingInput = `${b64Header}.${b64Payload}`;
  if (
    !p256.verify(
      signature.toDERRawBytes(),
      sha256(encoder.encode(signingInput)),
      issuerPoint.toRawBytes(),
    )
  ) {
    throw new Error("status list issuer signature verification failed");
  }

  const issuer = requireBoundedString(
    payload,
    "iss",
    "status list payload",
    SWIYU_STRING_SLOT_BYTES,
  );
  if (issuer !== request.expectedIssuer) {
    throw new Error("status list issuer does not match the expected issuer");
  }
  const subject = requireBoundedString(
    payload,
    "sub",
    "status list payload",
    160,
  );
  if (subject !== request.expectedSubject) {
    throw new Error("status list subject does not match the credential status URI");
  }
  const iat = requireUnsignedDecimal(
    requireProperty(payload, "iat", "status list payload").value,
    "status list payload.iat",
  ).value;
  const exp = requireUnsignedDecimal(
    requireProperty(payload, "exp", "status list payload").value,
    "status list payload.exp",
  ).value;
  const ttl = requireUnsignedDecimal(
    requireProperty(payload, "ttl", "status list payload").value,
    "status list payload.ttl",
  ).value;
  if (ttl === 0n) throw new Error("status list payload.ttl must be positive");
  if (exp < iat) throw new Error("status list payload.exp must not precede iat");
  validateCurrentTime(request.currentTime);
  const validBefore = exp < iat + ttl ? exp : iat + ttl;
  if (request.currentTime < iat) {
    throw new Error("status list token is not yet valid at currentTime");
  }
  if (request.currentTime >= validBefore) {
    throw new Error("status list token is stale at currentTime");
  }

  const statusList = requireObject(
    requireProperty(payload, "status_list", "status list payload").value,
    "status list payload.status_list",
  );
  const bits = requireUnsignedDecimal(
    requireProperty(statusList, "bits", "status list payload.status_list").value,
    "status list payload.status_list.bits",
    1,
  ).value;
  if (bits !== 2n) {
    throw new Error("status list payload.status_list.bits must equal 2");
  }
  const encodedList = requireBoundedString(
    statusList,
    "lst",
    "status list payload.status_list",
    65_536,
  );
  const compressed = decodeBase64urlStrict(encodedList, "status list lst");
  let packed: Uint8Array;
  try {
    packed = request.inflateZlib(compressed, MAX_STATUS_LIST_BYTES);
  } catch (error) {
    throw new Error("status list lst is not a bounded zlib stream", { cause: error });
  }
  if (
    !(packed instanceof Uint8Array) ||
    packed.length === 0 ||
    packed.length > MAX_STATUS_LIST_BYTES
  ) {
    throw new Error(
      `decoded status list must contain 1..${MAX_STATUS_LIST_BYTES} bytes`,
    );
  }
  // The JWT carries no unpadded management length. Its authenticated capacity
  // is therefore exactly four 2-bit entries per decompressed byte.
  const statuses = unpackTwoBitStatuses(packed);
  const epoch = Number(iat);
  if (!Number.isSafeInteger(epoch)) {
    throw new Error("status list iat is too large to derive a safe epoch");
  }
  const tree = FixedIndexStatusTree.buildSwiyuProfile(statuses, epoch);
  const tokenDigest = base64urlEncode(sha256(encoder.encode(request.compactJwt)));
  const privateSnapshot: Readonly<SwiyuPrivateStatusSnapshot> = Object.freeze({
    id: `statuslist-jwt:${tokenDigest}`,
    uri: subject,
    root: tree.root,
    epoch,
    listLength: tree.entryCount,
  });
  const commitment = Object.freeze(
    computeSwiyuStatusProfileCommitment(privateSnapshot),
  );
  const authoritativeSnapshot: Readonly<SwiyuAuthoritativeStatusSnapshot> =
    Object.freeze({
      id: privateSnapshot.id,
      issuer,
      kid,
      subject,
      commitment,
      epoch,
      listLength: tree.entryCount,
      validBefore,
      provenance: `statuslist+jwt#sha256:${tokenDigest}`,
    });
  return Object.freeze({ privateSnapshot, authoritativeSnapshot, tree });
}

function unpackTwoBitStatuses(packed: Uint8Array): StatusBit[] {
  const statuses = Array<StatusBit>(packed.length * 4);
  for (let byteIndex = 0; byteIndex < packed.length; byteIndex += 1) {
    const value = packed[byteIndex]!;
    for (let slot = 0; slot < 4; slot += 1) {
      statuses[byteIndex * 4 + slot] = ((value >> (slot * 2)) & 0x03) as StatusBit;
    }
  }
  return statuses;
}

function publicPoint(
  key: EcdsaPublicKey,
): ReturnType<typeof p256.ProjectivePoint.fromAffine> {
  const x = bigEndianBytesToBigInt(
    decodeBase64urlStrict(key.x, "status list issuer key x", 32),
  );
  const y = bigEndianBytesToBigInt(
    decodeBase64urlStrict(key.y, "status list issuer key y", 32),
  );
  try {
    const point = p256.ProjectivePoint.fromAffine({ x, y });
    point.assertValidity();
    return point;
  } catch (error) {
    throw new Error("status list issuer key is not a valid P-256 point", {
      cause: error,
    });
  }
}

function requireBoundedString(
  object: Parameters<typeof requireProperty>[0],
  key: string,
  path: string,
  maximumLength: number,
): string {
  const value = requireString(requireProperty(object, key, path).value, `${path}.${key}`)
    .value;
  if (value.length === 0 || value.length > maximumLength) {
    throw new Error(`${path}.${key} length must be in 1..${maximumLength}`);
  }
  return value;
}

function requireExactString(
  object: Parameters<typeof requireProperty>[0],
  key: string,
  path: string,
  expected: string,
  maximumLength: number,
): void {
  const value = requireBoundedString(object, key, path, maximumLength);
  if (value !== expected) {
    throw new Error(`${path}.${key} must equal ${expected}`);
  }
}

function validateCurrentTime(value: bigint): void {
  if (typeof value !== "bigint" || value < 0n || value >= 1n << 64n) {
    throw new Error("currentTime must be an unsigned 64-bit bigint");
  }
}

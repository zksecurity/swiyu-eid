import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2";
import {
  TernaryFixedIndexStatusTree,
  type TernaryStatusWitness,
} from "../status-designs/ternary-fixed-index-merkle.js";
import {
  PackedStatusChunkTree,
  type PackedStatusChunkWitness,
} from "../status-designs/packed-status-chunk-merkle.js";
import type { StatusBit } from "../status-designs/fixed-index-merkle.js";
import type { EcdsaPublicKey } from "../types.js";
import { base64urlEncode } from "../utils.js";
import {
  SWIYU_MAX_STATUS_LIST_LENGTH,
  SWIYU_PROFILE_VERSION,
  SWIYU_STRING_SLOT_BYTES,
} from "./constants.js";
import {
  computeSwiyuPreparedStatusCommitment,
  computeSwiyuPreparedStatusUriCommitment,
  type SwiyuHashLimbs,
} from "./commitments.js";
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
import type { SwiyuPrivateStatusSnapshot } from "./types.js";

const encoder = new TextEncoder();
const MAX_STATUS_LIST_BYTES = SWIYU_MAX_STATUS_LIST_LENGTH / 4;
const RESIDENCE_STATUS_CONSTRUCTOR_TOKEN = Symbol("authenticated residence status");
const authenticatedResidenceStatuses = new WeakSet<object>();

export type SwiyuResidenceBoundedZlibInflater = (
  compressed: Uint8Array,
  maxOutputBytes: number,
) => Uint8Array;

export interface SwiyuTernaryStatusListJwtResolutionRequest {
  compactJwt: string;
  /** Trust-checked P-256 status-list issuer key. */
  issuerPublicKey: EcdsaPublicKey;
  expectedIssuer: string;
  /** Private URI authenticated by the residence credential's status reference. */
  expectedSubject: string;
  credentialStatusIndex: number;
  currentTime: bigint;
  inflateZlib: SwiyuResidenceBoundedZlibInflater;
}

/**
 * Verifier-safe result of authenticated status-list resolution. Instances can
 * only be created by an authenticated status-list resolver; URI and root are
 * never properties of this object. The tree profile is explicit for key and
 * circuit routing.
 */
export class SwiyuResidenceVerifierStatus {
  constructor(
    token: typeof RESIDENCE_STATUS_CONSTRUCTOR_TOKEN,
    readonly preparedStatusCommitment: Readonly<SwiyuHashLimbs>,
    readonly tokenId: string,
    readonly issuer: string,
    readonly kid: string,
    readonly epoch: number,
    readonly listLength: number,
    readonly validBefore: bigint,
    readonly provenance: string,
    readonly treeProfile:
      | "fixed-index-status-ternary-merkle-v1"
      | "packed-status-chunk-ternary-merkle-v2",
  ) {
    if (token !== RESIDENCE_STATUS_CONSTRUCTOR_TOKEN) {
      throw new Error("residence verifier status can only be created by the authenticated resolver");
    }
    authenticatedResidenceStatuses.add(this);
    Object.freeze(this);
  }

  static isAuthenticated(value: unknown): value is SwiyuResidenceVerifierStatus {
    return typeof value === "object" && value !== null
      && authenticatedResidenceStatuses.has(value);
  }

  static resolve(
    request: SwiyuTernaryStatusListJwtResolutionRequest,
    treeProfile:
      | "fixed-index-status-ternary-merkle-v1"
      | "packed-status-chunk-ternary-merkle-v2" =
        "fixed-index-status-ternary-merkle-v1",
  ): SwiyuResolvedTernaryStatusList | SwiyuResolvedPackedStatusList {
    const parts = request.compactJwt.split(".");
    if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
      throw new Error("status list JWS must contain exactly three non-empty parts");
    }
    const [b64Header, b64Payload, b64Signature] = parts as [string, string, string];
    const header = requireObject(
      parseStrictCompactJson(decodeUtf8Strict(
        decodeBase64urlStrict(b64Header, "status list protected header"),
        "status list protected header",
      )),
      "status list header",
    );
    const payload = requireObject(
      parseStrictCompactJson(decodeUtf8Strict(
        decodeBase64urlStrict(b64Payload, "status list payload"),
        "status list payload",
      )),
      "status list payload",
    );

    requireExactString(header, "alg", "status list header", "ES256", 5);
    requireExactString(header, "typ", "status list header", "statuslist+jwt", 14);
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
    verifyStatusListSignature(
      request.issuerPublicKey,
      kid,
      `${b64Header}.${b64Payload}`,
      b64Signature,
    );

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
      !(packed instanceof Uint8Array)
      || packed.length === 0
      || packed.length > MAX_STATUS_LIST_BYTES
    ) {
      throw new Error(`decoded status list must contain 1..${MAX_STATUS_LIST_BYTES} bytes`);
    }

    const epoch = Number(iat);
    if (!Number.isSafeInteger(epoch)) {
      throw new Error("status list iat is too large to derive a safe epoch");
    }
    if (
      !Number.isSafeInteger(request.credentialStatusIndex)
      || request.credentialStatusIndex < 0
      || request.credentialStatusIndex >= packed.length * 4
    ) {
      throw new Error("credential status index is outside the authenticated list");
    }
    if (treeProfile === "packed-status-chunk-ternary-merkle-v2") {
      const tree = PackedStatusChunkTree.buildSwiyuProfile(packed, epoch);
      const statusWitness = freezePackedWitness(
        tree.witness(request.credentialStatusIndex),
      );
      if (statusWitness.status !== 0) {
        throw new Error(`credential status is not valid (value ${statusWitness.status})`);
      }
      return buildResolvedStatus(
        tree,
        statusWitness,
        subject,
        issuer,
        kid,
        epoch,
        validBefore,
        request.compactJwt,
        treeProfile,
      );
    }

    // Legacy control: authenticated bytes -> statuses -> per-status ternary
    // leaves. The packed v2 path above never performs this expansion.
    const statuses = unpackTwoBitStatuses(packed);
    const tree = TernaryFixedIndexStatusTree.buildSwiyuProfile(statuses, epoch);
    const statusWitness = freezeWitness(tree.witness(request.credentialStatusIndex));
    if (statusWitness.status !== 0) {
      throw new Error(`credential status is not valid (value ${statusWitness.status})`);
    }

    return buildResolvedStatus(
      tree,
      statusWitness,
      subject,
      issuer,
      kid,
      epoch,
      validBefore,
      request.compactJwt,
      treeProfile,
    );
  }
}

export interface SwiyuResolvedTernaryStatusList {
  /** Wallet-only status URI/root and tree material. */
  privateSnapshot: Readonly<SwiyuPrivateStatusSnapshot>;
  statusWitness: Readonly<TernaryStatusWitness>;
  tree: TernaryFixedIndexStatusTree;
  /** Safe to send to the verifier; contains neither status URI nor root. */
  verifierStatus: SwiyuResidenceVerifierStatus;
}

export interface SwiyuResolvedPackedStatusList {
  /** Wallet-only status URI/root and packed tree material. */
  privateSnapshot: Readonly<SwiyuPrivateStatusSnapshot>;
  statusWitness: Readonly<PackedStatusChunkWitness>;
  tree: PackedStatusChunkTree;
  /** Safe to send to the verifier; contains neither status URI nor root. */
  verifierStatus: SwiyuResidenceVerifierStatus;
}

export function resolveSwiyuTernaryStatusListJwt(
  request: SwiyuTernaryStatusListJwtResolutionRequest,
): SwiyuResolvedTernaryStatusList {
  return SwiyuResidenceVerifierStatus.resolve(
    request,
    "fixed-index-status-ternary-merkle-v1",
  ) as SwiyuResolvedTernaryStatusList;
}

/** Resolve the same authenticated Status List JWT directly into v2 chunks. */
export function resolveSwiyuPackedStatusListJwt(
  request: SwiyuTernaryStatusListJwtResolutionRequest,
): SwiyuResolvedPackedStatusList {
  return SwiyuResidenceVerifierStatus.resolve(
    request,
    "packed-status-chunk-ternary-merkle-v2",
  ) as SwiyuResolvedPackedStatusList;
}

function unpackTwoBitStatuses(packed: Uint8Array): StatusBit[] {
  const statuses = Array<StatusBit>(packed.length * 4);
  for (let byteIndex = 0; byteIndex < packed.length; byteIndex += 1) {
    const value = packed[byteIndex]!;
    for (let slot = 0; slot < 4; slot++) {
      statuses[byteIndex * 4 + slot] = ((value >> (slot * 2)) & 0x03) as StatusBit;
    }
  }
  return statuses;
}

function freezeWitness(witness: TernaryStatusWitness): Readonly<TernaryStatusWitness> {
  return Object.freeze({
    ...witness,
    siblings: Object.freeze(witness.siblings.map((pair) => Object.freeze([...pair]))) as
      TernaryStatusWitness["siblings"],
  });
}

function freezePackedWitness(
  witness: PackedStatusChunkWitness,
): Readonly<PackedStatusChunkWitness> {
  return Object.freeze({
    ...witness,
    chunk: Object.freeze([...witness.chunk]),
    siblings: Object.freeze(witness.siblings.map((pair) => Object.freeze([...pair]))) as
      PackedStatusChunkWitness["siblings"],
  });
}

function buildResolvedStatus<
  Tree extends TernaryFixedIndexStatusTree | PackedStatusChunkTree,
  Witness extends TernaryStatusWitness | PackedStatusChunkWitness,
>(
  tree: Tree,
  statusWitness: Readonly<Witness>,
  subject: string,
  issuer: string,
  kid: string,
  epoch: number,
  validBefore: bigint,
  compactJwt: string,
  treeProfile: SwiyuResidenceVerifierStatus["treeProfile"],
): Readonly<{
  privateSnapshot: Readonly<SwiyuPrivateStatusSnapshot>;
  statusWitness: Readonly<Witness>;
  tree: Tree;
  verifierStatus: SwiyuResidenceVerifierStatus;
}> {
  const tokenDigest = base64urlEncode(sha256(encoder.encode(compactJwt)));
  const tokenId = `statuslist-jwt:${tokenDigest}`;
  const privateSnapshot: Readonly<SwiyuPrivateStatusSnapshot> = Object.freeze({
    id: tokenId,
    uri: subject,
    root: tree.root,
    epoch,
    listLength: tree.entryCount,
  });
  const preparedStatusCommitment = Object.freeze(
    computeSwiyuPreparedStatusCommitment(
      computeSwiyuPreparedStatusUriCommitment(subject),
      tree.root,
    ),
  );
  const verifierStatus = new SwiyuResidenceVerifierStatus(
    RESIDENCE_STATUS_CONSTRUCTOR_TOKEN,
    preparedStatusCommitment,
    tokenId,
    issuer,
    kid,
    epoch,
    tree.entryCount,
    validBefore,
    `statuslist+jwt#sha256:${tokenDigest}`,
    treeProfile,
  );
  return Object.freeze({ privateSnapshot, statusWitness, tree, verifierStatus });
}

function verifyStatusListSignature(
  key: EcdsaPublicKey,
  protectedKid: string,
  signingInput: string,
  encodedSignature: string,
): void {
  if (key.kty !== "EC" || key.crv !== "P-256") {
    throw new Error("status list issuer key must be a P-256 JWK");
  }
  if (key.kid !== protectedKid) {
    throw new Error("status list issuer key must carry the exact protected kid");
  }
  const x = bigEndianBytesToBigInt(
    decodeBase64urlStrict(key.x, "status list issuer key x", 32),
  );
  const y = bigEndianBytesToBigInt(
    decodeBase64urlStrict(key.y, "status list issuer key y", 32),
  );
  let point: ReturnType<typeof p256.ProjectivePoint.fromAffine>;
  try {
    point = p256.ProjectivePoint.fromAffine({ x, y });
    point.assertValidity();
  } catch (error) {
    throw new Error("status list issuer key is not a valid P-256 point", { cause: error });
  }
  const signatureBytes = decodeBase64urlStrict(
    encodedSignature,
    "status list signature",
    64,
  );
  let signature: ReturnType<typeof p256.Signature.fromCompact>;
  try {
    signature = p256.Signature.fromCompact(signatureBytes);
  } catch (error) {
    throw new Error("status list signature is not a compact P-256 signature", { cause: error });
  }
  if (!p256.verify(
    signature.toDERRawBytes(),
    sha256(encoder.encode(signingInput)),
    point.toRawBytes(),
  )) throw new Error("status list issuer signature verification failed");
}

function requireBoundedString(
  object: Parameters<typeof requireProperty>[0],
  key: string,
  path: string,
  maximumLength: number,
): string {
  const value = requireString(requireProperty(object, key, path).value, `${path}.${key}`).value;
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
  if (requireBoundedString(object, key, path, maximumLength) !== expected) {
    throw new Error(`${path}.${key} must equal ${expected}`);
  }
}

function validateCurrentTime(value: bigint): void {
  if (typeof value !== "bigint" || value < 0n || value >= 1n << 64n) {
    throw new Error("currentTime must be an unsigned 64-bit bigint");
  }
}

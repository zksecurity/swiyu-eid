/** Synthetic SD-JWT fixtures — same test keys as openac-sdk/tests/swiyu-zkp/fixture.ts */
import { createHash } from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  FixedIndexStatusTree,
  computeSwiyuStatusProfileCommitment,
} from "../../../../components/zkid/wallet-unit-poc/openac-sdk/dist/swiyu-zkp/index.js";

const SDK_NODE_MODULES = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../components/zkid/wallet-unit-poc/openac-sdk/node_modules",
);
const { p256 } = await import(
  join(SDK_NODE_MODULES, "@noble/curves/nist.js")
);
const { sha256 } = await import(join(SDK_NODE_MODULES, "@noble/hashes/sha2.js"));

export const ISSUER_PRIVATE_KEY = bigintToBytes(
  0x123456789abcdef123456789abcdefn,
  32,
);
export const HOLDER_PRIVATE_KEY = bigintToBytes(
  0xabcdef123456789abcdef123456789n,
  32,
);
export const CHECKED_IN_DID_TDW_KID =
  "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch:api:v1:did#assert-key-01";

function bigintToBytes(value, length) {
  const out = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i -= 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function base64urlEncode(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function publicJwk(privateKey, kid) {
  const point = p256.ProjectivePoint.fromPrivateKey(privateKey).toAffine();
  return {
    kty: "EC",
    crv: "P-256",
    x: base64urlEncode(bigintToBytes(point.x, 32)),
    y: base64urlEncode(bigintToBytes(point.y, 32)),
    ...(kid === undefined ? {} : { kid }),
  };
}

export function signJwt(headerJson, payloadJson, privateKey = ISSUER_PRIVATE_KEY) {
  const header = base64urlEncode(Buffer.from(headerJson, "utf8"));
  const payload = base64urlEncode(Buffer.from(payloadJson, "utf8"));
  const signingInput = `${header}.${payload}`;
  const signature = p256.sign(
    sha256(new TextEncoder().encode(signingInput)),
    privateKey,
  );
  return `${signingInput}.${base64urlEncode(signature.toCompactRawBytes())}`;
}

export function buildCredentialFixture(options = {}) {
  const issuerKid = options.issuerKid ?? CHECKED_IN_DID_TDW_KID;
  const issuerPublicKey = publicJwk(ISSUER_PRIVATE_KEY, issuerKid);
  const holderPublicKey = publicJwk(HOLDER_PRIVATE_KEY);
  const salt = options.disclosureSalt ?? "abcdefghijklmnop";
  const name = options.disclosureName ?? "birthdate";
  const birthdate = options.birthdate ?? "2000-02-29";
  const disclosure = base64urlEncode(
    Buffer.from(JSON.stringify([salt, name, birthdate])),
  );
  const disclosureDigest = base64urlEncode(
    createHash("sha256").update(disclosure).digest(),
  );
  const header = {
    alg: "ES256",
    typ: "dc+sd-jwt",
    kid: issuerKid,
    profile_version: "swiss-profile-vc:1.0.0",
  };
  const payload = {
    iss: options.issuer ?? "did:example:issuer",
    vct: options.vct ?? "https://example.ch/vct/person",
    ...(options.swiyuIssuerShape ? { iat: 1_700_000_000 } : {}),
    nbf: options.nbf ?? 1_700_000_000,
    exp: options.exp ?? 1_800_000_000,
    cnf: { jwk: holderPublicKey },
    status: {
      status_list: {
        uri: "https://status.example.ch/lists/2026-07",
        idx: options.statusIndex ?? 42,
      },
    },
    _sd_alg: "sha-256",
    _sd: [options.digestOverride ?? disclosureDigest],
  };
  const headerJson = JSON.stringify(header);
  const payloadJson = JSON.stringify(payload);
  const jwt = signJwt(headerJson, payloadJson, ISSUER_PRIVATE_KEY);
  return {
    compactSdJwt: `${jwt}~${disclosure}~`,
    issuerPublicKey,
    holderPublicKey,
    holderPrivateKeyHex: bytesToHex(HOLDER_PRIVATE_KEY),
    statusUri: payload.status.status_list.uri,
    statusIndex: payload.status.status_list.idx,
  };
}

export function makeChallenge(snapshotId = "ch-tsl-2026-07-epoch-172") {
  return {
    nonce: "n-7f3f778d0be4474e",
    clientId: "x509_san_dns:verifier.example.ch",
    responseUri: "https://verifier.example.ch/oid4vp/callback",
    state: "state-aaf24c5d",
    queryId: "age-over-18-and-valid-status",
    profile: "swiyu-age18-status-2k-v0",
    cutoffDate: "2007-06-15",
    currentTime: "1750000000",
    statusListSnapshot: snapshotId,
  };
}

export function makeStatus(index = 42) {
  const tree = FixedIndexStatusTree.buildSwiyuProfile(Array(65536).fill(0), 172);
  const snapshot = {
    id: "ch-tsl-2026-07-epoch-172",
    uri: "https://status.example.ch/lists/2026-07",
    root: tree.root,
    epoch: tree.epoch,
    listLength: tree.entryCount,
  };
  const witness = tree.witness(index);
  const commitment = computeSwiyuStatusProfileCommitment(snapshot);
  const authoritativeSnapshot = {
    id: snapshot.id,
    issuer: "did:example:issuer",
    kid: CHECKED_IN_DID_TDW_KID,
    subject: snapshot.uri,
    commitment: {
      hashHi: commitment.hashHi.toString(),
      hashLo: commitment.hashLo.toString(),
    },
    epoch: snapshot.epoch,
    listLength: snapshot.listLength,
    validBefore: "1800000000",
    provenance: "fixture-statuslist+jwt#sha256:fixture",
  };
  return { snapshot, authoritativeSnapshot, witness };
}

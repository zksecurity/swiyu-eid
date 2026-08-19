import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2";
import { SWIYU_AGE18_STATUS_PROFILE } from "../../src/swiyu-zkp/constants.js";
import { FixedIndexStatusTree } from "../../src/status-designs/fixed-index-merkle.js";
import { computeSwiyuStatusProfileCommitment } from "../../src/swiyu-zkp/commitments.js";
import {
  bigintToLittleEndian32,
  concatBytes,
  equalBytes,
} from "../../src/swiyu-zkp/encoding.js";
import type {
  SwiyuChallenge,
  SwiyuCircuitInputs,
  SwiyuDenseStatusWitness,
  SwiyuAuthoritativeStatusSnapshot,
  SwiyuPrivateStatusSnapshot,
  SwiyuProofBackend,
  SwiyuWitnessGenerator,
} from "../../src/swiyu-zkp/types.js";
import {
  base64urlEncode,
  bigintToBytes,
} from "../../src/utils.js";

export const ISSUER_PRIVATE_KEY = bigintToBytes(0x123456789abcdef123456789abcdefn, 32);
export const HOLDER_PRIVATE_KEY = bigintToBytes(0xabcdef123456789abcdef123456789n, 32);
export const CHECKED_IN_DID_TDW_KID =
  "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch:api:v1:did#assert-key-01";

export interface CredentialFixtureOptions {
  birthdate?: string;
  disclosureName?: string;
  disclosureSalt?: string;
  nbf?: number;
  exp?: number;
  statusIndex?: number;
  digestOverride?: string;
  additionalDisclosures?: Array<{
    salt: string;
    name: string;
    value: unknown;
  }>;
  issuerKid?: string;
  swiyuIssuerShape?: boolean;
  vct?: string;
  issuer?: string;
  headerJson?: (canonical: string) => string;
  payloadJson?: (canonical: string) => string;
}

export function buildCredentialFixture(options: CredentialFixtureOptions = {}) {
  const issuerKid = options.issuerKid ?? CHECKED_IN_DID_TDW_KID;
  const issuerPublicKey = publicJwk(ISSUER_PRIVATE_KEY, issuerKid);
  const holderPublicKey = publicJwk(HOLDER_PRIVATE_KEY);
  const salt = options.disclosureSalt ?? "abcdefghijklmnop";
  const name = options.disclosureName ?? "birthdate";
  const birthdate = options.birthdate ?? "2000-02-29";
  const disclosure = base64urlEncode(
    new TextEncoder().encode(JSON.stringify([salt, name, birthdate])),
  );
  const disclosureDigest = base64urlEncode(
    sha256(new TextEncoder().encode(disclosure)),
  );
  const additionalDisclosures = (options.additionalDisclosures ?? []).map(
    ({ salt: additionalSalt, name: additionalName, value }) =>
      base64urlEncode(
        new TextEncoder().encode(
          JSON.stringify([additionalSalt, additionalName, value]),
        ),
      ),
  );
  const additionalDigests = additionalDisclosures.map((encoded) =>
    base64urlEncode(sha256(new TextEncoder().encode(encoded))),
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
    _sd: [options.digestOverride ?? disclosureDigest, ...additionalDigests],
  };
  const canonicalHeader = JSON.stringify(header);
  const canonicalPayload = JSON.stringify(payload);
  const headerJson = options.headerJson?.(canonicalHeader) ?? canonicalHeader;
  const payloadJson = options.payloadJson?.(canonicalPayload) ?? canonicalPayload;
  const jwt = signJwt(headerJson, payloadJson, ISSUER_PRIVATE_KEY);
  return {
    compactSdJwt: `${jwt}~${[disclosure, ...additionalDisclosures].join("~")}~`,
    jwt,
    disclosure,
    disclosureDigest,
    issuerPublicKey,
    holderPublicKey,
    statusUri: payload.status.status_list.uri,
    statusIndex: payload.status.status_list.idx,
  };
}

export function signJwt(
  headerJson: string,
  payloadJson: string,
  privateKey = ISSUER_PRIVATE_KEY,
): string {
  const header = base64urlEncode(new TextEncoder().encode(headerJson));
  const payload = base64urlEncode(new TextEncoder().encode(payloadJson));
  const signingInput = `${header}.${payload}`;
  const signature = p256.sign(
    sha256(new TextEncoder().encode(signingInput)),
    privateKey,
  );
  return `${signingInput}.${base64urlEncode(signature.toCompactRawBytes())}`;
}

export function publicJwk(privateKey: Uint8Array, kid?: string) {
  const point = p256.ProjectivePoint.fromPrivateKey(privateKey).toAffine();
  return {
    kty: "EC" as const,
    crv: "P-256" as const,
    x: base64urlEncode(bigintToBytes(point.x, 32)),
    y: base64urlEncode(bigintToBytes(point.y, 32)),
    ...(kid === undefined ? {} : { kid }),
  };
}

let cachedStatusTree: FixedIndexStatusTree | undefined;

export function makeStatus(
  index = 42,
): {
  snapshot: SwiyuPrivateStatusSnapshot;
  authoritativeSnapshot: SwiyuAuthoritativeStatusSnapshot;
  witness: SwiyuDenseStatusWitness;
} {
  cachedStatusTree ??= FixedIndexStatusTree.buildSwiyuProfile(
    Array<0>(65_536).fill(0),
    172,
  );
  const witness = cachedStatusTree.witness(index);
  const snapshot: SwiyuPrivateStatusSnapshot = {
    id: "ch-tsl-2026-07-epoch-172",
    uri: "https://status.example.ch/lists/2026-07",
    root: cachedStatusTree.root,
    epoch: cachedStatusTree.epoch,
    listLength: cachedStatusTree.entryCount,
  };
  const authoritativeSnapshot: SwiyuAuthoritativeStatusSnapshot = {
    id: snapshot.id,
    issuer: "did:example:issuer",
    kid: CHECKED_IN_DID_TDW_KID,
    subject: snapshot.uri,
    commitment: computeSwiyuStatusProfileCommitment(snapshot),
    epoch: snapshot.epoch,
    listLength: snapshot.listLength,
    validBefore: 1_800_000_000n,
    provenance: "fixture-statuslist+jwt#sha256:fixture",
  };
  return { snapshot, authoritativeSnapshot, witness };
}

export function makeChallenge(
  snapshotId = "ch-tsl-2026-07-epoch-172",
): SwiyuChallenge {
  return {
    nonce: "n-7f3f778d0be4474e",
    clientId: "x509_san_dns:verifier.example.ch",
    responseUri: "https://verifier.example.ch/oid4vp/callback",
    state: "state-aaf24c5d",
    queryId: "age-over-18-and-valid-status",
    profile: SWIYU_AGE18_STATUS_PROFILE,
    cutoffDate: "2007-06-15",
    currentTime: 1_750_000_000n,
    statusListSnapshot: snapshotId,
  };
}

export function holderSigner(privateKey = HOLDER_PRIVATE_KEY) {
  return {
    signChallengeDigest(digest: Uint8Array) {
      return p256.sign(digest, privateKey).toCompactRawBytes();
    },
  };
}

export class RecordingWitnessGenerator implements SwiyuWitnessGenerator {
  inputs?: SwiyuCircuitInputs;

  async calculateSwiyuWitnessWtns(
    inputs: Readonly<SwiyuCircuitInputs>,
  ): Promise<Uint8Array> {
    this.inputs = inputs as SwiyuCircuitInputs;
    return new Uint8Array([0x77, 0x74, 0x6e, 0x73]);
  }
}

/** Test-only binding oracle; production source contains no fake proof backend. */
export class BindingTestBackend implements SwiyuProofBackend {
  constructor(private readonly witnesses: RecordingWitnessGenerator) {}

  async proveFromWitness() {
    if (!this.witnesses.inputs) throw new Error("missing recorded circuit inputs");
    const input = this.witnesses.inputs;
    const scalars = [
      1n,
      input.issuerPubKeyX,
      input.issuerPubKeyY,
      input.challengeHash,
      input.cutoffDate,
      input.currentTime,
      input.expectedMetadataHashHi,
      input.expectedMetadataHashLo,
      input.expectedStatusSnapshotHashHi,
      input.expectedStatusSnapshotHashLo,
    ];
    const publicValues = scalars.map(bigintToLittleEndian32);
    return {
      proof: concatBytes(publicValues),
      publicValues,
    };
  }

  async verify(
    proof: Uint8Array,
    _verifyingKey: Uint8Array,
    expectedPublicContext: Uint8Array,
  ) {
    const valid = equalBytes(proof, expectedPublicContext);
    const publicValues = Array.from({ length: 10 }, (_, index) =>
      proof.slice(index * 32, (index + 1) * 32),
    );
    return {
      valid,
      publicValues,
      error: valid ? undefined : "expected public context mismatch",
    };
  }
}

#!/usr/bin/env node
import { createInterface } from "node:readline";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { assessArtifactReadiness } from "./artifacts.mjs";
import {
  AGE25_CIRCUIT_ID,
  AGE25_PROFILE,
  CIRCUIT_ID,
  PROFILE,
  artifactPaths,
  nativeBackendImportUrl,
  nobleNistImportUrl,
  sdkRootImportUrl,
  sdkImportUrl,
} from "./paths.mjs";
import {
  publicPrepareError,
  rejectsPrivateJwkMaterial,
  validateRequestShape,
} from "./validation.mjs";

const PROTOCOL = "swiyu.provider.v1";
const OPERATIONS = ["initialize", "prepare", "present", "verify", "cleanup"];

/** @type {Map<string, { prepared: object, issuerPublicKey: object, profile: string }>} */
const handles = new Map();

let sdk = null;
let sdkRoot = null;
let nativeBackendModule = null;
let p256 = null;
let witnessCalculator = null;

async function loadSdk() {
  if (!sdk) {
    sdk = await import(sdkImportUrl());
  }
  return sdk;
}

async function loadSdkRoot() {
  if (!sdkRoot) {
    sdkRoot = await import(sdkRootImportUrl());
  }
  return sdkRoot;
}

async function loadNativeBackendModule() {
  if (!nativeBackendModule) {
    nativeBackendModule = await import(nativeBackendImportUrl());
  }
  return nativeBackendModule;
}

async function loadP256() {
  if (!p256) {
    p256 = (await import(nobleNistImportUrl())).p256;
  }
  return p256;
}

function reply(id, status, result, error) {
  const msg = { protocol: PROTOCOL, id, status };
  if (status === "ok") {
    msg.result = result ?? {};
  } else {
    msg.error = error ?? { code: status, message: status };
  }
  process.stdout.write(`${JSON.stringify(msg)}\n`);
}

function operationReadiness() {
  const readiness = assessArtifactReadiness();
  return {
    initialize: { status: "implemented" },
    prepare: {
      status: "implemented",
      coverage: "sdk-parse-precompute",
      note:
        "parses dc+sd-jwt structure and precomputes credential fields; issuer signature and trust are not verified",
    },
    present: {
      status: readiness.available ? "implemented" : "unavailable",
      reason: readiness.available ? undefined : "ARTIFACTS_MISSING",
      detail:
        "creates a swiyu proof envelope using the SDK wallet and native swiyu-profile backend",
      artifactsAvailable: readiness.available,
    },
    verify: {
      status: readiness.available ? "implemented" : "unavailable",
      reason: readiness.available ? undefined : "ARTIFACTS_MISSING",
      detail:
        "verifies a swiyu proof envelope using verifier-provided issuer/status inputs and the native swiyu-profile backend",
      artifactsAvailable: readiness.available,
    },
    cleanup: { status: "implemented" },
  };
}

function badProfile(id, profile) {
  reply(id, "unsupported", undefined, {
    code: "unsupported_profile",
    message: `profile not supported: ${profile}`,
  });
}

function artifactBlock(id, operation) {
  const readiness = assessArtifactReadiness();
  reply(id, "error", undefined, {
    code: "ARTIFACTS_MISSING",
    message: `${operation} requires proving artifacts (explicit env paths)`,
    missing: readiness.missing,
    envRequired: readiness.envRequired,
    buildCommands: readiness.buildCommands,
  });
}

async function handleInitialize(id) {
  const readiness = assessArtifactReadiness();
  const mod = await loadSdk();
  reply(id, "ok", {
    targetProfile: PROFILE,
    profiles: [PROFILE, AGE25_PROFILE],
    circuits: [CIRCUIT_ID, AGE25_CIRCUIT_ID],
    operations: OPERATIONS,
    operationReadiness: operationReadiness(),
    artifacts: {
      available: readiness.available,
      missing: readiness.missing,
      envRequired: readiness.envRequired,
      available_files: readiness.available_files,
      provenance: readiness.provenance,
      buildCommands: readiness.buildCommands,
      note: readiness.note,
    },
    limitations: [
      "requires explicit artifact roots for the swiyu witness wasm, proving key, verifying key, and swiyu-profile binary",
      "holder signing is currently supplied as local runner private key material; callback/key-handle signing remains a later wallet integration step",
      "issuer trust and status snapshot selection remain verifier/runner supplied policy inputs",
      "openac-age25-jwt-v0 is declared for the shared age-25 claim; proving artifacts are not packaged",
    ],
    sdkProfile: mod.SWIYU_AGE18_STATUS_PROFILE,
    sdkCircuit: mod.SWIYU_AGE18_STATUS_CIRCUIT,
  });
}

function requiredObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function requiredString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function requiredSafeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  return value;
}

function parseBigIntValue(value, label) {
  if (typeof value === "bigint") {
    return value;
  }
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    return BigInt(value);
  }
  if (typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value)) {
    return BigInt(value);
  }
  throw new Error(`${label} must be a non-negative integer string or safe integer`);
}

function normalizeChallenge(value) {
  const obj = requiredObject(value, "request_context");
  return {
    nonce: requiredString(obj.nonce, "request_context.nonce"),
    clientId: requiredString(obj.clientId, "request_context.clientId"),
    responseUri: requiredString(obj.responseUri, "request_context.responseUri"),
    state: requiredString(obj.state, "request_context.state"),
    queryId: requiredString(obj.queryId, "request_context.queryId"),
    profile: requiredString(obj.profile, "request_context.profile"),
    cutoffDate: requiredString(obj.cutoffDate, "request_context.cutoffDate"),
    currentTime: parseBigIntValue(obj.currentTime, "request_context.currentTime"),
    statusListSnapshot: requiredString(
      obj.statusListSnapshot,
      "request_context.statusListSnapshot",
    ),
  };
}

function normalizePrivateStatusSnapshot(value) {
  const obj = requiredObject(value, "inputs.statusSnapshot");
  return {
    id: requiredString(obj.id, "inputs.statusSnapshot.id"),
    uri: requiredString(obj.uri, "inputs.statusSnapshot.uri"),
    root: requiredString(obj.root, "inputs.statusSnapshot.root"),
    epoch: requiredSafeInteger(obj.epoch, "inputs.statusSnapshot.epoch"),
    listLength: requiredSafeInteger(
      obj.listLength,
      "inputs.statusSnapshot.listLength",
    ),
  };
}

function normalizeAuthoritativeStatusSnapshot(value) {
  const obj = requiredObject(value, "inputs.statusSnapshot");
  const commitment = requiredObject(
    obj.commitment,
    "inputs.statusSnapshot.commitment",
  );
  return {
    id: requiredString(obj.id, "inputs.statusSnapshot.id"),
    issuer: requiredString(obj.issuer, "inputs.statusSnapshot.issuer"),
    kid: requiredString(obj.kid, "inputs.statusSnapshot.kid"),
    subject: requiredString(obj.subject, "inputs.statusSnapshot.subject"),
    commitment: {
      hashHi: parseBigIntValue(
        commitment.hashHi,
        "inputs.statusSnapshot.commitment.hashHi",
      ),
      hashLo: parseBigIntValue(
        commitment.hashLo,
        "inputs.statusSnapshot.commitment.hashLo",
      ),
    },
    epoch: requiredSafeInteger(obj.epoch, "inputs.statusSnapshot.epoch"),
    listLength: requiredSafeInteger(
      obj.listLength,
      "inputs.statusSnapshot.listLength",
    ),
    validBefore: parseBigIntValue(
      obj.validBefore,
      "inputs.statusSnapshot.validBefore",
    ),
    provenance: requiredString(obj.provenance, "inputs.statusSnapshot.provenance"),
  };
}

function normalizeStatusWitness(value) {
  const obj = requiredObject(value, "inputs.statusWitness");
  if (!Array.isArray(obj.siblings)) {
    throw new Error("inputs.statusWitness.siblings must be an array");
  }
  return {
    design: requiredString(obj.design, "inputs.statusWitness.design"),
    index: requiredSafeInteger(obj.index, "inputs.statusWitness.index"),
    status: requiredSafeInteger(obj.status, "inputs.statusWitness.status"),
    entryCount: requiredSafeInteger(
      obj.entryCount,
      "inputs.statusWitness.entryCount",
    ),
    epoch: requiredSafeInteger(obj.epoch, "inputs.statusWitness.epoch"),
    root: requiredString(obj.root, "inputs.statusWitness.root"),
    siblings: obj.siblings.map((sibling, index) =>
      requiredString(sibling, `inputs.statusWitness.siblings[${index}]`),
    ),
  };
}

function hexToBytes(hex, label) {
  if (typeof hex !== "string" || !/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) {
    throw new Error(`${label} must be even-length hexadecimal`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function holderSignerFromInputs(inputs) {
  const key = hexToBytes(
    requiredString(inputs?.holderPrivateKeyHex, "inputs.holderPrivateKeyHex"),
    "inputs.holderPrivateKeyHex",
  );
  const curve = await loadP256();
  return {
    signChallengeDigest(digest) {
      return curve.sign(digest, key).toCompactRawBytes();
    },
  };
}

function bigintToLittleEndian32(value) {
  if (typeof value !== "bigint" || value < 0n) {
    throw new Error("fake witness public value must be a non-negative bigint");
  }
  const out = new Uint8Array(32);
  let remaining = value;
  for (let index = 0; index < 32; index += 1) {
    out[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  if (remaining !== 0n) {
    throw new Error("fake witness public value exceeds 32 bytes");
  }
  return out;
}

function fakePublicContextWitness(inputs) {
  const scalars = [
    1n,
    inputs.issuerPubKeyX,
    inputs.issuerPubKeyY,
    inputs.challengeHash,
    inputs.cutoffDate,
    inputs.currentTime,
    inputs.expectedMetadataHashHi,
    inputs.expectedMetadataHashLo,
    inputs.expectedStatusSnapshotHashHi,
    inputs.expectedStatusSnapshotHashLo,
  ];
  const out = new Uint8Array(32 * scalars.length);
  scalars.forEach((scalar, index) => out.set(bigintToLittleEndian32(scalar), index * 32));
  return out;
}

async function proofBackend() {
  const readiness = assessArtifactReadiness();
  if (!readiness.available) {
    throw new Error("native swiyu artifacts are missing");
  }
  const paths = artifactPaths();
  const { NativeNodeSwiyuProofBackend } = await loadNativeBackendModule();
  return new NativeNodeSwiyuProofBackend({
    binaryPath: paths.nativeBinary,
    cwd: paths.keysRoot,
    tempRoot: process.env.SWIYU_OPENAC_TEMP_ROOT,
  });
}

async function swiyuWitnessGenerator() {
  if (process.env.SWIYU_OPENAC_TEST_FAKE_WITNESS === "1") {
    return {
      async calculateSwiyuWitnessWtns(inputs) {
        return fakePublicContextWitness(inputs);
      },
    };
  }
  if (!witnessCalculator) {
    const paths = artifactPaths();
    const mod = await loadSdkRoot();
    witnessCalculator = new mod.WitnessCalculator(join(paths.artifactRoot, "assets"));
    await witnessCalculator.init();
  }
  return witnessCalculator;
}

function measuredWitnessGenerator(generator, sizes) {
  return {
    async calculateSwiyuWitnessWtns(inputs) {
      const witness = await generator.calculateSwiyuWitnessWtns(inputs);
      sizes.witness = witness?.byteLength ?? witness?.length;
      return witness;
    },
  };
}

function measuredProofBackend(backend, sizes) {
  return {
    async proveFromWitness(provingKey, witness) {
      sizes.witness = witness?.byteLength ?? witness?.length;
      const result = await backend.proveFromWitness(provingKey, witness);
      sizes.proof = result.proof?.byteLength ?? result.proof?.length;
      return result;
    },
    async verify(proof, verifyingKey, expectedPublicContext) {
      return backend.verify(proof, verifyingKey, expectedPublicContext);
    },
  };
}

function encodePresentation(envelope) {
  return Buffer.from(JSON.stringify(envelope), "utf8").toString("base64url");
}

function decodePresentation(value) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("presentation must be a non-empty opaque string");
  }
  try {
    return JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
  } catch (error) {
    throw new Error("presentation could not be decoded as a swiyu proof envelope");
  }
}

function age25NotPackaged(id, operation) {
  reply(id, "unsupported", undefined, {
    code: "unsupported_profile",
    message: `${operation} for ${AGE25_PROFILE} is circuit-source only until witness WASM and proving keys are packaged`,
    circuit: AGE25_CIRCUIT_ID,
    claim: "swiyu.shared.age25-holder-challenge.v0",
  });
}

async function handlePrepare(id, payload) {
  const profile = payload?.profile;
  if (profile === AGE25_PROFILE) {
    age25NotPackaged(id, "prepare");
    return;
  }
  if (profile !== PROFILE) {
    badProfile(id, profile);
    return;
  }
  const cred = payload?.credential;
  if (cred?.format !== "dc+sd-jwt" || typeof cred?.data !== "string" || !cred.data) {
    reply(id, "error", undefined, {
      code: "bad_credential",
      message: "credential must be dc+sd-jwt with non-empty data",
    });
    return;
  }
  const issuerPublicKey = payload?.context?.issuerPublicKey;
  if (!issuerPublicKey || typeof issuerPublicKey !== "object") {
    reply(id, "error", undefined, {
      code: "bad_credential",
      message: "context.issuerPublicKey (P-256 JWK) is required",
    });
    return;
  }
  if (rejectsPrivateJwkMaterial(issuerPublicKey)) {
    reply(id, "error", undefined, {
      code: "bad_credential",
      message: "issuerPublicKey must not include private JWK field d",
    });
    return;
  }
  const mod = await loadSdk();
  try {
    const prepared = mod.prepareSwiyuCredential({
      compactSdJwt: cred.data,
      issuerPublicKey,
    });
    const handle = randomUUID();
    handles.set(handle, { prepared, issuerPublicKey, profile });
    reply(id, "ok", {
      handle,
      metadata: {
        profile: prepared.profile,
        circuitId: prepared.circuitId,
        stage: "parsed",
        coverage: "sdk-parse-precompute",
        note:
          "SDK prepare parses/precomputes credential fields only; issuer signature/trust not verified; no ZK proof emitted",
      },
    });
  } catch (err) {
    reply(id, "error", undefined, publicPrepareError(err));
  }
}

async function handlePresent(id, payload) {
  const profile = payload?.profile;
  if (profile === AGE25_PROFILE) {
    age25NotPackaged(id, "present");
    return;
  }
  if (profile !== PROFILE) {
    badProfile(id, profile);
    return;
  }
  const state = handles.get(payload?.handle);
  if (!state) {
    reply(id, "error", undefined, {
      code: "bad_handle",
      message: "unknown or stale handle",
    });
    return;
  }
  const readiness = assessArtifactReadiness();
  if (!readiness.available) {
    artifactBlock(id, "present");
    return;
  }
  try {
    const mod = await loadSdk();
    const artifactSizes = {};
    const backend = measuredProofBackend(await proofBackend(), artifactSizes);
    const wallet = new mod.SwiyuZkpWallet({
      witnessGenerator: measuredWitnessGenerator(
        await swiyuWitnessGenerator(),
        artifactSizes,
      ),
      proofBackend: backend,
    });
    const envelope = await wallet.show({
      prepared: state.prepared,
      challenge: normalizeChallenge(payload?.request_context),
      holderSigner: await holderSignerFromInputs(payload?.inputs ?? {}),
      statusSnapshot: normalizePrivateStatusSnapshot(payload?.inputs?.statusSnapshot),
      statusWitness: normalizeStatusWitness(payload?.inputs?.statusWitness),
      provingKey: { kind: "local-file", path: artifactPaths().provingKey },
    });
    reply(id, "ok", {
      presentation: encodePresentation(envelope),
      artifact_sizes: {
        witness: artifactSizes.witness,
        proof: artifactSizes.proof,
      },
      public_outputs: {
        profile: envelope.profile,
        circuit_id: envelope.circuitId,
        issuer: envelope.lookup.issuer,
        kid: envelope.lookup.kid,
        vct: envelope.lookup.vct,
      },
    });
  } catch (err) {
    reply(id, "error", undefined, {
      code: String(err?.message ?? "").includes("holderPrivateKeyHex")
        ? "bad_inputs"
        : "present_failed",
      message: err instanceof Error ? err.message : String(err),
    });
  }
}

async function handleVerify(id, payload) {
  const profile = payload?.profile;
  if (profile === AGE25_PROFILE) {
    age25NotPackaged(id, "verify");
    return;
  }
  if (profile !== PROFILE) {
    badProfile(id, profile);
    return;
  }
  const readiness = assessArtifactReadiness();
  if (!readiness.available) {
    artifactBlock(id, "verify");
    return;
  }
  let envelope;
  try {
    envelope = decodePresentation(payload?.presentation);
  } catch (err) {
    reply(id, "error", undefined, {
      code: "bad_presentation",
      message: err instanceof Error ? err.message : String(err),
    });
    return;
  }
  try {
    const mod = await loadSdk();
    const verifier = new mod.SwiyuZkpVerifier(await proofBackend());
    const result = await verifier.verify({
      envelope,
      challenge: normalizeChallenge(payload?.request_context),
      issuerPublicKey: requiredObject(
        payload?.inputs?.issuerPublicKey,
        "inputs.issuerPublicKey",
      ),
      statusSnapshot: normalizeAuthoritativeStatusSnapshot(
        payload?.inputs?.statusSnapshot,
      ),
      verifyingKey: { kind: "local-file", path: artifactPaths().verifyingKey },
    });
    reply(id, "ok", {
      verified: result.valid,
      reason: result.valid ? null : result.error ?? "proof verification failed",
      profile: envelope.profile,
      circuit_id: envelope.circuitId,
    });
  } catch (err) {
    reply(id, "error", undefined, {
      code: "verify_failed",
      message: err instanceof Error ? err.message : String(err),
    });
  }
}

function handleCleanup(id) {
  handles.clear();
  reply(id, "ok", {});
}

async function dispatch(req) {
  const shape = validateRequestShape(req);
  if (!shape.ok) {
    reply(shape.id, "error", undefined, shape.error);
    return;
  }
  const { id, operation, payload } = shape;
  if (req?.protocol !== PROTOCOL) {
    reply(id, "error", undefined, {
      code: "bad_protocol",
      message: `expected protocol ${PROTOCOL}`,
    });
    return;
  }
  switch (operation) {
    case "initialize":
      await handleInitialize(id);
      break;
    case "prepare":
      await handlePrepare(id, payload);
      break;
    case "present":
      await handlePresent(id, payload);
      break;
    case "verify":
      await handleVerify(id, payload);
      break;
    case "cleanup":
      handleCleanup(id);
      break;
    default:
      reply(id, "unsupported", undefined, {
        code: "unknown_operation",
        message: String(operation),
      });
  }
}

async function main() {
  const rl = createInterface({ input: process.stdin, terminal: false });
  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }
    let req;
    try {
      req = JSON.parse(trimmed);
    } catch {
      reply("", "error", undefined, {
        code: "malformed_request",
        message: "request line is not valid JSON",
      });
      continue;
    }
    try {
      await dispatch(req);
    } catch (err) {
      reply(typeof req?.id === "string" ? req.id : "", "error", undefined, {
        code: "internal_error",
        message: err?.message ?? String(err),
      });
    }
  }
}

main();

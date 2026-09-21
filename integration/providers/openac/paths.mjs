import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const PROVIDER_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(PROVIDER_DIR, "../../..");
const SDK_ROOT = join(REPO_ROOT, "components/zkid/wallet-unit-poc/openac-sdk");
const SDK_ENTRY = join(SDK_ROOT, "dist/index.js");
const SDK_SWIYU = join(SDK_ROOT, "dist/swiyu-zkp/index.js");
const SDK_NATIVE_BACKEND = join(SDK_ROOT, "dist/swiyu-zkp/native-backend-node.js");
const SDK_NOBLE_NIST = join(SDK_ROOT, "node_modules/@noble/curves/nist.js");

export const PROFILE = "swiyu-age18-status-2k-v0";
export const CIRCUIT_ID = "swiyu_age18_status_2k";
export const AGE25_PROFILE = "openac-age25-jwt-v0";
export const AGE25_CIRCUIT_ID = "swiyu_age25_jwt";

function envRoot(name) {
  const value = process.env[name];
  return value ? resolve(value) : null;
}

export function artifactPaths() {
  const artifactRoot = envRoot("SWIYU_OPENAC_ARTIFACT_ROOT");
  const keysRoot = envRoot("SWIYU_OPENAC_KEYS_ROOT");
  const witnessWasm = artifactRoot
    ? join(artifactRoot, "assets/swiyu_age18_status_2k.wasm")
    : null;
  const provingKey = keysRoot
    ? join(keysRoot, "keys/swiyu_age18_status_2k_proving.key")
    : null;
  const verifyingKey = keysRoot
    ? join(keysRoot, "keys/swiyu_age18_status_2k_verifying.key")
    : null;
  const nativeBinary = keysRoot
    ? join(keysRoot, "target/release/swiyu-profile")
    : null;
  return {
    artifactRoot,
    keysRoot,
    witnessWasm,
    provingKey,
    verifyingKey,
    nativeBinary,
    sdkRoot: SDK_ROOT,
    sdkEntry: SDK_ENTRY,
    sdkSwiyu: SDK_SWIYU,
    providerDir: PROVIDER_DIR,
    repoRoot: REPO_ROOT,
  };
}

export function sdkRootImportUrl() {
  const paths = artifactPaths();
  if (!existsSync(paths.sdkEntry)) {
    throw new Error(`openac-sdk dist missing: ${paths.sdkEntry}`);
  }
  return paths.sdkEntry;
}

export function sdkImportUrl() {
  const paths = artifactPaths();
  if (!existsSync(paths.sdkSwiyu)) {
    throw new Error(`openac-sdk dist missing: ${paths.sdkSwiyu}`);
  }
  return paths.sdkSwiyu;
}

export function nativeBackendImportUrl() {
  if (!existsSync(SDK_NATIVE_BACKEND)) {
    throw new Error(`openac-sdk native backend dist missing: ${SDK_NATIVE_BACKEND}`);
  }
  return SDK_NATIVE_BACKEND;
}

export function nobleNistImportUrl() {
  if (!existsSync(SDK_NOBLE_NIST)) {
    throw new Error(`openac-sdk noble dependency missing: ${SDK_NOBLE_NIST}`);
  }
  return SDK_NOBLE_NIST;
}

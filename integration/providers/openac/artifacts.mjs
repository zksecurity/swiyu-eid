import { accessSync, constants, existsSync, statSync } from "node:fs";
import { artifactPaths } from "./paths.mjs";

function fileMeta(path, { executable = false } = {}) {
  if (!path || !existsSync(path)) {
    return { path, present: false };
  }
  const st = statSync(path);
  if (!st.isFile() || st.size === 0) {
    return {
      path,
      present: false,
      invalid: true,
      reason: st.isFile() ? "empty_file" : "not_a_regular_file",
    };
  }
  if (executable) {
    try {
      accessSync(path, constants.X_OK);
    } catch {
      return {
        path,
        present: false,
        invalid: true,
        reason: "not_executable",
      };
    }
  }
  return { path, present: true, sizeBytes: st.size, mtimeMs: st.mtimeMs };
}

export const BUILD_COMMANDS = [
  "cd components/zkid/wallet-unit-poc/circom && npm run compile:swiyu",
  "cd components/zkid/wallet-unit-poc/openac-sdk && npm run build:wasm",
  "cd components/zkid/wallet-unit-poc/ecdsa-spartan2 && cargo build --release --bin swiyu-profile",
  "cd components/zkid/wallet-unit-poc/ecdsa-spartan2 && cargo run --release --bin swiyu-profile -- setup <OUT_DIR>",
];

export function assessArtifactReadiness() {
  const paths = artifactPaths();
  const required = {
    witnessWasm: { path: paths.witnessWasm, executable: false },
    provingKey: { path: paths.provingKey, executable: false },
    verifyingKey: { path: paths.verifyingKey, executable: false },
    nativeBinary: { path: paths.nativeBinary, executable: true },
  };
  const available_files = Object.fromEntries(
    Object.entries(required).map(([name, spec]) => [
      name,
      fileMeta(spec.path, { executable: spec.executable }),
    ]),
  );
  const missing = Object.entries(available_files)
    .filter(([, meta]) => !meta.present)
    .map(([name]) => name);
  const envRequired = [];
  if (!paths.artifactRoot) {
    envRequired.push("SWIYU_OPENAC_ARTIFACT_ROOT");
  }
  if (!paths.keysRoot) {
    envRequired.push("SWIYU_OPENAC_KEYS_ROOT");
  }
  return {
    available: missing.length === 0 && envRequired.length === 0,
    missing,
    available_files,
    envRequired,
    buildCommands: BUILD_COMMANDS,
    provenance: "available_files reports on-disk presence only; cryptographic readiness not verified",
    note:
      "Set SWIYU_OPENAC_ARTIFACT_ROOT (witness wasm tree) and SWIYU_OPENAC_KEYS_ROOT (ecdsa-spartan2 tree with keys/ and target/release/swiyu-profile)",
  };
}

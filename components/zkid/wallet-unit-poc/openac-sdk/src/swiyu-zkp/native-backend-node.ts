import { spawn } from "node:child_process";
import {
  chmod,
  lstat,
  mkdtemp,
  readFile,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, normalize } from "node:path";
import {
  SWIYU_AGE18_STATUS_CIRCUIT,
  SWIYU_AGE18_STATUS_PROFILE,
} from "./constants.js";
import type {
  SwiyuBackendVerification,
  SwiyuKeyMaterial,
  SwiyuProofBackend,
  SwiyuProveResult,
} from "./types.js";

const PROVING_KEY_NAME = "swiyu_age18_status_2k_proving.key";
const VERIFYING_KEY_NAME = "swiyu_age18_status_2k_verifying.key";
const PROOF_NAME = "swiyu_age18_status_2k.proof";
const CONTEXT_NAME = "swiyu_age18_status_2k.public-context";
const WITNESS_NAME = "swiyu_age18_status_2k.wtns";
const PUBLIC_VALUE_COUNT = 10;
const SCALAR_BYTES = 32;
const PUBLIC_CONTEXT_BYTES = PUBLIC_VALUE_COUNT * SCALAR_BYTES;
const DEFAULT_PROVE_TIMEOUT_MS = 60 * 60_000;
const DEFAULT_VERIFY_TIMEOUT_MS = 10 * 60_000;
const DEFAULT_MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024;
const DEFAULT_MAX_PROOF_BYTES = 512 * 1024 * 1024;

export type SwiyuNativeCommandTermination =
  | "completed"
  | "timeout"
  | "output-limit";

export interface SwiyuNativeCommandRequest {
  readonly executable: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
}

export interface SwiyuNativeCommandResult {
  readonly exitCode: number | null;
  readonly signal: string | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly termination: SwiyuNativeCommandTermination;
}

/** Narrow injection seam used by tests; production defaults to `spawn` without a shell. */
export interface SwiyuNativeCommandRunner {
  run(request: Readonly<SwiyuNativeCommandRequest>): Promise<SwiyuNativeCommandResult>;
}

export interface NativeNodeSwiyuProofBackendOptions {
  /** Absolute path to the prebuilt `swiyu-profile` binary. */
  readonly binaryPath: string;
  /** Absolute ecdsa-spartan2 directory used as the command working directory. */
  readonly cwd: string;
  /** Existing absolute directory in which private per-call directories are created. */
  readonly tempRoot?: string;
  readonly proveTimeoutMs?: number;
  readonly verifyTimeoutMs?: number;
  readonly maxCommandOutputBytes?: number;
  readonly maxProofBytes?: number;
  readonly commandRunner?: SwiyuNativeCommandRunner;
}

/**
 * Node-only adapter for the fixed-profile Rust CLI.
 *
 * Each operation gets a mode-0700 directory. Large keys are symlinked into
 * that directory under the CLI's fixed filename, never copied into JS memory.
 */
export class NativeNodeSwiyuProofBackend implements SwiyuProofBackend {
  private readonly binaryPath: string;
  private readonly cwd: string;
  private readonly tempRoot: string;
  private readonly proveTimeoutMs: number;
  private readonly verifyTimeoutMs: number;
  private readonly maxCommandOutputBytes: number;
  private readonly maxProofBytes: number;
  private readonly commandRunner: SwiyuNativeCommandRunner;

  constructor(options: NativeNodeSwiyuProofBackendOptions) {
    if (!options || typeof options !== "object") {
      throw new TypeError("native swiyu backend options are required");
    }
    this.binaryPath = requireAbsoluteNormalizedPath(
      options.binaryPath,
      "swiyu-profile binary",
    );
    this.cwd = requireAbsoluteNormalizedPath(options.cwd, "command cwd");
    this.tempRoot = requireAbsoluteNormalizedPath(
      options.tempRoot ?? tmpdir(),
      "temporary directory root",
    );
    this.proveTimeoutMs = positiveInteger(
      options.proveTimeoutMs ?? DEFAULT_PROVE_TIMEOUT_MS,
      "prove timeout",
    );
    this.verifyTimeoutMs = positiveInteger(
      options.verifyTimeoutMs ?? DEFAULT_VERIFY_TIMEOUT_MS,
      "verify timeout",
    );
    this.maxCommandOutputBytes = positiveInteger(
      options.maxCommandOutputBytes ?? DEFAULT_MAX_COMMAND_OUTPUT_BYTES,
      "maximum command output",
    );
    this.maxProofBytes = positiveInteger(
      options.maxProofBytes ?? DEFAULT_MAX_PROOF_BYTES,
      "maximum proof size",
    );
    this.commandRunner = options.commandRunner ?? new SpawnCommandRunner();
  }

  async proveFromWitness(
    provingKey: SwiyuKeyMaterial,
    witness: Uint8Array,
  ): Promise<SwiyuProveResult> {
    const keyPath = await resolveLocalKey(provingKey, "proving key");
    const witnessBytes = requireNonEmptyBytes(witness, "witness");

    return this.withWorkspace(async (workspace) => {
      const witnessPath = join(workspace, WITNESS_NAME);
      await Promise.all([
        symlink(keyPath, join(workspace, PROVING_KEY_NAME), "file"),
        writePrivateFile(witnessPath, witnessBytes),
      ]);

      const result = await this.commandRunner.run({
        executable: this.binaryPath,
        args: ["prove", witnessPath, workspace],
        cwd: this.cwd,
        timeoutMs: this.proveTimeoutMs,
        maxOutputBytes: this.maxCommandOutputBytes,
      });
      assertSuccessfulCommand(result, "swiyu native prove");

      const [proof, context] = await Promise.all([
        readRegularFileBounded(
          join(workspace, PROOF_NAME),
          this.maxProofBytes,
          "proof",
        ),
        readRegularFileExact(
          join(workspace, CONTEXT_NAME),
          PUBLIC_CONTEXT_BYTES,
          "public context",
        ),
      ]);
      assertProveOutput(result.stdout, proof.length, context.length);

      return {
        proof,
        publicValues: parsePublicValues(context),
      };
    });
  }

  async verify(
    proof: Uint8Array,
    verifyingKey: SwiyuKeyMaterial,
    expectedPublicContext: Uint8Array,
  ): Promise<SwiyuBackendVerification> {
    const keyPath = await resolveLocalKey(verifyingKey, "verifying key");
    const proofBytes = requireNonEmptyBytes(proof, "proof");
    if (proofBytes.length > this.maxProofBytes) {
      throw new Error(`proof exceeds ${this.maxProofBytes} bytes`);
    }
    const expected = requirePublicContext(expectedPublicContext);
    const publicValues = parsePublicValues(expected);

    return this.withWorkspace(async (workspace) => {
      await Promise.all([
        symlink(keyPath, join(workspace, VERIFYING_KEY_NAME), "file"),
        writePrivateFile(join(workspace, PROOF_NAME), proofBytes),
        writePrivateFile(join(workspace, CONTEXT_NAME), expected),
      ]);

      const result = await this.commandRunner.run({
        executable: this.binaryPath,
        args: ["verify", workspace],
        cwd: this.cwd,
        timeoutMs: this.verifyTimeoutMs,
        maxOutputBytes: this.maxCommandOutputBytes,
      });
      const failure = commandFailure(result, "swiyu native verify");
      if (failure !== undefined) {
        return { valid: false, publicValues: [], error: failure };
      }
      if (!isExactVerifyOutput(result.stdout)) {
        return {
          valid: false,
          publicValues: [],
          error: "swiyu native verify returned malformed success output",
        };
      }

      const storedContext = await readRegularFileExact(
        join(workspace, CONTEXT_NAME),
        PUBLIC_CONTEXT_BYTES,
        "public context",
      );
      if (!equalBytes(storedContext, expected)) {
        return {
          valid: false,
          publicValues: [],
          error: "swiyu native verify changed the expected public context",
        };
      }
      return { valid: true, publicValues };
    });
  }

  private async withWorkspace<T>(operation: (workspace: string) => Promise<T>): Promise<T> {
    const workspace = await mkdtemp(join(this.tempRoot, "swiyu-native-"));
    try {
      await chmod(workspace, 0o700);
      return await operation(workspace);
    } finally {
      await rm(workspace, { recursive: true, force: true, maxRetries: 3 });
    }
  }
}

class SpawnCommandRunner implements SwiyuNativeCommandRunner {
  run(request: Readonly<SwiyuNativeCommandRequest>): Promise<SwiyuNativeCommandResult> {
    return new Promise((resolve, reject) => {
      const child = spawn(request.executable, [...request.args], {
        cwd: request.cwd,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      });
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let capturedBytes = 0;
      let termination: SwiyuNativeCommandTermination = "completed";
      let settled = false;

      const terminate = (reason: Exclude<SwiyuNativeCommandTermination, "completed">) => {
        if (termination !== "completed") return;
        termination = reason;
        child.kill("SIGKILL");
      };
      const capture = (destination: Buffer[], chunk: Buffer | string) => {
        if (termination !== "completed") return;
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        const remaining = request.maxOutputBytes - capturedBytes;
        if (remaining > 0) destination.push(bytes.subarray(0, remaining));
        capturedBytes += Math.min(bytes.length, Math.max(remaining, 0));
        if (bytes.length > remaining) terminate("output-limit");
      };

      child.stdout.on("data", (chunk: Buffer | string) => capture(stdout, chunk));
      child.stderr.on("data", (chunk: Buffer | string) => capture(stderr, chunk));
      const timer = setTimeout(() => terminate("timeout"), request.timeoutMs);

      child.once("error", (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(error);
      });
      child.once("close", (exitCode, signal) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve({
          exitCode,
          signal,
          stdout: Buffer.concat(stdout).toString("utf8"),
          stderr: Buffer.concat(stderr).toString("utf8"),
          termination,
        });
      });
    });
  }
}

async function resolveLocalKey(
  material: SwiyuKeyMaterial,
  label: string,
): Promise<string> {
  if (
    material instanceof Uint8Array ||
    material === null ||
    typeof material !== "object" ||
    material.kind !== "local-file"
  ) {
    throw new TypeError(
      `native swiyu ${label} must be a { kind: "local-file", path } reference`,
    );
  }
  const lexicalPath = requireAbsoluteNormalizedPath(material.path, label);
  const canonicalPath = await realpath(lexicalPath);
  const metadata = await stat(canonicalPath);
  if (!metadata.isFile() || metadata.size <= 0) {
    throw new Error(`native swiyu ${label} must reference a non-empty regular file`);
  }
  return canonicalPath;
}

function requireAbsoluteNormalizedPath(value: unknown, label: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.includes("\0") ||
    !isAbsolute(value) ||
    normalize(value) !== value
  ) {
    throw new TypeError(`${label} must be an absolute normalized local path`);
  }
  return value;
}

function positiveInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${label} must be a positive safe integer`);
  }
  return value;
}

function requireNonEmptyBytes(value: Uint8Array, label: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length === 0) {
    throw new TypeError(`${label} must be a non-empty Uint8Array`);
  }
  return value;
}

function requirePublicContext(value: Uint8Array): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== PUBLIC_CONTEXT_BYTES) {
    throw new TypeError(
      `expected public context must contain exactly ${PUBLIC_CONTEXT_BYTES} bytes`,
    );
  }
  return new Uint8Array(value);
}

async function writePrivateFile(path: string, bytes: Uint8Array): Promise<void> {
  await writeFile(path, bytes, { flag: "wx", mode: 0o600 });
}

async function readRegularFileBounded(
  path: string,
  maximumBytes: number,
  label: string,
): Promise<Uint8Array> {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.size <= 0 || metadata.size > maximumBytes) {
    throw new Error(
      `${label} must be a non-empty regular file no larger than ${maximumBytes} bytes`,
    );
  }
  const bytes = await readFile(path);
  if (bytes.length !== metadata.size) {
    throw new Error(`${label} changed while it was being read`);
  }
  return new Uint8Array(bytes);
}

async function readRegularFileExact(
  path: string,
  expectedBytes: number,
  label: string,
): Promise<Uint8Array> {
  const bytes = await readRegularFileBounded(path, expectedBytes, label);
  if (bytes.length !== expectedBytes) {
    throw new Error(`${label} must contain exactly ${expectedBytes} bytes`);
  }
  return bytes;
}

function parsePublicValues(context: Uint8Array): Uint8Array[] {
  if (context.length !== PUBLIC_CONTEXT_BYTES) {
    throw new Error(`public context must contain exactly ${PUBLIC_CONTEXT_BYTES} bytes`);
  }
  return Array.from({ length: PUBLIC_VALUE_COUNT }, (_, index) =>
    context.slice(index * SCALAR_BYTES, (index + 1) * SCALAR_BYTES),
  );
}

function assertSuccessfulCommand(
  result: Readonly<SwiyuNativeCommandResult>,
  label: string,
): void {
  const failure = commandFailure(result, label);
  if (failure !== undefined) throw new Error(failure);
}

function commandFailure(
  result: Readonly<SwiyuNativeCommandResult>,
  label: string,
): string | undefined {
  if (result.termination === "timeout") return `${label} timed out`;
  if (result.termination === "output-limit") {
    return `${label} exceeded the configured output limit`;
  }
  if (result.termination !== "completed") {
    return `${label} returned an invalid command termination state`;
  }
  if (result.exitCode !== 0 || result.signal !== null) {
    const detail = boundedDiagnostic(result.stderr || result.stdout);
    return `${label} failed (exit ${result.exitCode ?? "none"}${
      result.signal === null ? "" : `, signal ${result.signal}`
    })${detail.length === 0 ? "" : `: ${detail}`}`;
  }
  return undefined;
}

function boundedDiagnostic(value: string): string {
  return value.replace(/\s+/g, " ").trim().slice(0, 512);
}

function assertProveOutput(
  stdout: string,
  proofBytes: number,
  contextBytes: number,
): void {
  const match = /^proof_bytes=(\d+) context_bytes=(\d+)$/.exec(stdout.trim());
  if (
    match === null ||
    Number(match[1]) !== proofBytes ||
    Number(match[2]) !== contextBytes
  ) {
    throw new Error("swiyu native prove returned malformed or inconsistent output");
  }
}

function isExactVerifyOutput(stdout: string): boolean {
  return (
    stdout.trim() ===
    `verified profile=${SWIYU_AGE18_STATUS_PROFILE} circuit=${SWIYU_AGE18_STATUS_CIRCUIT}`
  );
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

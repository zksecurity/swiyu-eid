#!/usr/bin/env node

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { isAbsolute, normalize, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { inflateSync } from "node:zlib";
import type { EcdsaPublicKey } from "../types.js";
import { NativeNodeSwiyuProofBackend } from "./native-backend-node.js";
import { parseJsonWithUniqueKeys, type StrictJsonNode } from "./strict-json.js";
import { resolveSwiyuStatusListJwt } from "./status-list-resolver.js";
import type { SwiyuAuthoritativeStatusSnapshot } from "./types.js";
import { SwiyuZkpVerifier } from "./wallet.js";
import {
  SWIYU_SIDECAR_MAX_REQUEST_BYTES,
  SwiyuVerifierSidecarService,
  type SwiyuSidecarIssuerRecord,
  type SwiyuSidecarTrustAnchor,
} from "./sidecar.js";

const DEFAULT_PATH = "/v1/verify";
const DEFAULT_CONCURRENCY = 1;
const DEFAULT_REQUEST_TIMEOUT_MS = 180_000;
const DEFAULT_VERIFICATION_TIMEOUT_MS = 120_000;
const MAX_CONFIG_BYTES = 4 * 1024 * 1024;
const MAX_STATUS_LIST_JWT_BYTES = 128 * 1024;
const MAX_LOCAL_PATH_LENGTH = 4_096;
const MAX_REGISTRY_ENTRIES = 4_096;
const encoder = new TextEncoder();

export interface SwiyuSidecarServerOptions {
  service: SwiyuVerifierSidecarService;
  host?: "127.0.0.1" | "::1" | "localhost";
  /** Port zero is accepted by the programmatic API for isolated tests only. */
  port: number;
  path?: string;
  maxRequestBytes?: number;
  maxConcurrentRequests?: number;
  requestTimeoutMs?: number;
  verificationTimeoutMs?: number;
}

export interface RunningSwiyuSidecar {
  readonly host: string;
  readonly port: number;
  readonly path: string;
  close(): Promise<void>;
}

interface NormalizedServerOptions {
  service: SwiyuVerifierSidecarService;
  host: "127.0.0.1" | "::1" | "localhost";
  port: number;
  path: string;
  maxRequestBytes: number;
  maxConcurrentRequests: number;
  requestTimeoutMs: number;
  verificationTimeoutMs: number;
}

export async function startSwiyuSidecarServer(
  options: SwiyuSidecarServerOptions,
): Promise<RunningSwiyuSidecar> {
  const normalized = normalizeServerOptions(options);
  let activeRequests = 0;
  const server = createServer((request, response) => {
    void handleRequest(request, response, normalized, {
      enter(): boolean {
        if (activeRequests >= normalized.maxConcurrentRequests) return false;
        activeRequests += 1;
        return true;
      },
      leave(): void {
        activeRequests -= 1;
      },
    });
  });
  server.requestTimeout = normalized.requestTimeoutMs;
  server.headersTimeout = Math.min(normalized.requestTimeoutMs, 10_000);
  server.keepAliveTimeout = 1_000;
  server.maxRequestsPerSocket = 8;

  await new Promise<void>((accept, reject) => {
    const onError = (error: Error) => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      accept();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(normalized.port, normalized.host);
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    await closeServer(server);
    throw new Error("swiyu sidecar did not acquire a TCP address");
  }

  let closed = false;
  return Object.freeze({
    host: normalized.host,
    port: address.port,
    path: normalized.path,
    async close(): Promise<void> {
      if (closed) return;
      closed = true;
      await closeServer(server);
    },
  });
}

async function handleRequest(
  request: IncomingMessage,
  response: ServerResponse,
  options: NormalizedServerOptions,
  concurrency: { enter(): boolean; leave(): void },
): Promise<void> {
  if (!isLoopbackAddress(request.socket.remoteAddress)) {
    sendFailure(response, 403);
    request.resume();
    return;
  }
  if (request.method !== "POST" || request.url !== options.path) {
    sendFailure(response, 404);
    request.resume();
    return;
  }
  const contentType = request.headers["content-type"];
  if (
    typeof contentType !== "string" ||
    !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(contentType)
  ) {
    sendFailure(response, 415);
    request.resume();
    return;
  }
  const declaredLength = parseContentLength(request.headers["content-length"]);
  if (
    declaredLength === null ||
    (declaredLength !== undefined && declaredLength > options.maxRequestBytes)
  ) {
    sendFailure(response, 413);
    request.resume();
    return;
  }
  if (!concurrency.enter()) {
    sendFailure(response, 503);
    request.resume();
    return;
  }

  let verificationStarted = false;
  try {
    const body = await readBoundedBody(request, options.maxRequestBytes);
    const requestJson = new TextDecoder("utf-8", { fatal: true }).decode(body);
    const verification = options.service.verifyJson(requestJson);
    verificationStarted = true;
    void verification.finally(() => concurrency.leave()).catch(() => undefined);
    const result = await withTimeout(
      verification,
      options.verificationTimeoutMs,
    );
    if (response.destroyed || response.headersSent) return;
    const encoded = JSON.stringify(result);
    response.writeHead(200, {
      "Content-Type": "application/json; charset=utf-8",
      "Content-Length": encoder.encode(encoded).length,
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    });
    response.end(encoded);
  } catch {
    sendFailure(response, 400);
  } finally {
    if (!verificationStarted) concurrency.leave();
  }
}

async function readBoundedBody(
  request: IncomingMessage,
  maximumBytes: number,
): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let length = 0;
  let oversized = false;
  for await (const rawChunk of request) {
    const chunk = rawChunk instanceof Uint8Array
      ? rawChunk
      : new Uint8Array(rawChunk as ArrayBuffer);
    length += chunk.byteLength;
    if (length > maximumBytes) {
      oversized = true;
      continue;
    }
    chunks.push(new Uint8Array(chunk));
  }
  if (oversized || length === 0) throw new Error("invalid request size");
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.length;
  }
  return body;
}

function sendFailure(response: ServerResponse, status: number): void {
  if (response.destroyed || response.headersSent) return;
  const body = '{"verified":false}';
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": body.length,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    Connection: "close",
  });
  response.end(body);
}

function parseContentLength(value: string | undefined): number | undefined | null {
  if (value === undefined) return undefined;
  if (!/^(0|[1-9][0-9]*)$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

function normalizeServerOptions(
  options: SwiyuSidecarServerOptions,
): NormalizedServerOptions {
  if (!(options.service instanceof SwiyuVerifierSidecarService)) {
    throw new Error("a SwiyuVerifierSidecarService is required");
  }
  const host = options.host ?? "127.0.0.1";
  if (host !== "127.0.0.1" && host !== "::1" && host !== "localhost") {
    throw new Error("swiyu sidecar host must be loopback-only");
  }
  if (!Number.isInteger(options.port) || options.port < 0 || options.port > 65_535) {
    throw new Error("swiyu sidecar port must be in 0..65535");
  }
  const path = options.path ?? DEFAULT_PATH;
  if (!/^\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$/.test(path) || path === "/") {
    throw new Error("swiyu sidecar path must be one explicit absolute HTTP path");
  }
  return {
    service: options.service,
    host,
    port: options.port,
    path,
    maxRequestBytes: boundedInteger(
      options.maxRequestBytes ?? SWIYU_SIDECAR_MAX_REQUEST_BYTES,
      "maxRequestBytes",
      128,
      SWIYU_SIDECAR_MAX_REQUEST_BYTES,
    ),
    maxConcurrentRequests: boundedInteger(
      options.maxConcurrentRequests ?? DEFAULT_CONCURRENCY,
      "maxConcurrentRequests",
      1,
      64,
    ),
    requestTimeoutMs: boundedInteger(
      options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS,
      "requestTimeoutMs",
      100,
      600_000,
    ),
    verificationTimeoutMs: boundedInteger(
      options.verificationTimeoutMs ?? DEFAULT_VERIFICATION_TIMEOUT_MS,
      "verificationTimeoutMs",
      100,
      600_000,
    ),
  };
}

function isLoopbackAddress(address: string | undefined): boolean {
  return address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1";
}

function boundedInteger(
  value: number,
  label: string,
  minimum: number,
  maximum: number,
): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be an integer in ${minimum}..${maximum}`);
  }
  return value;
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_accept, reject) => {
        timer = setTimeout(() => reject(new Error("verification timed out")), timeoutMs);
        timer.unref?.();
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

async function closeServer(server: ReturnType<typeof createServer>): Promise<void> {
  await new Promise<void>((accept, reject) => {
    server.close((error) => error ? reject(error) : accept());
    server.closeIdleConnections?.();
  });
}

interface SidecarFileConfig {
  listen: Omit<SwiyuSidecarServerOptions, "service">;
  verifyingKeyPath: string;
  nativeBackend: {
    binaryPath: string;
    cwd: string;
    tempRoot?: string;
    verifyTimeoutMs?: number;
  };
  issuers: SwiyuSidecarIssuerRecord[];
  statusLists: SidecarStatusListFileConfig[];
}

interface SidecarStatusListFileConfig {
  jwtPath: string;
  issuer: string;
  kid: string;
  subject: string;
}

export interface SwiyuLocalStatusListJwtRequest {
  jwtPath: string;
  issuerPublicKey: EcdsaPublicKey;
  expectedIssuer: string;
  expectedSubject: string;
  currentTime: bigint;
}

export async function loadSwiyuSidecarFromConfigFile(
  configPath: string,
): Promise<SwiyuSidecarServerOptions> {
  const absoluteConfigPath = resolve(configPath);
  const configBytes = await readBoundedLocalFile(
    absoluteConfigPath,
    MAX_CONFIG_BYTES,
    "sidecar configuration",
  );
  const configText = new TextDecoder("utf-8", { fatal: true }).decode(configBytes);
  const parsed = parseFileConfig(configText);
  const baseDirectory = resolve(absoluteConfigPath, "..");
  const verifyingKeyPath = localPath(
    baseDirectory,
    parsed.verifyingKeyPath,
    "verifying_key",
  );
  const verifyingKeyMetadata = await stat(verifyingKeyPath);
  if (!verifyingKeyMetadata.isFile() || verifyingKeyMetadata.size <= 0) {
    throw new Error("swiyu verification key must be a non-empty local file");
  }
  const nativeVerifyTimeoutMs =
    parsed.nativeBackend.verifyTimeoutMs ?? DEFAULT_VERIFICATION_TIMEOUT_MS;
  const listenVerifyTimeoutMs =
    parsed.listen.verificationTimeoutMs ?? DEFAULT_VERIFICATION_TIMEOUT_MS;
  if (listenVerifyTimeoutMs < nativeVerifyTimeoutMs) {
    throw new Error("configuration.listen.verification_timeout_ms must be at least native_backend.verify_timeout_ms");
  }
  const backend = new NativeNodeSwiyuProofBackend({
    binaryPath: localPath(
      baseDirectory,
      parsed.nativeBackend.binaryPath,
      "native_backend.binary",
    ),
    cwd: localPath(
      baseDirectory,
      parsed.nativeBackend.cwd,
      "native_backend.cwd",
    ),
    ...(parsed.nativeBackend.tempRoot === undefined ? {} : {
      tempRoot: localPath(
        baseDirectory,
        parsed.nativeBackend.tempRoot,
        "native_backend.temp_root",
      ),
    }),
    verifyTimeoutMs: nativeVerifyTimeoutMs,
  });
  const issuerKeys = buildLocalIssuerKeyRegistry(parsed.issuers);
  const startupTime = BigInt(Math.floor(Date.now() / 1_000));
  const statusSnapshots: SwiyuAuthoritativeStatusSnapshot[] = [];
  const snapshotIds = new Set<string>();
  const statusBindings = new Set<string>();
  for (const [index, statusList] of parsed.statusLists.entries()) {
    const issuerKey = issuerKeys.get(issuerRegistryKey(
      statusList.issuer,
      statusList.kid,
    ));
    if (!issuerKey) {
      throw new Error(
        `configuration.status_lists[${index}] does not identify one provisioned issuer and kid`,
      );
    }
    const snapshot = await provisionSwiyuAuthoritativeStatusSnapshotFromFile({
      jwtPath: localPath(
        baseDirectory,
        statusList.jwtPath,
        `configuration.status_lists[${index}].jwt_file`,
      ),
      issuerPublicKey: issuerKey,
      expectedIssuer: statusList.issuer,
      expectedSubject: statusList.subject,
      currentTime: startupTime,
    });
    if (snapshotIds.has(snapshot.id)) {
      throw new Error("configuration.status_lists derives a duplicate snapshot id");
    }
    snapshotIds.add(snapshot.id);
    const binding = statusListBindingKey(statusList);
    if (statusBindings.has(binding)) {
      throw new Error(
        "configuration.status_lists ambiguously repeats an issuer, kid, and subject",
      );
    }
    statusBindings.add(binding);
    statusSnapshots.push(snapshot);
  }
  const service = new SwiyuVerifierSidecarService({
    verifier: new SwiyuZkpVerifier(backend),
    verifyingKey: Object.freeze({ kind: "local-file", path: verifyingKeyPath }),
    issuers: parsed.issuers,
    statusSnapshots,
  });
  return { service, ...parsed.listen };
}

/**
 * Node-only production adapter for one locally provisioned signed status list.
 * The returned object deliberately omits the private subject URI and Merkle root.
 */
export async function provisionSwiyuAuthoritativeStatusSnapshotFromFile(
  request: Readonly<SwiyuLocalStatusListJwtRequest>,
): Promise<Readonly<SwiyuAuthoritativeStatusSnapshot>> {
  if (
    typeof request.jwtPath !== "string" ||
    !isAbsolute(request.jwtPath) ||
    normalize(request.jwtPath) !== request.jwtPath ||
    request.jwtPath.length > MAX_LOCAL_PATH_LENGTH ||
    request.jwtPath.includes("\0")
  ) {
    throw new Error("signed status-list JWT path must be an absolute normalized local path");
  }
  const compactJwtBytes = await readBoundedLocalFile(
    request.jwtPath,
    MAX_STATUS_LIST_JWT_BYTES,
    "signed status-list JWT",
  );
  const compactJwt = new TextDecoder("utf-8", { fatal: true }).decode(
    compactJwtBytes,
  );
  return resolveSwiyuStatusListJwt({
    compactJwt,
    issuerPublicKey: request.issuerPublicKey,
    expectedIssuer: request.expectedIssuer,
    expectedSubject: request.expectedSubject,
    currentTime: request.currentTime,
    inflateZlib(compressed, maxOutputBytes) {
      const inflated = inflateSync(compressed, {
        maxOutputLength: maxOutputBytes,
      });
      return new Uint8Array(
        inflated.buffer,
        inflated.byteOffset,
        inflated.byteLength,
      );
    },
  }).authoritativeSnapshot;
}

async function readBoundedLocalFile(
  path: string,
  maximumBytes: number,
  label: string,
): Promise<Uint8Array> {
  const metadata = await stat(path);
  if (!metadata.isFile() || metadata.size <= 0 || metadata.size > maximumBytes) {
    throw new Error(`${label} must be a non-empty local file of at most ${maximumBytes} bytes`);
  }
  const bytes = await readFile(path);
  if (bytes.length !== metadata.size || bytes.length > maximumBytes) {
    throw new Error(`${label} changed while it was being read`);
  }
  return new Uint8Array(bytes);
}

function localPath(baseDirectory: string, path: string, label: string): string {
  if (
    typeof path !== "string" ||
    path.length === 0 ||
    path.length > MAX_LOCAL_PATH_LENGTH ||
    path.includes("\0")
  ) {
    throw new Error(`${label} must be a local filesystem path`);
  }
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(path)) {
    throw new Error(`${label} must not be a URL`);
  }
  return resolve(baseDirectory, path);
}

function parseFileConfig(source: string): SidecarFileConfig {
  const value = strictJsonValue(parseJsonWithUniqueKeys(source));
  const root = exactRecord(value, "configuration", [
    "listen",
    "verifying_key",
    "issuers",
    "status_lists",
    "native_backend",
  ]);
  const listenValue = exactRecord(root.listen, "configuration.listen", [
    "host",
    "port",
    "path",
  ], [
    "max_request_bytes",
    "max_concurrent_requests",
    "request_timeout_ms",
    "verification_timeout_ms",
  ]);
  const host = requiredString(listenValue.host, "configuration.listen.host", 9);
  if (host !== "127.0.0.1" && host !== "::1" && host !== "localhost") {
    throw new Error("configuration.listen.host must be loopback-only");
  }
  const port = integerInRange(
    listenValue.port,
    "configuration.listen.port",
    1,
    65_535,
  );
  const listen: Omit<SwiyuSidecarServerOptions, "service"> = {
    host,
    port,
    path: requiredString(listenValue.path, "configuration.listen.path", 2_048),
    ...(listenValue.max_request_bytes === undefined ? {} : {
      maxRequestBytes: integerInRange(
        listenValue.max_request_bytes,
        "configuration.listen.max_request_bytes",
        128,
        SWIYU_SIDECAR_MAX_REQUEST_BYTES,
      ),
    }),
    ...(listenValue.max_concurrent_requests === undefined ? {} : {
      maxConcurrentRequests: integerInRange(
        listenValue.max_concurrent_requests,
        "configuration.listen.max_concurrent_requests",
        1,
        64,
      ),
    }),
    ...(listenValue.request_timeout_ms === undefined ? {} : {
      requestTimeoutMs: integerInRange(
        listenValue.request_timeout_ms,
        "configuration.listen.request_timeout_ms",
        100,
        600_000,
      ),
    }),
    ...(listenValue.verification_timeout_ms === undefined ? {} : {
      verificationTimeoutMs: integerInRange(
        listenValue.verification_timeout_ms,
        "configuration.listen.verification_timeout_ms",
        100,
        600_000,
      ),
    }),
  };
  const nativeValue = exactRecord(
    root.native_backend,
    "configuration.native_backend",
    ["binary", "cwd"],
    ["temp_root", "verify_timeout_ms"],
  );
  const nativeBackend = {
    binaryPath: requiredString(
      nativeValue.binary,
      "configuration.native_backend.binary",
      MAX_LOCAL_PATH_LENGTH,
    ),
    cwd: requiredString(
      nativeValue.cwd,
      "configuration.native_backend.cwd",
      MAX_LOCAL_PATH_LENGTH,
    ),
    ...(nativeValue.temp_root === undefined ? {} : {
      tempRoot: requiredString(
        nativeValue.temp_root,
        "configuration.native_backend.temp_root",
        MAX_LOCAL_PATH_LENGTH,
      ),
    }),
    ...(nativeValue.verify_timeout_ms === undefined ? {} : {
      verifyTimeoutMs: integerInRange(
        nativeValue.verify_timeout_ms,
        "configuration.native_backend.verify_timeout_ms",
        100,
        600_000,
      ),
    }),
  };
  const issuers = boundedArray(
    root.issuers,
    "configuration.issuers",
    1,
    MAX_REGISTRY_ENTRIES,
  ).map(
    (item, index): SwiyuSidecarIssuerRecord => {
      const record = exactRecord(item, `configuration.issuers[${index}]`, [
        "issuer",
        "kid",
        "public_key",
        "vct_values",
        "trust_anchors",
      ]);
      const key = exactRecord(record.public_key, `configuration.issuers[${index}].public_key`, [
        "kty",
        "crv",
        "x",
        "y",
        "kid",
      ]);
      return {
        issuer: requiredString(record.issuer, `configuration.issuers[${index}].issuer`, 112),
        kid: requiredString(record.kid, `configuration.issuers[${index}].kid`, 112),
        publicKey: {
          kty: requiredLiteral(key.kty, "EC", `configuration.issuers[${index}].public_key.kty`),
          crv: requiredLiteral(key.crv, "P-256", `configuration.issuers[${index}].public_key.crv`),
          x: requiredString(key.x, `configuration.issuers[${index}].public_key.x`, 43),
          y: requiredString(key.y, `configuration.issuers[${index}].public_key.y`, 43),
          kid: requiredString(key.kid, `configuration.issuers[${index}].public_key.kid`, 112),
        },
        vctValues: stringArray(record.vct_values, `configuration.issuers[${index}].vct_values`),
        trustAnchors: fileTrustAnchors(record.trust_anchors, `configuration.issuers[${index}].trust_anchors`),
      };
    },
  );
  const statusLists = boundedArray(
    root.status_lists,
    "configuration.status_lists",
    1,
    MAX_REGISTRY_ENTRIES,
  ).map((item, index): SidecarStatusListFileConfig => {
    const path = `configuration.status_lists[${index}]`;
    const statusList = exactRecord(item, path, [
      "jwt_file",
      "issuer",
      "kid",
      "subject",
    ]);
    return {
      jwtPath: requiredString(statusList.jwt_file, `${path}.jwt_file`, MAX_LOCAL_PATH_LENGTH),
      issuer: requiredString(statusList.issuer, `${path}.issuer`, 112),
      kid: requiredString(statusList.kid, `${path}.kid`, 112),
      subject: requiredString(statusList.subject, `${path}.subject`, 160),
    };
  });
  return {
    listen,
    verifyingKeyPath: requiredString(
      root.verifying_key,
      "configuration.verifying_key",
      MAX_LOCAL_PATH_LENGTH,
    ),
    nativeBackend,
    issuers,
    statusLists,
  };
}

function fileTrustAnchors(value: unknown, path: string): SwiyuSidecarTrustAnchor[] {
  return boundedArray(value, path, 0, 64).map((item, index) => {
    const anchor = exactRecord(item, `${path}[${index}]`, ["did", "trustRegistryUri"]);
    return {
      did: requiredString(anchor.did, `${path}[${index}].did`, 512),
      trustRegistryUri: requiredString(
        anchor.trustRegistryUri,
        `${path}[${index}].trustRegistryUri`,
        2_048,
      ),
    };
  });
}

function strictJsonValue(node: StrictJsonNode): unknown {
  if (node.kind === "string") return node.value;
  if (node.kind === "literal") return node.value;
  if (node.kind === "number") {
    const number = Number(node.raw);
    if (!Number.isSafeInteger(number) || !/^-?(0|[1-9][0-9]*)$/.test(node.raw)) {
      throw new Error("configuration numbers must be safe canonical integers");
    }
    return number;
  }
  if (node.kind === "array") return node.items.map(strictJsonValue);
  return Object.fromEntries(
    [...node.properties].map(([key, property]) => [key, strictJsonValue(property.value)]),
  );
}

function exactRecord(
  value: unknown,
  path: string,
  requiredKeys: readonly string[],
  optionalKeys: readonly string[] = [],
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${path} must be an object`);
  }
  const record = value as Record<string, unknown>;
  const allowed = new Set([...requiredKeys, ...optionalKeys]);
  if (Object.keys(record).some((key) => !allowed.has(key))) {
    throw new Error(`${path} contains an unsupported field`);
  }
  for (const key of requiredKeys) {
    if (!(key in record)) throw new Error(`${path}.${key} is required`);
  }
  return record;
}

function requiredArray(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${path} must be an array`);
  return value;
}

function boundedArray(
  value: unknown,
  path: string,
  minimumLength: number,
  maximumLength: number,
): unknown[] {
  const array = requiredArray(value, path);
  if (array.length < minimumLength || array.length > maximumLength) {
    throw new Error(`${path} must contain ${minimumLength}..${maximumLength} entries`);
  }
  return array;
}

function requiredString(
  value: unknown,
  path: string,
  maximumLength = 4_096,
): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximumLength ||
    value.includes("\0")
  ) {
    throw new Error(`${path} must be a non-empty string of at most ${maximumLength} characters`);
  }
  return value;
}

function requiredInteger(value: unknown, path: string): number {
  if (!Number.isSafeInteger(value)) throw new Error(`${path} must be a safe integer`);
  return value as number;
}

function integerInRange(
  value: unknown,
  path: string,
  minimum: number,
  maximum: number,
): number {
  const integer = requiredInteger(value, path);
  if (integer < minimum || integer > maximum) {
    throw new Error(`${path} must be in ${minimum}..${maximum}`);
  }
  return integer;
}

function requiredLiteral<T extends string>(value: unknown, literal: T, path: string): T {
  if (value !== literal) throw new Error(`${path} must equal ${literal}`);
  return literal;
}

function stringArray(value: unknown, path: string): string[] {
  return boundedArray(value, path, 1, 64).map((item, index) =>
    requiredString(item, `${path}[${index}]`, 112),
  );
}

function buildLocalIssuerKeyRegistry(
  issuers: readonly SwiyuSidecarIssuerRecord[],
): ReadonlyMap<string, EcdsaPublicKey> {
  const keys = new Map<string, EcdsaPublicKey>();
  for (const [index, issuer] of issuers.entries()) {
    if (issuer.publicKey.kid !== issuer.kid) {
      throw new Error(
        `configuration.issuers[${index}] public key kid does not match its record kid`,
      );
    }
    const key = issuerRegistryKey(issuer.issuer, issuer.kid);
    if (keys.has(key)) {
      throw new Error("configuration.issuers ambiguously repeats an issuer and kid");
    }
    keys.set(key, issuer.publicKey);
  }
  return keys;
}

function issuerRegistryKey(issuer: string, kid: string): string {
  return `${issuer.length}:${issuer}${kid}`;
}

function statusListBindingKey(statusList: SidecarStatusListFileConfig): string {
  return JSON.stringify([statusList.issuer, statusList.kid, statusList.subject]);
}

async function runCli(): Promise<void> {
  const [configPath, ...rest] = process.argv.slice(2);
  if (!configPath || rest.length !== 0) {
    throw new Error("usage: openac-swiyu-sidecar <config.json>");
  }
  const runtime = await startSwiyuSidecarServer(
    await loadSwiyuSidecarFromConfigFile(configPath),
  );
  process.stdout.write(
    `swiyu verifier sidecar listening on http://${runtime.host}:${runtime.port}${runtime.path}\n`,
  );
  let closing = false;
  const shutdown = () => {
    if (closing) return;
    closing = true;
    void runtime.close().then(() => process.exit(0), () => process.exit(1));
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : undefined;
if (invokedPath === import.meta.url) {
  void runCli().catch((error) => {
    process.stderr.write(
      `openac-swiyu-sidecar failed: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  });
}

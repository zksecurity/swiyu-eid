#!/usr/bin/env node
/**
 * Harness-owned loopback HTTP wrapper around the SDK sidecar service.
 * Policy and crypto come from SwiyuVerifierSidecarService + NativeNodeSwiyuProofBackend.
 * This process does not reimplement VCT/issuer/status/session checks in Python.
 */
import { createServer } from "node:http";
import { readFileSync, writeFileSync, chmodSync, appendFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  artifactPaths,
  nativeBackendImportUrl,
  sdkImportUrl,
} from "./paths.mjs";

const MAX_REQUEST_BYTES = 2 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 180_000;
const FIXED_REJECT = '{"verified":false}';
const VERIFY_PATH = "/verify";

function parseArgs(argv) {
  const out = { fixture: null, readyFile: null, traceFile: null };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = argv[i + 1];
    if (arg === "--fixture" && next) {
      out.fixture = next;
      i += 1;
    } else if (arg === "--ready-file" && next) {
      out.readyFile = next;
      i += 1;
    } else if (arg === "--trace-file" && next) {
      out.traceFile = next;
      i += 1;
    }
  }
  if (!out.fixture || !out.readyFile) {
    throw new Error("usage: transcript-sidecar.mjs --fixture PATH --ready-file PATH [--trace-file PATH]");
  }
  return out;
}

function asBigInt(value, label) {
  if (typeof value === "bigint") return value;
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value)) return BigInt(value);
  throw new Error(`${label} must be a non-negative integer`);
}

function loadFactory(path) {
  const document = JSON.parse(readFileSync(path, "utf8"));
  if (!document || document.schema !== "swiyu.transcript-fixture.v1") {
    throw new Error("unsupported transcript fixture schema");
  }
  const variants = document.variants;
  if (!Array.isArray(variants) || variants.length === 0) {
    throw new Error("fixture variants are required");
  }
  return document;
}

function provisionFromFactory(document) {
  const issuers = [];
  const snapshots = [];
  const seenIssuers = new Set();
  const seenSnapshots = new Set();
  for (const variant of document.variants) {
    const issuer = variant?.given?.issuer;
    if (!issuer?.public_key || !issuer.issuer_id || !issuer.key_id) {
      throw new Error("fixture variant missing issuer authority");
    }
    const issuerKey = `${issuer.issuer_id}\0${issuer.key_id}`;
    if (!seenIssuers.has(issuerKey)) {
      seenIssuers.add(issuerKey);
      issuers.push({
        issuer: issuer.issuer_id,
        kid: issuer.key_id,
        publicKey: issuer.public_key,
        vctValues: issuer.allowed_vcts,
        trustAnchors: issuer.trust_anchors ?? [],
      });
    }
    const raw = variant?.verify?.inputs?.statusSnapshot;
    if (!raw) throw new Error("fixture variant missing authoritative status snapshot");
    if (!seenSnapshots.has(raw.id)) {
      seenSnapshots.add(raw.id);
      snapshots.push({
        id: raw.id,
        issuer: raw.issuer,
        kid: raw.kid,
        subject: raw.subject,
        commitment: {
          hashHi: asBigInt(raw.commitment.hashHi, "commitment.hashHi"),
          hashLo: asBigInt(raw.commitment.hashLo, "commitment.hashLo"),
        },
        epoch: Number(raw.epoch),
        listLength: Number(raw.listLength),
        validBefore: asBigInt(raw.validBefore, "validBefore"),
        provenance: raw.provenance,
      });
    }
  }
  return { issuers, snapshots };
}

function appendTrace(traceFile, record) {
  if (!traceFile) return;
  appendFileSync(traceFile, `${JSON.stringify(record)}\n`, { mode: 0o600 });
}

function sendFixed(response, status, body = FIXED_REJECT) {
  if (response.destroyed || response.headersSent) return;
  const payload = Buffer.from(body, "utf8");
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": payload.length,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    Connection: "close",
  });
  response.end(payload);
}

function isLoopback(address) {
  return address === "127.0.0.1" || address === "::1" || address === ":ffff:127.0.0.1";
}

async function readBody(request, maximumBytes) {
  const chunks = [];
  let length = 0;
  for await (const raw of request) {
    const chunk = raw instanceof Uint8Array ? raw : Buffer.from(raw);
    length += chunk.byteLength;
    if (length > maximumBytes) {
      throw new Error("too large");
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, length);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const fixturePath = resolve(args.fixture);
  const document = loadFactory(fixturePath);
  const { issuers, snapshots } = provisionFromFactory(document);

  const paths = artifactPaths();
  if (!paths.nativeBinary || !paths.verifyingKey || !paths.keysRoot ||
      !statSync(paths.nativeBinary).isFile() || !statSync(paths.verifyingKey).isFile()) {
    throw new Error("real native verification artifacts are required");
  }
  const sdk = await import(pathToFileURL(sdkImportUrl()).href);
  const native = await import(pathToFileURL(nativeBackendImportUrl()).href);
  const verifyingKey = { kind: "local-file", path: paths.verifyingKey };
  const backend = new native.NativeNodeSwiyuProofBackend({
    binaryPath: paths.nativeBinary,
    cwd: paths.keysRoot,
    ...(process.env.SWIYU_OPENAC_TEMP_ROOT ? {tempRoot: process.env.SWIYU_OPENAC_TEMP_ROOT} : {}),
    verifyTimeoutMs: 180_000,
  });
  const service = new sdk.SwiyuVerifierSidecarService({
    verifier: new sdk.SwiyuZkpVerifier(backend),
    verifyingKey,
    issuers,
    statusSnapshots: snapshots,
  });

  if (args.traceFile) {
    writeFileSync(args.traceFile, "", { mode: 0o600 });
    chmodSync(args.traceFile, 0o600);
  }

  let busy = Promise.resolve();
  const server = createServer((request, response) => {
    const job = busy.then(() => handle(request, response, service, args.traceFile));
    busy = job.catch(() => undefined);
  });
  server.requestTimeout = REQUEST_TIMEOUT_MS;
  server.headersTimeout = REQUEST_TIMEOUT_MS;
  server.keepAliveTimeout = 1_000;
  server.maxRequestsPerSocket = 1;

  await new Promise((accept, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", accept);
  });
  const address = server.address();
  const url = `http://127.0.0.1:${address.port}${VERIFY_PATH}`;
  const ready = { url, pid: process.pid };
  writeFileSync(args.readyFile, `${JSON.stringify(ready)}\n`, { mode: 0o600 });
  chmodSync(args.readyFile, 0o600);
}

async function handle(request, response, service, traceFile) {
  const started = Date.now();
  if (!isLoopback(request.socket.remoteAddress)) {
    sendFixed(response, 403);
    request.resume();
    return;
  }
  if (request.method !== "POST" || request.url !== VERIFY_PATH) {
    sendFixed(response, 404);
    request.resume();
    return;
  }
  try {
    const body = await readBody(request, MAX_REQUEST_BYTES);
    const text = new TextDecoder("utf-8", { fatal: true }).decode(body);
    appendTrace(traceFile, {
      direction: "incoming",
      at: started,
      method: request.method,
      url: request.url,
      bytes: body.length,
    });
    const result = await service.verifyJson(text);
    const encoded = JSON.stringify(result);
    appendTrace(traceFile, {
      direction: "outgoing",
      at: Date.now(),
      status: 200,
      bytes: Buffer.byteLength(encoded),
    });
    sendFixed(response, 200, encoded);
  } catch {
    appendTrace(traceFile, {
      direction: "outgoing",
      at: Date.now(),
      status: 400,
      bytes: Buffer.byteLength(FIXED_REJECT),
    });
    sendFixed(response, 400);
  }
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
  process.exit(1);
});

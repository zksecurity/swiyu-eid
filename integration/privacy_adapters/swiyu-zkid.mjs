#!/usr/bin/env node
/**
 * Privacy scenario collector for Swiyu/zkID SDK + loopback sidecar.
 * Uses dist public APIs. Cryptographic backends here are explicit mocks
 * unless a case is labeled evidence_kind=crypto (none in this campaign:
 * real proving artifacts are not exercised).
 */
import { existsSync } from "node:fs";
import { register } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { deflateSync, inflateSync } from "node:zlib";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "../..");
const SDK_ROOT = join(REPO_ROOT, "components/zkid/wallet-unit-poc/openac-sdk");
const SDK_SWIYU = join(SDK_ROOT, "dist/swiyu-zkp/index.js");
const SDK_SIDECAR = join(SDK_ROOT, "dist/swiyu-zkp/sidecar-node.js");
register(pathToFileURL(join(HERE, "sidecar-export-loader.mjs")).href, import.meta.url);
const NOBLE_NIST = join(SDK_ROOT, "node_modules/@noble/curves/nist.js");
const NOBLE_SHA = join(SDK_ROOT, "node_modules/@noble/hashes/sha2.js");

const PROVIDER = {
  id: "swiyu-zkid-integration",
  title: "Swiyu zkID SDK/sidecar privacy integration (mock crypto backends)",
};

const SYNTH_HOLDER = "SYNTH-HOLDER-SECRET-9f3a7c21";
const SYNTH_HOLDER_B = "SYNTH-HOLDER-SECRET-9f3a7c22";
const SYNTH_STATUS_URI = "https://status.example.ch/lists/2026-07";
const ISSUER = "did:example:issuer";
const IAT = 1_750_000_000;
const CHECKED_IN_DID_TDW_KID =
  "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch:api:v1:did#assert-key-01";
const ISSUER_PRIVATE_KEY = bigintToBytes(0x123456789abcdef123456789abcdefn, 32);

const encoder = new TextEncoder();

async function loadSdk() {
  if (!existsSync(SDK_SWIYU)) {
    throw new Error(`openac-sdk dist missing: ${SDK_SWIYU}`);
  }
  return import(pathToFileURL(SDK_SWIYU).href);
}

async function loadSidecarNode() {
  if (!existsSync(SDK_SIDECAR)) {
    throw new Error(`openac-sdk sidecar-node dist missing: ${SDK_SIDECAR}`);
  }
  return import(pathToFileURL(SDK_SIDECAR).href);
}

async function loadP256() {
  const { p256 } = await import(pathToFileURL(NOBLE_NIST).href);
  return p256;
}

async function loadSha256() {
  const { sha256 } = await import(pathToFileURL(NOBLE_SHA).href);
  return sha256;
}

class MockVerifyBackend {
  async proveFromWitness() {
    throw new Error("mock verifier cannot prove");
  }
  async verify(proof, verifyingKey, expectedPublicContext) {
    return {
      valid: true,
      publicValues: Array.from({ length: 10 }, (_, index) =>
        expectedPublicContext.slice(index * 32, (index + 1) * 32),
      ),
    };
  }
}

class GateVerifyBackend {
  block = true;
  releaseGate;
  started;
  constructor() {
    this.started = new Promise((accept) => {
      this.markStarted = accept;
    });
  }
  async proveFromWitness() {
    throw new Error("mock verifier cannot prove");
  }
  async verify(_proof, _key, context) {
    this.markStarted();
    if (this.block) {
      await new Promise((accept) => {
        this.releaseGate = accept;
      });
    }
    return {
      valid: true,
      publicValues: Array.from({ length: 10 }, (_, index) =>
        context.slice(index * 32, (index + 1) * 32),
      ),
    };
  }
  release() {
    this.block = false;
    this.releaseGate?.();
  }
}

class MockSplitBackend {
  crypto_label = "mock-split-backend";
  async prepare(request) {
    const publicValues = [pad32(request.witness), pad32(request.circuitId)];
    return {
      handle: {
        id: hex(request.witness.subarray(0, 8)),
        publicValues,
      },
      publicValues,
    };
  }
  async proveLinked(request) {
    const handle = request.preparedHandle;
    const commitment = pad32(handle.id);
    const showPublic = [pad32(request.showWitness), pad32(request.showCircuitId)];
    return {
      prepare: {
        proof: concatBytes([...handle.publicValues, commitment]),
        publicValues: handle.publicValues,
        sharedCommitment: commitment,
      },
      show: {
        proof: concatBytes([...showPublic, commitment]),
        publicValues: showPublic,
        sharedCommitment: commitment,
      },
    };
  }
  async verifyProof() {
    throw new Error("not used");
  }
}

async function collectSidecarHttp(sdk, sidecarNode) {
  const distMismatch = await recordDistInstanceofMismatch(sdk, sidecarNode);
  const ctx = setupSidecar(sdk, sidecarNode, new MockVerifyBackend());
  const runtime = await sidecarNode.startSwiyuSidecarServer({
    service: ctx.service,
    host: "127.0.0.1",
    port: 0,
    path: "/v1/verify",
    maxRequestBytes: 128,
  });
  const url = `http://127.0.0.1:${runtime.port}${runtime.path}`;
  try {
    const secretBodyA = JSON.stringify({
      proof_envelope: "{}",
      expected: {},
      holder_secret: SYNTH_HOLDER,
    });
    const secretBodyB = JSON.stringify({
      proof_envelope: "{}",
      expected: {},
      holder_secret: SYNTH_HOLDER_B,
    });
    const samePublic = {
      method: "POST",
      path: "/v1/verify",
      content_type: "application/json",
      content_length: secretBodyA.length,
    };
    const malformedA = await postJson(url, secretBodyA);
    const malformedB = await postJson(url, secretBodyB);
    const oversizedBody = "x".repeat(ctx.maxSmall);
    const oversized = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: oversizedBody,
    });
    const oversizedView = {
      http_status: oversized.status,
      body: await oversized.text(),
    };
    const wrongPath = await fetch(`http://127.0.0.1:${runtime.port}/v1/other`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: ctx.body,
    });
    const wrongPathView = {
      http_status: wrongPath.status,
      body: await wrongPath.text(),
    };
    const wrongType = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: ctx.body,
    });
    const wrongTypeView = {
      http_status: wrongType.status,
      body: await wrongType.text(),
    };

    const rejectBody = '{"verified":false}';
    const secretCase = {
      id: "sidecar-http-secret-in-malformed-body",
      family: "failure_fallback",
      relation: "secret_scan",
      observer: "network-client",
      runtime: "node-sidecar-http",
      evidence_kind: "integration",
      secrets: [{ label: "holder_secret", value: SYNTH_HOLDER }],
      opaque_paths: [],
      compare_paths: ["/body"],
      records: [
        record({
          id: "malformed-with-secret",
          subject: "alice",
          session: "http-1",
          scope: "sidecar:/v1/verify",
          public_context: samePublic,
          expected_outcome: "reject",
          outcome: "reject",
          view: { http_status: malformedA.status, body: malformedA.body },
          allowed_public: { "/http_status": malformedA.status, "/body": rejectBody },
        }),
      ],
    };

    const samePublicEquiv = {
      id: "sidecar-http-same-public-rejection",
      family: "failure_fallback",
      relation: "equivalent",
      observer: "network-client",
      runtime: "node-sidecar-http",
      evidence_kind: "integration",
      secrets: [
        { label: "holder_secret", value: SYNTH_HOLDER },
        { label: "holder_secret_b", value: SYNTH_HOLDER_B },
      ],
      opaque_paths: [],
      compare_paths: ["/body", "/http_status"],
      records: [
        record({
          id: "malformed-a",
          subject: "alice",
          session: "http-eq-1",
          scope: "sidecar:/v1/verify",
          public_context: samePublic,
          expected_outcome: "reject",
          outcome: "reject",
          view: { http_status: malformedA.status, body: malformedA.body },
          allowed_public: { "/http_status": malformedA.status, "/body": rejectBody },
        }),
        record({
          id: "malformed-b",
          subject: "alice",
          session: "http-eq-2",
          scope: "sidecar:/v1/verify",
          public_context: { ...samePublic },
          expected_outcome: "reject",
          outcome: "reject",
          view: { http_status: malformedB.status, body: malformedB.body },
          allowed_public: { "/http_status": malformedB.status, "/body": rejectBody },
        }),
      ],
    };

    const rejectionMetadata = {
      id: "sidecar-http-rejection-metadata",
      family: "failure_fallback",
      relation: "secret_scan",
      observer: "network-client",
      runtime: "node-sidecar-http",
      evidence_kind: "integration",
      secrets: [{ label: "holder_secret", value: SYNTH_HOLDER }],
      opaque_paths: [],
      compare_paths: ["/http_status", "/body"],
      records: [
        record({
          id: "malformed-json",
          subject: "alice",
          session: "http-meta-1",
          scope: "sidecar:/v1/verify",
          public_context: {
            method: "POST",
            path: "/v1/verify",
            content_type: "application/json",
            content_length: secretBodyA.length,
          },
          expected_outcome: "reject",
          outcome: "reject",
          view: { http_status: malformedA.status, body: malformedA.body },
          allowed_public: { "/http_status": 400, "/body": rejectBody },
        }),
        record({
          id: "oversized",
          subject: "alice",
          session: "http-meta-2",
          scope: "sidecar:/v1/verify",
          public_context: {
            method: "POST",
            path: "/v1/verify",
            content_type: "application/json",
            content_length: oversizedBody.length,
          },
          expected_outcome: "reject",
          outcome: "reject",
          view: oversizedView,
          allowed_public: { "/http_status": 413, "/body": rejectBody },
        }),
        record({
          id: "wrong-path",
          subject: "alice",
          session: "http-meta-3",
          scope: "sidecar:/v1/other",
          public_context: {
            method: "POST",
            path: "/v1/other",
            content_type: "application/json",
            content_length: ctx.body.length,
          },
          expected_outcome: "reject",
          outcome: "reject",
          view: wrongPathView,
          allowed_public: { "/http_status": 404, "/body": rejectBody },
        }),
        record({
          id: "wrong-type",
          subject: "alice",
          session: "http-meta-4",
          scope: "sidecar:/v1/verify",
          public_context: {
            method: "POST",
            path: "/v1/verify",
            content_type: "text/plain",
            content_length: ctx.body.length,
          },
          expected_outcome: "reject",
          outcome: "reject",
          view: wrongTypeView,
          allowed_public: { "/http_status": 415, "/body": rejectBody },
        }),
      ],
    };

    const metrics = await collectHttpRepeatMetrics(url, secretBodyA);
    const cancel = await collectCancelRetry(sdk, sidecarNode);
    return [distMismatch, secretCase, samePublicEquiv, rejectionMetadata, metrics, cancel];
  } finally {
    await runtime.close();
  }
}

async function collectCancelRetry(sdk, sidecarNode) {
  const gate = new GateVerifyBackend();
  const ctx = setupSidecar(sdk, sidecarNode, gate);
  const runtime = await sidecarNode.startSwiyuSidecarServer({
    service: ctx.service,
    host: "127.0.0.1",
    port: 0,
    path: "/v1/verify",
    maxConcurrentRequests: 1,
  });
  const url = `http://127.0.0.1:${runtime.port}${runtime.path}`;
  try {
    const controller = new AbortController();
    const pending = fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json; charset=utf-8" },
      body: ctx.body,
      signal: controller.signal,
    });
    await gate.started;
    controller.abort();
    let abortedView;
    try {
      await pending;
      abortedView = { aborted: false };
    } catch (error) {
      abortedView = {
        aborted: true,
        error_name: error?.name ?? "Error",
        error_message: String(error?.message ?? error),
      };
    }
    gate.release();
    const retry = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json; charset=utf-8" },
      body: ctx.body,
    });
    const retryJson = await retry.json();
    return {
      id: "sidecar-http-cancel-retry",
      family: "session_isolation",
      relation: "secret_scan",
      observer: "network-client",
      runtime: "node-sidecar-http",
      evidence_kind: "integration",
      secrets: [],
      opaque_paths: [],
      compare_paths: ["/outcome_flag"],
      records: [
        record({
          id: "aborted",
          subject: "alice",
          session: "cancel-1",
          scope: "sidecar:/v1/verify",
          public_context: { attempt: "abort", method: "POST", path: "/v1/verify" },
          expected_outcome: "abort",
          outcome: abortedView.aborted ? "abort" : "unexpected",
          view: {
            outcome_flag: abortedView.aborted ? "abort" : "unexpected",
            aborted: abortedView.aborted,
            error_name: abortedView.error_name ?? null,
          },
        }),
        record({
          id: "retried",
          subject: "alice",
          session: "cancel-2",
          scope: "sidecar:/v1/verify",
          public_context: { attempt: "retry", method: "POST", path: "/v1/verify" },
          expected_outcome: "accept",
          outcome: retryJson.verified === true ? "accept" : "reject",
          view: {
            outcome_flag: retryJson.verified === true ? "accept" : "reject",
            http_status: retry.status,
            verified: retryJson.verified === true,
            body_keys: Object.keys(retryJson).sort(),
          },
        }),
      ],
    };
  } finally {
    gate.release();
    await runtime.close();
  }
}

async function collectSidecarLibrary(sdk) {
  const ctx = setupSidecar(sdk, sdk, new MockVerifyBackend());
  const views = [];
  for (const [id, payload] of [
    ["secret-in-json", JSON.stringify({ holder_secret: SYNTH_HOLDER })],
    ["unprovisioned-issuer", ctx.body.replace(ISSUER, "did:example:other-issuer")],
  ]) {
    try {
      await ctx.service.verifyJson(payload);
      views.push({ id, error_name: null, error_message: null });
    } catch (error) {
      views.push({
        id,
        error_name: error?.name ?? "Error",
        error_message: error?.message ?? String(error),
      });
    }
  }
  return [
    {
      id: "sidecar-library-rejection-equivalence",
      family: "failure_fallback",
      relation: "equivalent",
      observer: "http-library-boundary",
      runtime: "node-sdk-library",
      evidence_kind: "integration",
      secrets: [{ label: "holder_secret", value: SYNTH_HOLDER }],
      opaque_paths: [],
      compare_paths: ["/error_name", "/error_message"],
      records: views.map((view, index) =>
        record({
          id: view.id,
          subject: "alice",
          session: `lib-${index}`,
          scope: "SwiyuVerifierSidecarService.verifyJson",
          public_context: { api: "verifyJson" },
          expected_outcome: "reject",
          outcome: "reject",
          view: { error_name: view.error_name, error_message: view.error_message },
        }),
      ),
    },
  ];
}

async function collectSplit(sdk) {
  const descriptor = {
    profile: "privacy.integration.split.v1",
    prepareCircuitId: "prepare-circuit",
    showCircuitId: "show-circuit",
  };
  const lookup = {
    issuer: ISSUER,
    kid: "kid-1",
    vct: "https://example.ch/vct/person",
  };
  const backend = new MockSplitBackend();
  const walletA = new sdk.SwiyuSplitZkpWallet(backend);
  const walletB = new sdk.SwiyuSplitZkpWallet(backend);
  const key = new Uint8Array([1, 2, 3]);
  const witnessA = new Uint8Array(32).fill(0xa1);
  const witnessB = new Uint8Array(32).fill(0xb2);
  const pubA = [pad32(witnessA), pad32(descriptor.prepareCircuitId)];
  const pubB = [pad32(witnessB), pad32(descriptor.prepareCircuitId)];
  const preparedA = await walletA.prepare({
    descriptor,
    lookup,
    prepareWitness: witnessA,
    prepareProvingKey: key,
    expectedPreparePublicValues: pubA,
  });
  const preparedB = await walletB.prepare({
    descriptor,
    lookup,
    prepareWitness: witnessB,
    prepareProvingKey: key,
    expectedPreparePublicValues: pubB,
  });
  const challenge = {
    ...descriptor,
    challengeHash: 7n,
    currentTime: 1_750_000_000n,
  };
  const showPubA = [pad32(witnessA), pad32(descriptor.showCircuitId)];
  const showPubB = [pad32(witnessB), pad32(descriptor.showCircuitId)];
  const envA = await walletA.show({
    prepared: preparedA,
    challenge,
    showWitness: witnessA,
    showProvingKey: key,
    expectedShowPublicValues: showPubA,
  });
  const envB = await walletB.show({
    prepared: preparedB,
    challenge,
    showWitness: witnessB,
    showProvingKey: key,
    expectedShowPublicValues: showPubB,
  });
  let cross;
  try {
    await walletB.show({
      prepared: preparedA,
      challenge,
      showWitness: witnessA,
      showProvingKey: key,
      expectedShowPublicValues: showPubA,
    });
    cross = { error_message: null };
  } catch (error) {
    cross = { error_message: error?.message ?? String(error) };
  }

  const concurrentBackend = new MockSplitBackend();
  const concurrentWallet = new sdk.SwiyuSplitZkpWallet(concurrentBackend);
  const [c1, c2] = await Promise.all([
    prepareAndShow(concurrentWallet, descriptor, lookup, key, new Uint8Array(32).fill(1)),
    prepareAndShow(concurrentWallet, descriptor, lookup, key, new Uint8Array(32).fill(2)),
  ]);

  const mockCtx = {
    crypto_backend: "mock-split-backend",
    runtime_clear: "mock-byte-handles; not a real reblinding proof",
  };
  return [
    {
      id: "split-prepare-handle-isolation",
      family: "session_isolation",
      relation: "different",
      observer: "wallet",
      runtime: "node-sdk-library",
      evidence_kind: "integration",
      secrets: [],
      opaque_paths: ["/prepare_proof", "/show_proof"],
      compare_paths: ["/prepare_handle_id"],
      records: [
        record({
          id: "wallet-a",
          subject: "alice",
          session: "split-a",
          scope: "split-wallet",
          public_context: { lookup, ...mockCtx },
          expected_outcome: "accept",
          outcome: "accept",
          view: {
            lookup: { ...preparedA.lookup },
            profile: preparedA.profile,
            prepare_handle_id: hex(witnessA.subarray(0, 8)),
            prepare_proof: envA.prepareProof,
            show_proof: envA.showProof,
          },
        }),
        record({
          id: "wallet-b",
          subject: "bob",
          session: "split-b",
          scope: "split-wallet",
          public_context: { lookup, ...mockCtx },
          expected_outcome: "accept",
          outcome: "accept",
          view: {
            lookup: { ...preparedB.lookup },
            profile: preparedB.profile,
            prepare_handle_id: hex(witnessB.subarray(0, 8)),
            prepare_proof: envB.prepareProof,
            show_proof: envB.showProof,
          },
        }),
      ],
    },
    {
      id: "split-cross-wallet-reject",
      family: "session_isolation",
      relation: "secret_scan",
      observer: "wallet",
      runtime: "node-sdk-library",
      evidence_kind: "integration",
      secrets: [],
      opaque_paths: [],
      compare_paths: ["/error_message"],
      records: [
        record({
          id: "cross-wallet-show",
          subject: "alice",
          session: "split-cross",
          scope: "split-wallet",
          public_context: { lookup, ...mockCtx },
          expected_outcome: "reject",
          outcome: cross.error_message ? "reject" : "accept",
          view: cross,
        }),
      ],
    },
    {
      id: "split-prepare-concurrent",
      family: "prepared_state",
      relation: "different",
      observer: "wallet",
      runtime: "node-sdk-library",
      evidence_kind: "integration",
      secrets: [],
      opaque_paths: ["/prepare_proof", "/show_proof"],
      compare_paths: ["/prepare_proof"],
      records: [
        record({
          id: "concurrent-1",
          subject: "alice",
          session: "conc-1",
          scope: "split-wallet",
          public_context: mockCtx,
          expected_outcome: "accept",
          outcome: "accept",
          view: c1,
        }),
        record({
          id: "concurrent-2",
          subject: "alice",
          session: "conc-2",
          scope: "split-wallet",
          public_context: mockCtx,
          expected_outcome: "accept",
          outcome: "accept",
          view: c2,
        }),
      ],
    },
  ];
}

async function prepareAndShow(wallet, descriptor, lookup, key, witness) {
  const pub = [pad32(witness), pad32(descriptor.prepareCircuitId)];
  const prepared = await wallet.prepare({
    descriptor,
    lookup,
    prepareWitness: witness,
    prepareProvingKey: key,
    expectedPreparePublicValues: pub,
  });
  const env = await wallet.show({
    prepared,
    challenge: { ...descriptor, challengeHash: 9n, currentTime: 1n },
    showWitness: witness,
    showProvingKey: key,
    expectedShowPublicValues: [pad32(witness), pad32(descriptor.showCircuitId)],
  });
  return {
    lookup: { ...prepared.lookup },
    prepare_proof: env.prepareProof,
    show_proof: env.showProof,
  };
}

function collectNullifiers(sdk) {
  const holder = new Uint8Array(32).fill(0x11);
  const uid = new Uint8Array(32).fill(0x22);
  const binding = sdk.swiyuNullifierDigestLimbs(new Uint8Array(32).fill(0x55));
  const material = {
    holderSecret: holder,
    credentialUid: uid,
    credentialBindingHash: binding,
  };
  const seed = sdk.computeSwiyuNullifierCredentialSeed(material);
  const identifiers = {
    registryNamespace: "ch.swiyu.demo",
    verifierOrigin: "https://a.example",
    program: "aid",
    claimType: "age-over-18",
    epoch: 42n,
    eligibilityPolicy: "policy-v1",
  };
  const nf = (overrides = {}) => {
    const scope = sdk.buildSwiyuNullifierScope({ ...identifiers, ...overrides });
    const digest = sdk.computeSwiyuNullifierScopeDigest(scope);
    return hex(sdk.computeSwiyuScopedNullifier(seed, digest));
  };
  const originA = nf();
  const originARepeat = nf();
  const originB = nf({ verifierOrigin: "https://b.example" });
  const programB = nf({ program: "housing" });
  const epochB = nf({ epoch: 43n });

  const nonceA = "nonce-session-1";
  const nonceB = "nonce-session-2";
  const nonceANullifier = nf();
  const nonceBNullifier = nf();
  return [
    {
      id: "nullifier-scoped-origin-program-epoch",
      family: "scoped_identifier",
      relation: "scoped",
      observer: "wallet",
      runtime: "node-sdk-library",
      evidence_kind: "integration",
      secrets: [{ label: "holder_secret_bytes", value: SYNTH_HOLDER }],
      opaque_paths: ["/nullifier"],
      compare_paths: ["/nullifier"],
      records: [
        namedNullifier("alice-origin-a", "alice", "sess-a1", identifiers, originA),
        namedNullifier("alice-origin-a-repeat", "alice", "sess-a2", identifiers, originARepeat),
        namedNullifier(
          "alice-origin-b",
          "alice",
          "sess-b",
          { ...identifiers, verifierOrigin: "https://b.example" },
          originB,
        ),
        namedNullifier(
          "alice-program-b",
          "alice",
          "sess-p",
          { ...identifiers, program: "housing" },
          programB,
        ),
        namedNullifier(
          "alice-epoch-b",
          "alice",
          "sess-e",
          { ...identifiers, epoch: 43n },
          epochB,
        ),
      ],
    },
    {
      id: "nullifier-nonce-invariance",
      family: "linkability",
      relation: "same",
      observer: "wallet",
      runtime: "node-sdk-library",
      evidence_kind: "integration",
      secrets: [{ label: "holder_secret_bytes", value: SYNTH_HOLDER }],
      opaque_paths: ["/nullifier"],
      compare_paths: ["/nullifier"],
      records: [
        record({
          id: "nonce-a",
          subject: "alice",
          session: "n1",
          scope: scopeLabel(identifiers),
          public_context: {
            nonce: nonceA,
            scope_api_includes_nonce: false,
          },
          expected_outcome: "accept",
          outcome: "accept",
          view: { nullifier: nonceANullifier },
        }),
        record({
          id: "nonce-b",
          subject: "alice",
          session: "n2",
          scope: scopeLabel(identifiers),
          public_context: {
            nonce: nonceB,
            scope_api_includes_nonce: false,
          },
          expected_outcome: "accept",
          outcome: "accept",
          view: { nullifier: nonceBNullifier },
        }),
      ],
    },
  ];
}

function namedNullifier(id, subject, session, identifiers, nullifier) {
  return record({
    id,
    subject,
    session,
    scope: scopeLabel(identifiers),
    public_context: {
      origin: identifiers.verifierOrigin,
      program: identifiers.program,
      epoch: String(identifiers.epoch),
    },
    expected_outcome: "accept",
    outcome: "accept",
    view: { nullifier },
  });
}

function scopeLabel(identifiers) {
  return `origin:${identifiers.verifierOrigin}|program:${identifiers.program}|epoch:${identifiers.epoch}`;
}

async function collectStatusProjection(sdk) {
  const p256 = await loadP256();
  const sha256 = await loadSha256();
  const compactJwt = makeStatusListJwt(p256, sha256);
  const resolved = sdk.resolveSwiyuStatusListJwt({
    compactJwt,
    issuerPublicKey: publicJwk(p256, ISSUER_PRIVATE_KEY, CHECKED_IN_DID_TDW_KID),
    expectedIssuer: ISSUER,
    expectedSubject: SYNTH_STATUS_URI,
    currentTime: BigInt(IAT + 30),
    inflateZlib(compressed, maxOutputBytes) {
      return new Uint8Array(inflateSync(compressed, { maxOutputLength: maxOutputBytes }));
    },
  });
  const auth = resolved.authoritativeSnapshot;
  return {
    id: "status-list-authoritative-subject-uri",
    family: "status_access",
    relation: "secret_scan",
    observer: "authoritative SDK projection consumer",
    runtime: "node-sdk-library",
    evidence_kind: "integration",
    secrets: [{ label: "status_uri", value: SYNTH_STATUS_URI }],
    opaque_paths: ["/commitment"],
    compare_paths: ["/subject"],
    records: [
      record({
        id: "authoritative-snapshot",
        subject: "alice",
        session: "status-1",
        scope: "status-resolver-authoritativeSnapshot",
        public_context: {
          projection: "authoritativeSnapshot",
          boundary: "resolveSwiyuStatusListJwt return value",
          privateSnapshot_observed: false,
        },
        expected_outcome: "accept",
        outcome: "accept",
        view: {
          issuer: auth.issuer,
          kid: auth.kid,
          subject: auth.subject,
          epoch: auth.epoch,
          listLength: auth.listLength,
          provenance: auth.provenance,
          has_uri_field: Object.hasOwn(auth, "uri"),
          has_root_field: Object.hasOwn(auth, "root"),
          commitment: {
            hashHi: auth.commitment.hashHi.toString(),
            hashLo: auth.commitment.hashLo.toString(),
          },
          keys: Object.keys(auth).sort(),
          local_contract:
            "LOCAL SDK export: age18 policy comment calls the commitment URI-free; subject still copies the private status URI. Trusted sidecar already provisions known status subjects independently. Not a captured verifier HTTP leak and not a scan of privateSnapshot.",
        },
      }),
    ],
  };
}

function coverageGaps() {
  const skip = (id, family, reason) => ({
    id,
    family,
    relation: "equivalent",
    observer: "none",
    runtime: "unrun",
    evidence_kind: "integration",
    skip_reason: reason,
    secrets: [],
    opaque_paths: [],
    compare_paths: [],
    records: [],
  });
  return [
    skip(
      "skip-android-emulator",
      "disclosure",
      "Swiyu Android app runtime is unpackaged in this worktree; no emulator session was started.",
    ),
    skip(
      "skip-real-proof-crypto",
      "side_channel",
      "Real Spartan proving keys / native swiyu-profile binary were not invoked; crypto evidence_kind reserved for authentic proofs.",
    ),
    skip(
      "skip-authenticated-verifier-origin-binding",
      "scoped_identifier",
      "Nullifier origin is a caller-supplied identifier hash in buildSwiyuNullifierScope; this campaign does not observe an authenticated verifier origin binding, so copied malicious origin is not claimed tested.",
    ),
    skip(
      "skip-wallet-consent-credential-probing",
      "probing",
      "Credential probing at a wallet consent observer is a coverage gap; HTTP 400/413/404/415 differences are public method/path/type/length metadata, not consent-oracle leaks.",
    ),
    skip(
      "skip-hidden-branch-circuit",
      "hidden_branch",
      "Circuit branch traces are unavailable without a real witness/proof dump; mock backends do not expose branch bits. AND/OR comparison is a test-only control fixture.",
    ),
    skip(
      "skip-generic-prover-lifecycle",
      "prepared_state",
      "Generic OpenAC Prover.precompute/present requires WASM proving keys; inspected prover.ts but skipped heavy crypto.",
    ),
  ];
}

async function recordDistInstanceofMismatch(sdk, sidecarNode) {
  const ctx = setupSidecar(sdk, sdk, new MockVerifyBackend());
  let view;
  try {
    const runtime = await sidecarNode.startSwiyuSidecarServer({
      service: ctx.service,
      host: "127.0.0.1",
      port: 0,
    });
    await runtime.close();
    view = { started: true, error_message: null };
  } catch (error) {
    view = {
      started: false,
      error_message: error?.message ?? String(error),
    };
  }
  return {
    id: "sidecar-dist-entry-instanceof",
    family: "diagnostics",
    relation: "secret_scan",
    observer: "sdk-packaging",
    runtime: "node-sdk-library",
    evidence_kind: "integration",
    secrets: [],
    opaque_paths: [],
    compare_paths: ["/started", "/error_message"],
    records: [
      record({
        id: "index-service-into-sidecar-node-server",
        subject: "n/a",
        session: "packaging-1",
        scope: "dist-entrypoints",
        public_context: {
          service_entry: "dist/swiyu-zkp/index.js",
          server_entry: "dist/swiyu-zkp/sidecar-node.js",
        },
        expected_outcome: "accept",
        outcome: view.started ? "accept" : "reject",
        view,
      }),
    ],
  };
}

function setupSidecar(sdk, constructors, backend) {
  const key = cachedIssuerJwk;
  if (!key) {
    throw new Error("issuer JWK not primed");
  }
  const snapshotId = "ch-tsl-2026-07-epoch-172";
  const envelope = {
    version: sdk.SWIYU_PROOF_ENVELOPE_VERSION,
    profile: sdk.SWIYU_AGE18_STATUS_PROFILE,
    circuitId: sdk.SWIYU_AGE18_STATUS_CIRCUIT,
    proof: "UA",
    lookup: {
      issuer: ISSUER,
      kid: key.kid,
      vct: "https://example.ch/vct/person",
    },
  };
  const expected = {
    nonce: "n-7f3f778d0be4474e",
    client_id: "x509_san_dns:verifier.example.ch",
    response_uri: "https://verifier.example.ch/oid4vp/callback",
    state: "state-aaf24c5d",
    query_id: "age-over-18-and-valid-status",
    profile: sdk.SWIYU_AGE18_STATUS_PROFILE,
    circuit_id: sdk.SWIYU_AGE18_STATUS_CIRCUIT,
    cutoff_date: "2007-06-15",
    current_time: IAT,
    status_list_snapshot: snapshotId,
    vct_values: [envelope.lookup.vct],
    accepted_issuer_dids: [ISSUER],
    trust_anchors: [],
  };
  const body = JSON.stringify({
    proof_envelope: JSON.stringify(envelope),
    expected,
  });
  const authoritativeSnapshot = {
    id: snapshotId,
    issuer: ISSUER,
    kid: key.kid,
    subject: SYNTH_STATUS_URI,
    commitment: { hashHi: 1n, hashLo: 2n },
    epoch: 172,
    listLength: 8,
    validBefore: 1_800_000_000n,
    provenance: "integration-fixture",
  };
  const service = new constructors.SwiyuVerifierSidecarService({
    verifier: new constructors.SwiyuZkpVerifier(backend),
    verifyingKey: new Uint8Array([1, 2, 3]),
    issuers: [
      {
        issuer: ISSUER,
        kid: key.kid,
        publicKey: key,
        vctValues: [envelope.lookup.vct],
        trustAnchors: [],
      },
    ],
    statusSnapshots: [authoritativeSnapshot],
  });
  return { service, body, maxSmall: 129 };
}

let cachedIssuerJwk;

async function primeIssuerJwk() {
  if (cachedIssuerJwk) return cachedIssuerJwk;
  const p256 = await loadP256();
  cachedIssuerJwk = publicJwk(p256, ISSUER_PRIVATE_KEY, CHECKED_IN_DID_TDW_KID);
  return cachedIssuerJwk;
}

function publicJwk(p256, privateKey, kid) {
  const point = p256.ProjectivePoint.fromPrivateKey(privateKey).toAffine();
  return {
    kty: "EC",
    crv: "P-256",
    x: base64urlEncode(bigintToBytes(point.x, 32)),
    y: base64urlEncode(bigintToBytes(point.y, 32)),
    kid,
  };
}

function makeStatusListJwt(p256, sha256) {
  const header = {
    alg: "ES256",
    kid: CHECKED_IN_DID_TDW_KID,
    typ: "statuslist+jwt",
    profile_version: "swiss-profile-vc:1.0.0",
  };
  const packed = new Uint8Array([0xe4, 0x1b]);
  const payload = {
    ttl: 60,
    exp: IAT + 1_000,
    sub: SYNTH_STATUS_URI,
    iss: ISSUER,
    iat: IAT,
    status_list: {
      bits: 2,
      lst: base64urlEncode(new Uint8Array(deflateSync(packed, { level: 9 }))),
    },
  };
  const headerB64 = base64urlEncode(encoder.encode(JSON.stringify(header)));
  const payloadB64 = base64urlEncode(encoder.encode(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = p256.sign(sha256(encoder.encode(signingInput)), ISSUER_PRIVATE_KEY);
  return `${signingInput}.${base64urlEncode(signature.toCompactRawBytes())}`;
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });
  return { status: response.status, body: await response.text() };
}

function record(fields) {
  const rec = {
    id: fields.id,
    subject: fields.subject,
    session: fields.session,
    scope: fields.scope,
    public_context: fields.public_context,
    expected_outcome: fields.expected_outcome,
    outcome: fields.outcome,
    view: fields.view,
  };
  if (fields.allowed_public) rec.allowed_public = fields.allowed_public;
  if (fields.metrics) rec.metrics = fields.metrics;
  return rec;
}

async function collectHttpRepeatMetrics(url, body) {
  const subjects = [];
  for (let i = 0; i < 8; i += 1) {
    subjects.push("alice", "bob");
  }
  const records = [];
  for (let i = 0; i < subjects.length; i += 1) {
    const started = Date.now();
    const response = await postJson(url, body);
    const duration_ms = Date.now() - started;
    records.push(
      record({
        id: `http-metric-${i}`,
        subject: subjects[i],
        session: `metric-${i}`,
        scope: "sidecar:/v1/verify",
        public_context: {
          method: "POST",
          path: "/v1/verify",
          content_type: "application/json",
          content_length: body.length,
        },
        expected_outcome: "reject",
        outcome: "reject",
        view: { http_status: response.status, body: response.body },
        allowed_public: { "/http_status": 400, "/body": '{"verified":false}' },
        metrics: { duration_ms, size_bytes: response.body.length },
      }),
    );
  }
  return {
    id: "sidecar-http-repeat-metrics",
    family: "side_channel",
    relation: "metrics",
    observer: "network-client",
    runtime: "node-sidecar-http",
    evidence_kind: "integration",
    secrets: [{ label: "holder_secret", value: SYNTH_HOLDER }],
    opaque_paths: [],
    compare_paths: ["/http_status", "/body"],
    records,
  };
}

function hiddenBranchControl() {
  return {
    id: "ctrl-hidden-branch-and-or-clean",
    family: "hidden_branch",
    relation: "different",
    observer: "control",
    runtime: "fixture",
    evidence_kind: "control",
    secrets: [],
    opaque_paths: [],
    compare_paths: ["/predicate"],
    records: [
      record({
        id: "and-branch",
        subject: "alice",
        session: "ctrl-and",
        scope: "fixture-predicate",
        public_context: { evidence_kind: "control" },
        expected_outcome: "accept",
        outcome: "accept",
        view: { predicate: "AND" },
      }),
      record({
        id: "or-branch",
        subject: "alice",
        session: "ctrl-or",
        scope: "fixture-predicate",
        public_context: { evidence_kind: "control" },
        expected_outcome: "accept",
        outcome: "accept",
        view: { predicate: "OR" },
      }),
    ],
  };
}

function pad32(source) {
  const bytes = typeof source === "string" ? encoder.encode(source) : source;
  const out = new Uint8Array(32);
  out.set(bytes.subarray(0, Math.min(32, bytes.length)));
  return out;
}

function concatBytes(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function base64urlEncode(bytes) {
  return Buffer.from(bytes)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

function bigintToBytes(value, length) {
  const hexValue = value.toString(16).padStart(length * 2, "0");
  return Buffer.from(hexValue, "hex");
}

async function collectWithPrime() {
  await primeIssuerJwk();
  const sdk = await loadSdk();
  const sidecarNode = await loadSidecarNode();
  const cases = [];
  cases.push(...(await collectSidecarHttp(sdk, sidecarNode)));
  cases.push(...(await collectSidecarLibrary(sdk)));
  cases.push(...(await collectSplit(sdk)));
  cases.push(...collectNullifiers(sdk));
  cases.push(await collectStatusProjection(sdk));
  cases.push(hiddenBranchControl());
  cases.push(...coverageGaps());
  return {
    schema: "swiyu.privacy-traces.v1",
    provider: PROVIDER,
    cases,
  };
}

export { collectWithPrime as collect };

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const bundle = await collectWithPrime();
  process.stdout.write(`${JSON.stringify(bundle)}\n`);
}

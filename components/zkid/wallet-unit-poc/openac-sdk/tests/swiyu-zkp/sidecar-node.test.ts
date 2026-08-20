import { describe, expect, it } from "vitest";
import {
  SWIYU_AGE18_STATUS_CIRCUIT,
  SWIYU_AGE18_STATUS_PROFILE,
  SWIYU_PROOF_ENVELOPE_VERSION,
  SwiyuVerifierSidecarService,
  SwiyuZkpVerifier,
} from "../../src/index.js";
import {
  startSwiyuSidecarServer,
  type RunningSwiyuSidecar,
} from "../../src/swiyu-zkp/sidecar-node.js";
import type {
  SwiyuBackendVerification,
  SwiyuProofBackend,
} from "../../src/swiyu-zkp/types.js";
import { buildCredentialFixture, makeChallenge, makeStatus } from "./fixture.js";

class GateBackend implements SwiyuProofBackend {
  private releaseGate: (() => void) | undefined;
  private markStarted: () => void = () => undefined;
  readonly started = new Promise<void>((accept) => {
    this.markStarted = accept;
  });
  block = false;
  calls = 0;

  async proveFromWitness(): Promise<never> {
    throw new Error("not a prover");
  }

  async verify(
    _proof: Uint8Array,
    _verifyingKey: Uint8Array,
    context: Uint8Array,
  ): Promise<SwiyuBackendVerification> {
    this.calls += 1;
    this.markStarted();
    if (this.block) {
      await new Promise<void>((accept) => {
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

  release(): void {
    this.releaseGate?.();
  }
}

function setupService(backend = new GateBackend()) {
  const fixture = buildCredentialFixture();
  const { authoritativeSnapshot } = makeStatus();
  const challenge = makeChallenge(authoritativeSnapshot.id);
  const envelope = {
    version: SWIYU_PROOF_ENVELOPE_VERSION,
    profile: SWIYU_AGE18_STATUS_PROFILE,
    circuitId: SWIYU_AGE18_STATUS_CIRCUIT,
    proof: "UA",
    lookup: {
      issuer: "did:example:issuer",
      kid: fixture.issuerPublicKey.kid!,
      vct: "https://example.ch/vct/person",
    },
  } as const;
  const body = JSON.stringify({
    proof_envelope: JSON.stringify(envelope),
    expected: {
      nonce: challenge.nonce,
      client_id: challenge.clientId,
      response_uri: challenge.responseUri,
      state: challenge.state,
      query_id: challenge.queryId,
      profile: SWIYU_AGE18_STATUS_PROFILE,
      circuit_id: SWIYU_AGE18_STATUS_CIRCUIT,
      cutoff_date: challenge.cutoffDate,
      current_time: Number(challenge.currentTime),
      status_list_snapshot: challenge.statusListSnapshot,
      vct_values: [envelope.lookup.vct],
      accepted_issuer_dids: [envelope.lookup.issuer],
      trust_anchors: [],
    },
  });
  const service = new SwiyuVerifierSidecarService({
    verifier: new SwiyuZkpVerifier(backend),
    verifyingKey: new Uint8Array([1, 2, 3]),
    issuers: [{
      issuer: envelope.lookup.issuer,
      kid: envelope.lookup.kid,
      publicKey: fixture.issuerPublicKey,
      vctValues: [envelope.lookup.vct],
      trustAnchors: [],
    }],
    statusSnapshots: [authoritativeSnapshot],
  });
  return { backend, body, service };
}

function endpoint(runtime: RunningSwiyuSidecar, path = runtime.path): string {
  const host = runtime.host === "::1" ? "[::1]" : runtime.host;
  return `http://${host}:${runtime.port}${path}`;
}

describe("loopback swiyu verifier sidecar server", () => {
  it("serves only the exact JSON POST path and returns the fixed response", async () => {
    const context = setupService();
    const runtime = await startSwiyuSidecarServer({
      service: context.service,
      host: "127.0.0.1",
      port: 0,
      path: "/v1/verify",
    });
    try {
      const response = await fetch(endpoint(runtime), {
        method: "POST",
        headers: { "Content-Type": "application/json; charset=utf-8" },
        body: context.body,
      });
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({
        verified: true,
        profile: SWIYU_AGE18_STATUS_PROFILE,
        circuit_id: SWIYU_AGE18_STATUS_CIRCUIT,
        predicate_satisfied: true,
        status_valid: true,
        status_list_snapshot: makeChallenge().statusListSnapshot,
      });

      const wrongPath = await fetch(endpoint(runtime, "/v1/other"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: context.body,
      });
      expect(wrongPath.status).toBe(404);
      expect(await wrongPath.json()).toEqual({ verified: false });

      const wrongType = await fetch(endpoint(runtime), {
        method: "POST",
        headers: { "Content-Type": "text/plain" },
        body: context.body,
      });
      expect(wrongType.status).toBe(415);
      expect(await wrongType.json()).toEqual({ verified: false });
    } finally {
      await runtime.close();
    }
  });

  it("bounds request bytes and exposes no rejection diagnostics", async () => {
    const context = setupService();
    const runtime = await startSwiyuSidecarServer({
      service: context.service,
      port: 0,
      maxRequestBytes: 128,
    });
    try {
      const oversized = await fetch(endpoint(runtime), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "x".repeat(129),
      });
      expect(oversized.status).toBe(413);
      expect(await oversized.text()).toBe('{"verified":false}');

      const malformed = await fetch(endpoint(runtime), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      expect(malformed.status).toBe(400);
      expect(await malformed.text()).toBe('{"verified":false}');
    } finally {
      await runtime.close();
    }
  });

  it("rejects non-loopback binding before opening a listener", async () => {
    const context = setupService();
    await expect(
      startSwiyuSidecarServer({
        service: context.service,
        host: "0.0.0.0" as never,
        port: 7788,
      }),
    ).rejects.toThrow(/loopback-only/);
  });

  it("caps concurrent proof verification and closes cleanly", async () => {
    const backend = new GateBackend();
    backend.block = true;
    const context = setupService(backend);
    const runtime = await startSwiyuSidecarServer({
      service: context.service,
      port: 0,
      maxConcurrentRequests: 1,
    });
    try {
      const first = fetch(endpoint(runtime), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: context.body,
      });
      await backend.started;
      const second = await fetch(endpoint(runtime), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: context.body,
      });
      expect(second.status).toBe(503);
      expect(await second.text()).toBe('{"verified":false}');
      backend.release();
      expect((await first).status).toBe(200);
    } finally {
      backend.release();
      await runtime.close();
    }
  });

  it("keeps the concurrency slot occupied after an HTTP verification timeout", async () => {
    const backend = new GateBackend();
    backend.block = true;
    const context = setupService(backend);
    const runtime = await startSwiyuSidecarServer({
      service: context.service,
      port: 0,
      maxConcurrentRequests: 1,
      verificationTimeoutMs: 100,
    });
    try {
      const first = fetch(endpoint(runtime), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: context.body,
      });
      await backend.started;
      const firstResponse = await first;
      expect(firstResponse.status).toBe(400);

      const second = await fetch(endpoint(runtime), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: context.body,
      });
      expect(second.status).toBe(503);
      expect(await second.text()).toBe('{"verified":false}');
      expect(backend.calls).toBe(1);
      backend.release();
    } finally {
      backend.release();
      await runtime.close();
    }
  });
});

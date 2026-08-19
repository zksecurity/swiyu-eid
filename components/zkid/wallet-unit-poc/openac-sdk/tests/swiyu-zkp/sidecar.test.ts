import { describe, expect, it } from "vitest";
import {
  SWIYU_AGE18_STATUS_CIRCUIT,
  SWIYU_AGE18_STATUS_PROFILE,
  SWIYU_PROOF_ENVELOPE_VERSION,
  SwiyuSidecarRejection,
  SwiyuVerifierSidecarService,
  SwiyuZkpVerifier,
  buildSwiyuPublicContext,
  encodeSwiyuExpectedPublicContext,
} from "../../src/index.js";
import type {
  SwiyuBackendVerification,
  SwiyuKeyMaterial,
  SwiyuProofBackend,
  SwiyuProofEnvelope,
  SwiyuVerifyRequest,
} from "../../src/swiyu-zkp/types.js";
import type {
  SwiyuSidecarExpectedContext,
  SwiyuSidecarIssuerRecord,
} from "../../src/swiyu-zkp/sidecar.js";
import { base64urlEncode } from "../../src/utils.js";
import { buildCredentialFixture, makeChallenge, makeStatus } from "./fixture.js";

const TRUST_ANCHOR = Object.freeze({
  did: "did:example:anchor",
  trustRegistryUri: "https://trust.example/registry",
});

class RecordingVerificationBackend implements SwiyuProofBackend {
  calls: Array<{
    proof: Uint8Array;
    verifyingKey: SwiyuKeyMaterial;
    context: Uint8Array;
  }> = [];
  requiredContext?: Uint8Array;

  async proveFromWitness(): Promise<never> {
    throw new Error("verifier-side test backend cannot prove");
  }

  async verify(
    proof: Uint8Array,
    verifyingKey: SwiyuKeyMaterial,
    expectedPublicContext: Uint8Array,
  ): Promise<SwiyuBackendVerification> {
    this.calls.push({
      proof: new Uint8Array(proof),
      verifyingKey: verifyingKey instanceof Uint8Array
        ? new Uint8Array(verifyingKey)
        : { ...verifyingKey },
      context: new Uint8Array(expectedPublicContext),
    });
    const valid = this.requiredContext === undefined ||
      equalBytes(this.requiredContext, expectedPublicContext);
    return {
      valid,
      publicValues: valid
        ? Array.from({ length: 10 }, (_, index) =>
            expectedPublicContext.slice(index * 32, (index + 1) * 32),
          )
        : [],
      error: valid ? undefined : "context mismatch",
    };
  }
}

function setup() {
  const fixture = buildCredentialFixture();
  const { authoritativeSnapshot } = makeStatus();
  const challenge = makeChallenge(authoritativeSnapshot.id);
  const expected: SwiyuSidecarExpectedContext = {
    nonce: challenge.nonce,
    clientId: challenge.clientId,
    responseUri: challenge.responseUri,
    state: challenge.state,
    queryId: challenge.queryId,
    profile: SWIYU_AGE18_STATUS_PROFILE,
    circuitId: SWIYU_AGE18_STATUS_CIRCUIT,
    cutoffDate: challenge.cutoffDate,
    currentTime: challenge.currentTime,
    statusListSnapshot: challenge.statusListSnapshot,
    vctValues: ["https://example.ch/vct/person"],
    acceptedIssuerDids: ["did:example:issuer"],
    trustAnchors: [TRUST_ANCHOR],
  };
  const envelope: SwiyuProofEnvelope = {
    version: SWIYU_PROOF_ENVELOPE_VERSION,
    profile: SWIYU_AGE18_STATUS_PROFILE,
    circuitId: SWIYU_AGE18_STATUS_CIRCUIT,
    proof: base64urlEncode(new Uint8Array([0x50, 0x52, 0x4f, 0x4f, 0x46])),
    lookup: {
      issuer: "did:example:issuer",
      kid: fixture.issuerPublicKey.kid!,
      vct: "https://example.ch/vct/person",
    },
  };
  const issuer: SwiyuSidecarIssuerRecord = {
    issuer: envelope.lookup.issuer,
    kid: envelope.lookup.kid,
    publicKey: fixture.issuerPublicKey,
    vctValues: [envelope.lookup.vct],
    trustAnchors: [TRUST_ANCHOR],
  };
  const backend = new RecordingVerificationBackend();
  const pinnedVerifyingKey = new Uint8Array([0x99, 0x37, 0x42]);
  const service = new SwiyuVerifierSidecarService({
    verifier: new SwiyuZkpVerifier(backend),
    verifyingKey: pinnedVerifyingKey,
    issuers: [issuer],
    statusSnapshots: [authoritativeSnapshot],
  });
  return {
    fixture,
    authoritativeSnapshot,
    challenge,
    expected,
    envelope,
    issuer,
    backend,
    pinnedVerifyingKey,
    service,
  };
}

function javaRequest(
  envelope: SwiyuProofEnvelope,
  expected: SwiyuSidecarExpectedContext,
): string {
  return JSON.stringify({
    proof_envelope: JSON.stringify(envelope),
    expected: {
      nonce: expected.nonce,
      client_id: expected.clientId,
      response_uri: expected.responseUri,
      state: expected.state,
      query_id: expected.queryId,
      profile: expected.profile,
      circuit_id: expected.circuitId,
      cutoff_date: expected.cutoffDate,
      current_time: Number(expected.currentTime),
      status_list_snapshot: expected.statusListSnapshot,
      vct_values: expected.vctValues,
      accepted_issuer_dids: expected.acceptedIssuerDids,
      trust_anchors: expected.trustAnchors,
    },
  });
}

describe("swiyu verifier sidecar policy service", () => {
  it("matches Java casing, derives the exact context, and uses only pinned local authorities", async () => {
    const context = setup();
    const response = await context.service.verifyJson(
      javaRequest(context.envelope, context.expected),
    );

    expect(response).toEqual({
      verified: true,
      profile: SWIYU_AGE18_STATUS_PROFILE,
      circuit_id: SWIYU_AGE18_STATUS_CIRCUIT,
      predicate_satisfied: true,
      status_valid: true,
      status_list_snapshot: context.expected.statusListSnapshot,
    });
    expect(context.backend.calls).toHaveLength(1);
    expect(context.backend.calls[0]!.proof).toEqual(
      new Uint8Array([0x50, 0x52, 0x4f, 0x4f, 0x46]),
    );
    expect(context.backend.calls[0]!.verifyingKey).toEqual(
      context.pinnedVerifyingKey,
    );
    const independentContext = buildSwiyuPublicContext(
      context.fixture.issuerPublicKey,
      context.envelope.lookup,
      context.challenge,
      context.authoritativeSnapshot.commitment,
    );
    expect(context.backend.calls[0]!.context).toEqual(
      encodeSwiyuExpectedPublicContext(independentContext),
    );
  });

  it("cryptographically binds every expected session value instead of trusting envelope hints", async () => {
    const context = setup();
    await context.service.verifyJson(javaRequest(context.envelope, context.expected));
    context.backend.requiredContext = context.backend.calls[0]!.context;

    await expect(
      context.service.verifyJson(
        javaRequest(context.envelope, {
          ...context.expected,
          nonce: "attacker-selected-nonce",
        }),
      ),
    ).rejects.toBeInstanceOf(SwiyuSidecarRejection);

    await expect(
      context.service.verifyJson(
        javaRequest(
          {
            ...context.envelope,
            lookup: {
              ...context.envelope.lookup,
              issuer: "did:example:unprovisioned",
            },
          },
          context.expected,
        ),
      ),
    ).rejects.toBeInstanceOf(SwiyuSidecarRejection);
  });

  it("enforces VCT and accepted-issuer policies before calling the proof backend", async () => {
    for (const mutate of [
      (expected: SwiyuSidecarExpectedContext) => ({
        ...expected,
        vctValues: ["https://example.ch/vct/other"],
      }),
      (expected: SwiyuSidecarExpectedContext) => ({
        ...expected,
        acceptedIssuerDids: ["did:example:other"],
        trustAnchors: [],
      }),
      (expected: SwiyuSidecarExpectedContext) => ({
        ...expected,
        acceptedIssuerDids: [],
        trustAnchors: [{
          did: TRUST_ANCHOR.did,
          trustRegistryUri: "https://attacker.example/registry",
        }],
      }),
    ]) {
      const context = setup();
      await expect(
        context.service.verifyJson(
          javaRequest(context.envelope, mutate(context.expected)),
        ),
      ).rejects.toBeInstanceOf(SwiyuSidecarRejection);
      expect(context.backend.calls).toHaveLength(0);
    }
  });

  it("accepts a provisioned trust relationship as the Java policy alternative", async () => {
    const context = setup();
    await expect(
      context.service.verifyJson(
        javaRequest(context.envelope, {
          ...context.expected,
          acceptedIssuerDids: [],
          trustAnchors: [TRUST_ANCHOR],
        }),
      ),
    ).resolves.toMatchObject({ verified: true });
  });

  it("resolves only the expected snapshot and applies its exclusive freshness boundary", async () => {
    const context = setup();
    await expect(
      context.service.verifyJson(
        javaRequest(context.envelope, {
          ...context.expected,
          statusListSnapshot: "unknown-snapshot",
        }),
      ),
    ).rejects.toBeInstanceOf(SwiyuSidecarRejection);
    expect(context.backend.calls).toHaveLength(0);

    const staleService = new SwiyuVerifierSidecarService({
      verifier: new SwiyuZkpVerifier(context.backend),
      verifyingKey: context.pinnedVerifyingKey,
      issuers: [context.issuer],
      statusSnapshots: [{
        ...context.authoritativeSnapshot,
        validBefore: context.expected.currentTime,
      }],
    });
    await expect(
      staleService.verifyJson(javaRequest(context.envelope, context.expected)),
    ).rejects.toBeInstanceOf(SwiyuSidecarRejection);
    expect(context.backend.calls).toHaveLength(0);
  });

  it("rejects a status snapshot bound to a different issuer before backend verification", async () => {
    const context = setup();
    const crossIssuerService = new SwiyuVerifierSidecarService({
      verifier: new SwiyuZkpVerifier(context.backend),
      verifyingKey: context.pinnedVerifyingKey,
      issuers: [context.issuer],
      statusSnapshots: [{
        ...context.authoritativeSnapshot,
        issuer: "did:example:other-issuer",
      }],
    });

    await expect(
      crossIssuerService.verifyJson(javaRequest(context.envelope, context.expected)),
    ).rejects.toBeInstanceOf(SwiyuSidecarRejection);
    expect(context.backend.calls).toHaveLength(0);
  });

  it("rejects duplicate, extra, malformed, and non-canonical envelope fields", async () => {
    const context = setup();
    const valid = JSON.parse(
      javaRequest(context.envelope, context.expected),
    ) as Record<string, unknown>;
    const duplicateEnvelope =
      `{"version":"${SWIYU_PROOF_ENVELOPE_VERSION}",` +
      `"version":"${SWIYU_PROOF_ENVELOPE_VERSION}",` +
      `"profile":"${SWIYU_AGE18_STATUS_PROFILE}",` +
      `"circuitId":"${SWIYU_AGE18_STATUS_CIRCUIT}",` +
      '"proof":"UA","lookup":{"issuer":"did:example:issuer","kid":"k","vct":"v"}}';
    for (const request of [
      JSON.stringify({ ...valid, extra: true }),
      JSON.stringify({ ...valid, proof_envelope: duplicateEnvelope }),
      JSON.stringify({ ...valid, proof_envelope: "not-json" }),
      javaRequest({ ...context.envelope, proof: "not+base64url" }, context.expected),
    ]) {
      await expect(context.service.verifyJson(request)).rejects.toEqual(
        new SwiyuSidecarRejection(),
      );
    }
    expect(context.backend.calls).toHaveLength(0);
  });

  it("copies registries and the pinned key at construction", async () => {
    const context = setup();
    context.pinnedVerifyingKey.fill(0);
    context.issuer.vctValues[0] = "https://example.ch/vct/attacker";
    await context.service.verifyJson(javaRequest(context.envelope, context.expected));
    expect(context.backend.calls[0]!.verifyingKey).toEqual(
      new Uint8Array([0x99, 0x37, 0x42]),
    );
  });

  it("passes a copied local-file key reference without loading key bytes", async () => {
    const context = setup();
    let captured: SwiyuVerifyRequest | undefined;
    const keyReference = {
      kind: "local-file" as const,
      path: "/private/keys/swiyu_age18_status_2k_verifying.key",
    };
    const service = new SwiyuVerifierSidecarService({
      verifier: {
        async verify(request) {
          captured = request;
          return { valid: true };
        },
      },
      verifyingKey: keyReference,
      issuers: [context.issuer],
      statusSnapshots: [context.authoritativeSnapshot],
    });
    (keyReference as { path: string }).path = "/private/keys/attacker.key";

    await service.verifyJson(javaRequest(context.envelope, context.expected));

    expect(captured?.verifyingKey).toEqual({
      kind: "local-file",
      path: "/private/keys/swiyu_age18_status_2k_verifying.key",
    });
    expect(Object.isFrozen(captured?.verifyingKey)).toBe(true);
  });
});

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  SWIYU_MOBILE_EXPERIMENTS,
  hashSwiyuMobileRuntimeAgeChallenge,
  parseSwiyuMobileRuntimeRequestJson,
  parseSwiyuSidecarRequest,
} from "../../src/index.js";

interface RuntimeVector {
  request: Record<string, unknown>;
  expected: {
    challenge_sha256: string;
    challenge_scalar: string;
    proof_envelope: Record<string, unknown>;
    experiments: readonly Record<string, unknown>[];
  };
}

const vector = JSON.parse(readFileSync(
  new URL(
    "../../../../../../integration/contracts/fixtures/mobile-runtime-v1.json",
    import.meta.url,
  ),
  "utf8",
)) as RuntimeVector;

function parseVectorRequest() {
  return parseSwiyuMobileRuntimeRequestJson(JSON.stringify(vector.request));
}

describe("swiyu mobile runtime contract", () => {
  it("matches the shared Kotlin and zkID challenge vector", () => {
    const request = parseVectorRequest();
    const hash = hashSwiyuMobileRuntimeAgeChallenge(request);

    expect(Buffer.from(hash.digest).toString("hex")).toBe(
      vector.expected.challenge_sha256,
    );
    expect(hash.scalar.toString()).toBe(vector.expected.challenge_scalar);
  });

  it("pins every experiment profile and circuit sequence", () => {
    expect(JSON.parse(JSON.stringify(SWIYU_MOBILE_EXPERIMENTS))).toEqual(
      vector.expected.experiments,
    );
  });

  it("carries the age envelope into the verifier sidecar contract", () => {
    const request = parseVectorRequest();
    const envelope = vector.expected.proof_envelope;
    const parsed = parseSwiyuSidecarRequest(JSON.stringify({
      proof_envelope: JSON.stringify(envelope),
      expected: {
        nonce: request.challenge.nonce,
        client_id: request.challenge.clientId,
        response_uri: request.challenge.responseUri,
        state: request.challenge.state,
        query_id: request.challenge.queryId,
        profile: request.challenge.policy.profile,
        circuit_id: request.challenge.policy.circuitIds[0],
        cutoff_date: request.challenge.policy.parameters.cutoff_date,
        current_time: Number(request.challenge.policy.parameters.current_time),
        status_list_snapshot: request.challenge.policy.parameters.status_list_snapshot,
        vct_values: ["urn:example:identity"],
        accepted_issuer_dids: ["did:example:issuer"],
        trust_anchors: [],
      },
    }));

    expect(parsed.proofEnvelope).toEqual(envelope);
    expect(parsed.expected.nonce).toBe(request.challenge.nonce);
    expect(parsed.expected.currentTime).toBe(1_787_184_000n);
  });

  it("rejects ambiguous JSON and unknown circuit substitutions", () => {
    expect(() => parseSwiyuMobileRuntimeRequestJson(
      '{"schema":"swiyu.mobile-runtime-request.v1","schema":"swiyu.mobile-runtime-request.v1"}',
    )).toThrow();

    const changed = structuredClone(vector.request);
    const challenge = changed.challenge as Record<string, unknown>;
    const policy = challenge.policy as Record<string, unknown>;
    policy.circuit_ids = ["attacker_selected_circuit"];
    expect(() => parseSwiyuMobileRuntimeRequestJson(JSON.stringify(changed))).toThrow(
      "mobile runtime profile or circuit ids are not executable by this runtime",
    );
  });

  it("accepts standard JSON escapes at the Kotlin transport boundary", () => {
    const changed = structuredClone(vector.request);
    const challenge = changed.challenge as Record<string, unknown>;
    challenge.nonce = "opaque\"nonce\\value\nline";

    const parsed = parseSwiyuMobileRuntimeRequestJson(JSON.stringify(changed));

    expect(parsed.challenge.nonce).toBe("opaque\"nonce\\value\nline");
  });

  it("rejects experiment descriptors that do not yet have a mobile adapter", () => {
    for (const experiment of SWIYU_MOBILE_EXPERIMENTS.slice(1)) {
      const changed = structuredClone(vector.request);
      const challenge = changed.challenge as Record<string, unknown>;
      const policy = challenge.policy as Record<string, unknown>;
      policy.profile = experiment.profile;
      policy.circuit_ids = [...experiment.circuitIds];

      expect(() => parseSwiyuMobileRuntimeRequestJson(JSON.stringify(changed))).toThrow(
        "mobile runtime profile or circuit ids are not executable by this runtime",
      );
    }
  });

  it("validates the complete executable age parameter schema while parsing", () => {
    const extraParameter = structuredClone(vector.request);
    const extraPolicy = (extraParameter.challenge as Record<string, unknown>)
      .policy as Record<string, unknown>;
    (extraPolicy.parameters as Record<string, unknown>).unexpected = true;
    expect(() => parseSwiyuMobileRuntimeRequestJson(JSON.stringify(extraParameter))).toThrow(
      "request.challenge.policy.parameters.unexpected is not allowed",
    );

    const invalidSnapshot = structuredClone(vector.request);
    const invalidPolicy = (invalidSnapshot.challenge as Record<string, unknown>)
      .policy as Record<string, unknown>;
    (invalidPolicy.parameters as Record<string, unknown>).status_list_snapshot = "not allowed";
    expect(() => parseSwiyuMobileRuntimeRequestJson(JSON.stringify(invalidSnapshot))).toThrow(
      "request.challenge.policy.parameters.status_list_snapshot is invalid",
    );
  });

  it("binds the verifier nonce into the challenge digest", () => {
    const request = parseVectorRequest();
    const changed = structuredClone(vector.request);
    const challenge = changed.challenge as Record<string, unknown>;
    challenge.nonce = "different-nonce";
    const changedRequest = parseSwiyuMobileRuntimeRequestJson(JSON.stringify(changed));

    expect(hashSwiyuMobileRuntimeAgeChallenge(changedRequest).digest).not.toEqual(
      hashSwiyuMobileRuntimeAgeChallenge(request).digest,
    );
  });
});
